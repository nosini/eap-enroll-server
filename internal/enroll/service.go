// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package enroll implements enrollment: one-time codes, the EST handlers,
// device authentication and disabling devices.
package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nosini/eap-enroll-server/internal/attest"
	"github.com/nosini/eap-enroll-server/internal/config"
	"github.com/nosini/eap-enroll-server/internal/openbao"
	"github.com/nosini/eap-enroll-server/internal/store"
)

// codeBytes is the entropy of a one-time code.
const codeBytes = 20

var (
	labelPattern = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// Failure is a refusal with an HTTP status and an audit reason. Message
// is what the client sees; Err (optional) is logged, never sent.
type Failure struct {
	Status  int
	Reason  string
	Message string
	Err     error
}

func (f *Failure) Error() string {
	if f.Err != nil {
		return f.Reason + ": " + f.Err.Error()
	}
	return f.Reason
}

func (f *Failure) Unwrap() error { return f.Err }

func fail(status int, reason, message string, err error) *Failure {
	return &Failure{Status: status, Reason: reason, Message: message, Err: err}
}

// tooManyCertificatesRetry is the Retry-After the client gets when its
// device has reached an issuance cap.
const tooManyCertificatesRetry = 3600

// Service holds what the handlers and admin commands need.
type Service struct {
	cfg           *config.Config
	store         *store.Store
	bao           *openbao.Client
	log           *slog.Logger
	now           func() time.Time
	fingerprint   string
	limits        *limiter // per client address
	devices       *limiter // per device, for authenticated requests
	wifiIssuers   []*x509.Certificate
	deviceIssuers []*x509.Certificate
	attestation   *attest.Policy
	attestStatus  *attest.StatusList
}

// New creates the service.
func New(cfg *config.Config, st *store.Store, bao *openbao.Client, log *slog.Logger) (*Service, error) {
	fp, err := cfg.SetupFingerprint()
	if err != nil {
		return nil, err
	}
	wifiIssuers, err := config.ReadCertificates(cfg.WifiCACertsFile)
	if err != nil {
		return nil, err
	}
	deviceIssuers, err := config.ReadCertificates(cfg.DeviceCAFile)
	if err != nil {
		return nil, err
	}
	var attPolicy *attest.Policy
	var attStatus *attest.StatusList
	if ka := cfg.KeyAttestation; ka != nil {
		roots, err := config.ReadCertificates(ka.RootsFile)
		if err != nil {
			return nil, err
		}
		attPolicy = &attest.Policy{
			Roots:            roots,
			RequireStrongBox: ka.RequireStrongBox,
			VerifiedBootKeys: ka.VerifiedBootKeys,
			AppPackage:       ka.AppPackage,
			AppSigningCerts:  ka.AppSigningCerts,
		}
		attStatus, err = attest.NewStatusList(ka.StatusURL, log)
		if err != nil {
			return nil, err
		}
	}
	return &Service{
		cfg: cfg, store: st, bao: bao, log: log, now: time.Now, fingerprint: fp,
		limits: newLimiter(postBurst), devices: newLimiter(deviceBurst),
		wifiIssuers: wifiIssuers, deviceIssuers: deviceIssuers,
		attestation: attPolicy, attestStatus: attStatus,
	}, nil
}

// RunAttestationStatus refreshes the optional revocation list until ctx
// ends. It is a no-op without a status URL.
func (s *Service) RunAttestationStatus(ctx context.Context) {
	s.attestStatus.Run(ctx)
}

func hashCode(code string) []byte {
	sum := sha256.Sum256([]byte(code))
	return sum[:]
}

// SetupURI is what the QR code holds.
func (s *Service) SetupURI(code string) string {
	q := url.Values{}
	q.Set("v", "1")
	q.Set("url", s.cfg.PublicURL)
	q.Set("ca", s.fingerprint)
	q.Set("code", code)
	return "eapenroll://setup?" + q.Encode()
}

// CreateCode makes a one-time code for an enabled user and returns the
// setup URI and when the code expires.
func (s *Service) CreateCode(ctx context.Context, username, label string) (string, time.Time, error) {
	if !labelPattern.MatchString(label) {
		return "", time.Time{}, errors.New("label must be 1-64 letters, digits, spaces, '.', '_' or '-'")
	}
	name, err := s.bao.EnabledUser(ctx, username)
	if err != nil {
		return "", time.Time{}, err
	}
	raw := make([]byte, codeBytes)
	rand.Read(raw)
	code := codeEncoding.EncodeToString(raw)
	now := s.now()
	expires := now.Add(s.cfg.CodeTTL.D)
	if err := s.store.CreateCode(ctx, hashCode(code), name, label, now, expires); err != nil {
		return "", time.Time{}, err
	}
	s.log.Info("code_created", "username", name, "label", label, "expires", expires.UTC())
	return s.SetupURI(code), expires, nil
}

func newDeviceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// profile is one of the two certificate kinds.
type profile struct {
	kind    string
	mount   string
	role    string
	ttl     string
	ttlD    time.Duration
	curves  []elliptic.Curve
	issuers []*x509.Certificate
}

func (s *Service) wifiProfile() profile {
	o := s.cfg.OpenBao
	return profile{
		kind: store.KindWifi, mount: o.WifiMount, role: o.WifiRole,
		ttl: s.cfg.WifiTTL.Text, ttlD: s.cfg.WifiTTL.D,
		curves: []elliptic.Curve{elliptic.P384()}, issuers: s.wifiIssuers,
	}
}

func (s *Service) deviceProfile() profile {
	o := s.cfg.OpenBao
	return profile{
		kind: store.KindDevice, mount: o.DeviceMount, role: o.DeviceRole,
		ttl: s.cfg.DeviceTTL.Text, ttlD: s.cfg.DeviceTTL.D,
		curves: []elliptic.Curve{elliptic.P256(), elliptic.P384()}, issuers: s.deviceIssuers,
	}
}

func (s *Service) mountOf(kind string) string {
	if kind == store.KindDevice {
		return s.cfg.OpenBao.DeviceMount
	}
	return s.cfg.OpenBao.WifiMount
}

// parseCSR decodes an EST request body (base64 DER, whitespace ignored),
// checks the CSR's self-signature and that its key is ECDSA on one of the
// profile's curves. Subject and extensions are ignored.
func parseCSR(body []byte, p profile) (*x509.CertificateRequest, error) {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, string(body))
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, errors.New("body is not base64")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, errors.New("body is not a PKCS#10 request")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("CSR signature is invalid")
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !slices.Contains(p.curves, key.Curve) {
		names := make([]string, len(p.curves))
		for i, c := range p.curves {
			names[i] = c.Params().Name
		}
		return nil, fmt.Errorf("key must be ECDSA %s", strings.Join(names, " or "))
	}
	return csr, nil
}

// Subject attribute types the service allows in issued certificates.
var (
	oidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidProvince           = asn1.ObjectIdentifier{2, 5, 4, 8}
	oidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidSubjectAltName     = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// checkIssued makes sure OpenBao issued what was asked for before the
// certificate is recorded or handed out. The configured issuers come from
// the service's own configuration, not from OpenBao's answer.
func checkIssued(signed *openbao.Signed, csr *x509.CertificateRequest, username, uri string, p profile, now time.Time) error {
	c := signed.Certificate
	if c.Subject.CommonName != username {
		return fmt.Errorf("issued CN %q, expected %q", c.Subject.CommonName, username)
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !key.Equal(c.PublicKey) {
		return errors.New("issued certificate has a different public key")
	}
	if c.IsCA {
		return errors.New("issued certificate is a CA")
	}
	// Without basicConstraints, some verifiers (OpenSSL outside strict
	// mode) take keyCertSign to mean a CA, so the phone could issue
	// certificates of its own under the Wi-Fi CA.
	if c.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return errors.New("issued certificate may sign certificates or CRLs")
	}
	if !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
		len(c.UnknownExtKeyUsage) != 0 {
		return errors.New("issued certificate is not for client authentication only")
	}
	if len(c.DNSNames)+len(c.EmailAddresses)+len(c.IPAddresses) != 0 {
		return errors.New("issued certificate has DNS, e-mail or IP SANs")
	}
	if err := checkSAN(c, uri); err != nil {
		return err
	}
	if err := checkSubject(c); err != nil {
		return err
	}
	if len(c.UnhandledCriticalExtensions) != 0 {
		return fmt.Errorf("issued certificate has unhandled critical extensions %v", c.UnhandledCriticalExtensions)
	}
	if !c.NotAfter.After(now) {
		return errors.New("issued certificate is already expired")
	}
	if c.NotAfter.After(now.Add(p.ttlD + 5*time.Minute)) {
		return fmt.Errorf("issued certificate expires %v, after the profile's TTL", c.NotAfter.UTC())
	}
	if err := checkIssuer(c, p.issuers); err != nil {
		return err
	}
	if len(signed.Chain) > 0 {
		if err := c.CheckSignatureFrom(signed.Chain[0]); err != nil {
			return fmt.Errorf("issued certificate isn't signed by the first CA in the chain: %w", err)
		}
	}
	return nil
}

// checkSAN parses the raw subjectAltName extension. Wi-Fi certificates
// have no SAN or no names in it; device credentials have exactly the
// device URI. Any other name type is an error, including otherName (UPN),
// directory names and registered IDs.
func checkSAN(c *x509.Certificate, uri string) error {
	var ext *pkix.Extension
	for i := range c.Extensions {
		if c.Extensions[i].Id.Equal(oidSubjectAltName) {
			ext = &c.Extensions[i]
			break
		}
	}
	if ext == nil {
		if uri != "" {
			return fmt.Errorf("issued certificate has no URI SAN, expected %q", uri)
		}
		return nil
	}
	var names asn1.RawValue
	if rest, err := asn1.Unmarshal(ext.Value, &names); err != nil || len(rest) != 0 ||
		names.Class != asn1.ClassUniversal || names.Tag != asn1.TagSequence {
		return errors.New("issued certificate has a malformed subjectAltName")
	}
	var got []string
	rest := names.Bytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
			return errors.New("issued certificate has a malformed subjectAltName")
		}
		if gn.Class != asn1.ClassContextSpecific || gn.Tag != 6 {
			return fmt.Errorf("issued certificate has an unexpected SAN type (class %d, tag %d)", gn.Class, gn.Tag)
		}
		got = append(got, string(gn.Bytes))
	}
	if uri == "" {
		if len(got) != 0 {
			return fmt.Errorf("issued certificate has SANs %v, expected none", got)
		}
		return nil
	}
	if len(got) != 1 || got[0] != uri {
		return fmt.Errorf("issued URI SANs %v, expected %q", got, uri)
	}
	return nil
}

// checkSubject requires exactly one CN and only CN, C, L, ST, O and OU
// attributes, so no UID, serialNumber or other identifying attribute gets
// through.
func checkSubject(c *x509.Certificate) error {
	cn := 0
	for _, atv := range c.Subject.Names {
		switch {
		case atv.Type.Equal(oidCommonName):
			cn++
		case atv.Type.Equal(oidCountry), atv.Type.Equal(oidLocality), atv.Type.Equal(oidProvince),
			atv.Type.Equal(oidOrganization), atv.Type.Equal(oidOrganizationalUnit):
		default:
			return fmt.Errorf("issued certificate has unexpected subject attribute %v", atv.Type)
		}
	}
	if cn != 1 {
		return fmt.Errorf("issued certificate has %d CN attributes, expected exactly one", cn)
	}
	return nil
}

// checkIssuer requires the certificate to be signed by one of the
// configured CA certificates, independently of OpenBao's returned chain.
func checkIssuer(c *x509.Certificate, issuers []*x509.Certificate) error {
	for _, ca := range issuers {
		if bytes.Equal(c.RawIssuer, ca.RawSubject) && c.CheckSignatureFrom(ca) == nil {
			return nil
		}
	}
	return fmt.Errorf("issued certificate isn't signed by a configured CA (issuer %q)", c.Issuer)
}

// sign checks the user, signs the CSR, checks the result and records it.
// It returns the certificate followed by the CA chain.
func (s *Service) sign(ctx context.Context, p profile, dev store.Device, csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	name, err := s.bao.EnabledUser(ctx, dev.Username)
	if errors.Is(err, openbao.ErrUserNotEnabled) {
		return nil, fail(403, "user_disabled", "user is not enabled", nil)
	}
	if err != nil {
		return nil, fail(502, "openbao_error", "certificate authority unavailable", err)
	}
	if err := s.store.CheckCertificateLimit(ctx, dev.ID, p.kind, s.now()); err != nil {
		if errors.Is(err, store.ErrTooManyCertificates) {
			return nil, fail(429, "too_many_certificates", "too many certificates for this device", nil)
		}
		return nil, fail(500, "store_error", "internal error", err)
	}
	req := openbao.SignRequest{
		CSR:               string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})),
		CommonName:        name,
		ExcludeCNFromSANs: true,
		TTL:               p.ttl,
	}
	uri := ""
	if p.kind == store.KindDevice {
		uri = "urn:uuid:" + dev.ID
		req.URISANs = uri
	}
	signed, err := s.bao.Sign(ctx, p.mount, p.role, req)
	if err != nil {
		// OpenBao may have issued a certificate that can't be used; it
		// mustn't stay valid unrecorded.
		var issued *openbao.IssuedError
		if errors.As(err, &issued) {
			if issued.Serial != "" {
				s.revokeUnrecorded(ctx, p.mount, issued.Serial)
			} else {
				s.log.Error("revoke_failed", "mount", p.mount, "error", "unusable sign answer names no serial")
			}
			return nil, fail(502, "openbao_wrong_certificate", "certificate authority error", err)
		}
		return nil, fail(502, "openbao_error", "certificate authority unavailable", err)
	}
	serial := openbao.SerialText(signed.Certificate.SerialNumber)
	if err := checkIssued(signed, csr, name, uri, p, s.now()); err != nil {
		s.revokeUnrecorded(ctx, p.mount, serial)
		return nil, fail(502, "openbao_wrong_certificate", "certificate authority error", err)
	}
	err = s.store.AddCertificate(ctx, store.Certificate{
		Serial: serial, Kind: p.kind, DeviceID: dev.ID,
		Issued: s.now(), NotAfter: signed.Certificate.NotAfter,
	})
	if err != nil {
		s.revokeUnrecorded(ctx, p.mount, serial)
		switch {
		case errors.Is(err, store.ErrDeviceDisabled):
			return nil, fail(403, "device_disabled", "device is disabled", nil)
		case errors.Is(err, store.ErrTooManyCertificates):
			return nil, fail(429, "too_many_certificates", "too many certificates for this device", nil)
		}
		return nil, fail(500, "store_error", "internal error", err)
	}
	s.log.Info("certificate_issued", "kind", p.kind, "device", dev.ID, "username", name,
		"serial", serial, "not_after", signed.Certificate.NotAfter.UTC())
	return append([]*x509.Certificate{signed.Certificate}, signed.Chain...), nil
}

// revokeUnrecorded revokes a certificate that was issued but not handed
// out. Failures are logged; the certificate isn't in the store, so the
// log is the only record of it.
func (s *Service) revokeUnrecorded(ctx context.Context, mount, serial string) {
	ctx = context.WithoutCancel(ctx)
	err := s.bao.Revoke(ctx, mount, serial)
	if err == nil {
		err = s.bao.RotateCRL(ctx, mount)
	}
	if err != nil {
		s.log.Error("revoke_failed", "mount", mount, "serial", serial, "error", err.Error())
		return
	}
	s.log.Info("cert_revoked", "mount", mount, "serial", serial, "reason", "not handed out")
}

// EnrollDevice consumes a one-time code, creates a device and issues its
// device credential. The CSR must have been checked already.
func (s *Service) EnrollDevice(ctx context.Context, code string, csr *x509.CertificateRequest) (store.Device, []*x509.Certificate, error) {
	dev, err := s.store.UseCode(ctx, hashCode(code), newDeviceID(), s.now())
	switch {
	case errors.Is(err, store.ErrCodeInvalid):
		return dev, nil, fail(401, "bad_code", "invalid code", nil)
	case errors.Is(err, store.ErrCodeUsed):
		return dev, nil, fail(401, "code_used", "invalid code", nil)
	case errors.Is(err, store.ErrCodeExpired):
		return dev, nil, fail(401, "code_expired", "invalid code", nil)
	case err != nil:
		return dev, nil, fail(500, "store_error", "internal error", err)
	}
	certs, err := s.sign(ctx, s.deviceProfile(), dev, csr)
	if err != nil {
		if derr := s.store.DeleteDevice(context.WithoutCancel(ctx), dev.ID); derr != nil {
			s.log.Error("store_error", "device", dev.ID, "error", derr.Error())
		}
		return dev, nil, err
	}
	return dev, certs, nil
}

// Authenticate maps a verified client certificate to an enabled device
// and returns the certificate's serial. verified must come from
// tls.ConnectionState.VerifiedChains, so the certificate chains to
// device_ca_file.
func (s *Service) Authenticate(ctx context.Context, verified [][]*x509.Certificate) (store.Device, string, error) {
	if len(verified) == 0 || len(verified[0]) == 0 {
		return store.Device{}, "", fail(401, "no_client_cert", "client certificate required", nil)
	}
	leaf := verified[0][0]
	if len(leaf.URIs) != 1 || leaf.URIs[0].Scheme != "urn" || !strings.HasPrefix(leaf.URIs[0].Opaque, "uuid:") {
		return store.Device{}, "", fail(401, "unknown_cert", "unknown client certificate", nil)
	}
	id := strings.TrimPrefix(leaf.URIs[0].Opaque, "uuid:")
	if !uuidPattern.MatchString(id) {
		return store.Device{}, "", fail(401, "unknown_cert", "unknown client certificate", nil)
	}
	dev, err := s.store.Device(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return dev, "", fail(401, "unknown_cert", "unknown client certificate", nil)
	}
	if err != nil {
		return dev, "", fail(500, "store_error", "internal error", err)
	}
	if dev.Disabled != nil {
		return dev, "", fail(403, "device_disabled", "device is disabled", nil)
	}
	serial := openbao.SerialText(leaf.SerialNumber)
	cert, err := s.store.Certificate(ctx, store.KindDevice, serial)
	if errors.Is(err, store.ErrNotFound) || (err == nil && cert.DeviceID != dev.ID) {
		return dev, "", fail(401, "unknown_cert", "unknown client certificate", nil)
	}
	if err != nil {
		return dev, "", fail(500, "store_error", "internal error", err)
	}
	if !strings.EqualFold(leaf.Subject.CommonName, dev.Username) {
		return dev, "", fail(401, "unknown_cert", "unknown client certificate", nil)
	}
	if cert.Revoked != nil || cert.Superseded != nil {
		return dev, "", s.credentialReuse(ctx, dev, cert)
	}
	if !s.now().Before(cert.NotAfter) {
		return dev, "", fail(401, "expired_cert", "client certificate expired", nil)
	}
	// Marks the credential used and supersedes the older ones, checking
	// again in the transaction that it isn't superseded itself.
	err = s.store.UseCredential(ctx, dev.ID, serial, s.now())
	switch {
	case errors.Is(err, store.ErrSuperseded):
		// Superseded since it was read above: read it again for when.
		if cert, err = s.store.Certificate(ctx, store.KindDevice, serial); err != nil {
			return dev, "", fail(500, "store_error", "internal error", err)
		}
		return dev, "", s.credentialReuse(ctx, dev, cert)
	case errors.Is(err, store.ErrNotFound):
		return dev, "", fail(401, "unknown_cert", "unknown client certificate", nil)
	case err != nil:
		return dev, "", fail(500, "store_error", "internal error", err)
	}
	return dev, serial, nil
}

// credentialReuse handles a superseded (or revoked) device credential
// presented while its device is enabled. Only a newer credential's first
// use, or a renewal that replaced it before it was used, supersedes a
// credential of an enabled device. So someone other than the owner may
// hold a valid credential (or the phone kept using the old one, which
// can't be told apart): disable the device. The owner gets a new code and
// the copy stops working.
//
// The exception is a connection accepted before the credential was
// superseded: the phone may still have it open (keep-alive, HTTP/2)
// after switching to the renewed credential. That request is refused
// with 401 credential_superseded, and the phone reconnects.
func (s *Service) credentialReuse(ctx context.Context, dev store.Device, cert store.Certificate) error {
	if opened, ok := connOpened(ctx); ok && cert.Superseded != nil && opened.Unix() <= cert.Superseded.Unix() {
		return fail(401, "credential_superseded", "client certificate was replaced; reconnect with the current one", nil)
	}
	s.log.Error("credential_reuse", "device", dev.ID, "username", dev.Username,
		"label", dev.Label, "serial", cert.Serial)
	remaining, err := s.DisableDevice(context.WithoutCancel(ctx), dev.ID)
	var revErr *RevocationError
	switch {
	case errors.As(err, &revErr):
		// The device is disabled; an admin reruns `eap-enroll disable`
		// to revoke the rest.
		s.log.Error("revoke_failed", "device", dev.ID, "serials", remaining, "error", err.Error())
	case err != nil:
		// Not disabled: the next use of the credential tries again.
		s.log.Error("disable_failed", "device", dev.ID, "error", err.Error())
		return fail(500, "store_error", "internal error", err)
	}
	return fail(403, "credential_reuse", "device is disabled", nil)
}

// EnrollWifi issues a Wi-Fi certificate to an authenticated device.
func (s *Service) EnrollWifi(ctx context.Context, dev store.Device, csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	return s.sign(ctx, s.wifiProfile(), dev, csr)
}

// ReenrollDevice issues a new device credential to a device that
// authenticated with the credential presented. The presented one stays
// valid until the new one is first used. Credentials that earlier
// renewals with presented issued and that were never used are superseded:
// the phone didn't get them, or someone else holds them. So a phone whose
// renewal answers got lost can always renew again, and a copy of the
// credential can't keep an unused renewal in reserve.
func (s *Service) ReenrollDevice(ctx context.Context, dev store.Device, presented string, csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	certs, err := s.sign(ctx, s.deviceProfile(), dev, csr)
	if err != nil {
		return nil, err
	}
	issued := openbao.SerialText(certs[0].SerialNumber)
	unused, err := s.store.SupersedeUnused(ctx, dev.ID, presented, issued, s.now())
	if err != nil {
		// They stay valid until the next renewal or the new credential's
		// first use; the new one is recorded, so answer with it.
		s.log.Error("store_error", "device", dev.ID, "error", err.Error())
		return certs, nil
	}
	if len(unused) > 0 {
		s.log.Info("unused_credentials_superseded", "device", dev.ID, "username", dev.Username, "serials", unused)
		if err := s.retireSuperseded(ctx, dev); err != nil {
			s.log.Error("revoke_failed", "device", dev.ID, "kind", store.KindDevice, "error", err.Error())
		}
	}
	return certs, nil
}

// RevocationError is DisableDevice's error once the device is disabled:
// some of its certificates aren't revoked yet. Any other error means the
// device was not disabled.
type RevocationError struct {
	Err error
}

func (e *RevocationError) Error() string {
	return "device disabled, but revoking its certificates failed: " + e.Err.Error()
}

func (e *RevocationError) Unwrap() error { return e.Err }

// DisableDevice blocks a device at once and revokes its certificates. It
// returns the serials that are still to be revoked when OpenBao fails,
// with a *RevocationError; running it again retries them.
func (s *Service) DisableDevice(ctx context.Context, id string) ([]string, error) {
	now := s.now()
	dev, err := s.store.DisableDevice(ctx, id, now)
	if err != nil {
		return nil, err
	}
	s.log.Info("device_disabled", "device", dev.ID, "username", dev.Username, "label", dev.Label)
	certs, err := s.store.UnrevokedCertificates(ctx, id, now)
	if err != nil {
		return nil, &RevocationError{Err: err}
	}
	remaining, err := s.revoke(ctx, dev, certs, "device disabled")
	if err != nil {
		return remaining, &RevocationError{Err: err}
	}
	return nil, nil
}

// revoke revokes certificates of a device. Per mount: revoke all, rotate
// the CRL, then record. A certificate is only recorded as revoked once
// the CRL that lists it exists, so a failed rotation is retried by the
// next call. It returns the serials that are still to be revoked.
func (s *Service) revoke(ctx context.Context, dev store.Device, certs []store.Certificate, reason string) ([]string, error) {
	var remaining []string
	var errs []error
	for _, kind := range []string{store.KindWifi, store.KindDevice} {
		mount := s.mountOf(kind)
		var done []store.Certificate
		for _, c := range certs {
			if c.Kind != kind {
				continue
			}
			if err := s.bao.Revoke(ctx, mount, c.Serial); err != nil {
				errs = append(errs, err)
				remaining = append(remaining, c.Serial)
				continue
			}
			done = append(done, c)
		}
		if len(done) == 0 {
			continue
		}
		if err := s.bao.RotateCRL(ctx, mount); err != nil {
			errs = append(errs, err)
			for _, c := range done {
				remaining = append(remaining, c.Serial)
			}
			continue
		}
		for _, c := range done {
			if err := s.store.MarkRevoked(ctx, c.Kind, c.Serial, s.now()); err != nil {
				errs = append(errs, err)
				remaining = append(remaining, c.Serial)
				continue
			}
			s.log.Info("cert_revoked", "kind", c.Kind, "device", dev.ID, "username", dev.Username,
				"serial", c.Serial, "reason", reason)
		}
	}
	return remaining, errors.Join(errs...)
}

// revokeOlder revokes the device's certificates of kind that were issued
// before the one with serial.
func (s *Service) revokeOlder(ctx context.Context, dev store.Device, kind, serial string) error {
	older, err := s.store.OlderCertificates(ctx, dev.ID, kind, serial, s.now())
	if err != nil || len(older) == 0 {
		return err
	}
	_, err = s.revoke(ctx, dev, older, "superseded")
	return err
}

// retireSuperseded revokes the device's superseded device credentials in
// OpenBao. The database already refuses them; this makes the CRL say so
// too. A failure is retried on the next authenticated request.
func (s *Service) retireSuperseded(ctx context.Context, dev store.Device) error {
	certs, err := s.store.SupersededCertificates(ctx, dev.ID, s.now())
	if err != nil || len(certs) == 0 {
		return err
	}
	_, err = s.revoke(ctx, dev, certs, "superseded")
	return err
}

// ConfirmWifi is the phone's report that the Wi-Fi certificate with
// serial works; older Wi-Fi certificates of the device are revoked.
func (s *Service) ConfirmWifi(ctx context.Context, dev store.Device, serial string) error {
	serial = normalizeSerial(serial)
	cert, err := s.store.Certificate(ctx, store.KindWifi, serial)
	if errors.Is(err, store.ErrNotFound) || (err == nil && cert.DeviceID != dev.ID) {
		return fail(400, "unknown_serial", "unknown certificate", nil)
	}
	if err != nil {
		return fail(500, "store_error", "internal error", err)
	}
	if cert.Revoked != nil {
		return fail(400, "revoked_serial", "certificate is revoked", nil)
	}
	if err := s.revokeOlder(ctx, dev, store.KindWifi, serial); err != nil {
		return fail(502, "openbao_error", "certificate authority unavailable", err)
	}
	return nil
}

// normalizeSerial accepts hex with or without colons, any case and
// leading zeros, and returns openbao.SerialText's form ("" if invalid).
func normalizeSerial(v string) string {
	v = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(v), ":", ""))
	n, ok := new(big.Int).SetString(v, 16)
	if !ok || n.Sign() <= 0 || len(v) > 64 {
		return ""
	}
	return openbao.SerialText(n)
}

// PruneDevices deletes disabled devices whose certificates are all
// revoked or expired, and returns them and the disabled devices that
// still need a disable rerun. A deleted device's credentials are unknown
// afterwards and refused as such (401 unknown_cert).
func (s *Service) PruneDevices(ctx context.Context) (pruned, pending []store.Device, err error) {
	pruned, pending, err = s.store.PruneDevices(ctx, s.now())
	if err != nil {
		return nil, nil, err
	}
	for _, d := range pruned {
		s.log.Info("device_deleted", "device", d.ID, "username", d.Username, "label", d.Label)
	}
	return pruned, pending, nil
}

// CleanupCodes deletes expired codes.
func (s *Service) CleanupCodes(ctx context.Context) {
	n, err := s.store.DeleteExpiredCodes(ctx, s.now())
	if err != nil {
		s.log.Error("store_error", "error", err.Error())
	} else if n > 0 {
		s.log.Info("codes_expired", "count", n)
	}
}

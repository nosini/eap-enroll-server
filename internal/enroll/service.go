// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package enroll implements enrollment: one-time codes, the EST handlers,
// device authentication and disabling devices.
package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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

// Service holds what the handlers and admin commands need.
type Service struct {
	cfg         *config.Config
	store       *store.Store
	bao         *openbao.Client
	log         *slog.Logger
	now         func() time.Time
	fingerprint string
	limits      *limiter
}

// New creates the service.
func New(cfg *config.Config, st *store.Store, bao *openbao.Client, log *slog.Logger) (*Service, error) {
	fp, err := cfg.SetupFingerprint()
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, store: st, bao: bao, log: log, now: time.Now, fingerprint: fp, limits: newLimiter()}, nil
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
	kind   string
	mount  string
	role   string
	ttl    string
	curves []elliptic.Curve
}

func (s *Service) wifiProfile() profile {
	o := s.cfg.OpenBao
	return profile{store.KindWifi, o.WifiMount, o.WifiRole, s.cfg.WifiTTL.Text, []elliptic.Curve{elliptic.P384()}}
}

func (s *Service) deviceProfile() profile {
	o := s.cfg.OpenBao
	return profile{store.KindDevice, o.DeviceMount, o.DeviceRole, s.cfg.DeviceTTL.Text,
		[]elliptic.Curve{elliptic.P256(), elliptic.P384()}}
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

// checkIssued makes sure OpenBao issued what was asked for before the
// certificate is recorded or handed out.
func checkIssued(signed *openbao.Signed, csr *x509.CertificateRequest, username, uri string) error {
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
	if !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) ||
		slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) ||
		slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return errors.New("issued certificate is not for client authentication only")
	}
	if len(c.DNSNames)+len(c.EmailAddresses)+len(c.IPAddresses) != 0 {
		return errors.New("issued certificate has DNS, e-mail or IP SANs")
	}
	var uris []string
	for _, u := range c.URIs {
		uris = append(uris, u.String())
	}
	if (uri == "" && len(uris) != 0) || (uri != "" && (len(uris) != 1 || uris[0] != uri)) {
		return fmt.Errorf("issued URI SANs %v, expected %q", uris, uri)
	}
	if len(signed.Chain) > 0 {
		if err := c.CheckSignatureFrom(signed.Chain[0]); err != nil {
			return fmt.Errorf("issued certificate isn't signed by the first CA in the chain: %w", err)
		}
	}
	return nil
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
		return nil, fail(502, "openbao_error", "certificate authority unavailable", err)
	}
	serial := openbao.SerialText(signed.Certificate.SerialNumber)
	if err := checkIssued(signed, csr, name, uri); err != nil {
		s.revokeUnrecorded(ctx, p.mount, serial)
		return nil, fail(502, "openbao_wrong_certificate", "certificate authority error", err)
	}
	err = s.store.AddCertificate(ctx, store.Certificate{
		Serial: serial, Kind: p.kind, DeviceID: dev.ID,
		Issued: s.now(), NotAfter: signed.Certificate.NotAfter,
	})
	if err != nil {
		s.revokeUnrecorded(ctx, p.mount, serial)
		if errors.Is(err, store.ErrDeviceDisabled) {
			return nil, fail(403, "device_disabled", "device is disabled", nil)
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
	if cert.Revoked != nil {
		return dev, "", fail(401, "revoked_cert", "client certificate revoked", nil)
	}
	if !s.now().Before(cert.NotAfter) {
		return dev, "", fail(401, "expired_cert", "client certificate expired", nil)
	}
	if !strings.EqualFold(leaf.Subject.CommonName, dev.Username) {
		return dev, "", fail(401, "unknown_cert", "unknown client certificate", nil)
	}
	return dev, serial, nil
}

// EnrollWifi issues a Wi-Fi certificate to an authenticated device.
func (s *Service) EnrollWifi(ctx context.Context, dev store.Device, csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	return s.sign(ctx, s.wifiProfile(), dev, csr)
}

// ReenrollDevice issues a new device credential to an authenticated
// device. The old one stays valid until it expires or the device is
// disabled.
func (s *Service) ReenrollDevice(ctx context.Context, dev store.Device, csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	return s.sign(ctx, s.deviceProfile(), dev, csr)
}

// DisableDevice blocks a device at once and revokes its certificates. It
// returns the serials that are still to be revoked when OpenBao fails;
// running it again retries them.
func (s *Service) DisableDevice(ctx context.Context, id string) ([]string, error) {
	now := s.now()
	dev, err := s.store.DisableDevice(ctx, id, now)
	if err != nil {
		return nil, err
	}
	s.log.Info("device_disabled", "device", dev.ID, "username", dev.Username, "label", dev.Label)
	certs, err := s.store.UnrevokedCertificates(ctx, id, now)
	if err != nil {
		return nil, err
	}
	return s.revoke(ctx, dev, certs, "device disabled")
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

// CleanupCodes deletes expired codes.
func (s *Service) CleanupCodes(ctx context.Context) {
	n, err := s.store.DeleteExpiredCodes(ctx, s.now())
	if err != nil {
		s.log.Error("store_error", "error", err.Error())
	} else if n > 0 {
		s.log.Info("codes_expired", "count", n)
	}
}

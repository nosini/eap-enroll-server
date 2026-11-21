// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package enroll

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nosini/eap-enroll-server/internal/attest"
	"github.com/nosini/eap-enroll-server/internal/config"
	"github.com/nosini/eap-enroll-server/internal/openbao"
	"github.com/nosini/eap-enroll-server/internal/store"
)

// maxBody bounds an EST request body (a base64 CSR is well below 2 KiB).
const maxBody = 16 << 10

// maxConfirmBody bounds a wifi/confirm body, a serial in hex.
const maxConfirmBody = 256

// maxAttestationHeader matches the server's MaxHeaderBytes. A larger
// header is refused with 400 rather than reaching the TLS stack.
const maxAttestationHeader = 16 << 10

const estPrefix = "/.well-known/est/"

const pkcs7Type = "application/pkcs7-mime; smime-type=certs-only"

// encodeCerts is the EST response body: base64 of a certs-only PKCS#7,
// without line breaks. Strict decoders (Java's Base64.getDecoder(), GNU
// base64) reject CR, so no MIME-style lines.
func encodeCerts(certs []*x509.Certificate) ([]byte, error) {
	der, err := certsOnly(certs)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(der)), nil
}

// Handler returns the EST HTTP handler.
func (s *Service) Handler() (http.Handler, error) {
	wifiCA, err := cacertsBody(s.cfg.WifiCACertsFile)
	if err != nil {
		return nil, err
	}
	deviceCA, err := cacertsBody(s.cfg.DeviceCACertsFile)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+estPrefix+"wifi/cacerts", s.static(wifiCA))
	mux.HandleFunc("GET "+estPrefix+"device/cacerts", s.static(deviceCA))
	mux.HandleFunc("POST "+estPrefix+"device/simpleenroll", s.handleDeviceEnroll)
	mux.HandleFunc("POST "+estPrefix+"wifi/simpleenroll", s.handleEnroll("enroll_wifi", s.wifiProfile()))
	mux.HandleFunc("POST "+estPrefix+"device/simplereenroll", s.handleEnroll("reenroll_device", s.deviceProfile()))
	mux.HandleFunc("POST "+estPrefix+"wifi/confirm", s.authenticated("confirm_wifi", s.handleConfirm))
	if s.cfg.WifiProfile != nil {
		profile, err := profileBody(s.cfg.WifiProfile)
		if err != nil {
			return nil, err
		}
		mux.HandleFunc("GET "+estPrefix+"wifi/profile", s.authenticated("wifi_profile",
			func(w http.ResponseWriter, r *http.Request, dev store.Device, _ string) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.Write(profile)
			}))
	}
	return mux, nil
}

func cacertsBody(path string) ([]byte, error) {
	certs, err := config.ReadCertificates(path)
	if err != nil {
		return nil, err
	}
	return encodeCerts(certs)
}

func (s *Service) static(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", pkcs7Type)
		w.Header().Set("Content-Transfer-Encoding", "base64")
		w.Write(body)
	}
}

// refuse logs a refusal and answers with its status.
func (s *Service) refuse(w http.ResponseWriter, r *http.Request, event string, err error, attrs ...any) {
	var f *Failure
	if !errors.As(err, &f) {
		f = fail(500, "internal_error", "internal error", err)
	}
	attrs = append(attrs, "remote", r.RemoteAddr, "reason", f.Reason, "status", f.Status)
	if f.Err != nil {
		attrs = append(attrs, "error", f.Err.Error())
	}
	level := slog.LevelWarn
	if f.Status >= 500 {
		level = slog.LevelError
	}
	s.log.Log(r.Context(), level, event+"_refused", attrs...)
	if f.Reason == "too_many_certificates" {
		w.Header().Set("Retry-After", strconv.Itoa(tooManyCertificatesRetry))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The reason is a fixed code the client can act on (the app tells a
	// disabled account or a refused attestation from a disabled device,
	// which all answer 403); the body is text meant for logs.
	w.Header().Set("Enroll-Error", f.Reason)
	w.WriteHeader(f.Status)
	io.WriteString(w, f.Message+"\n")
}

func (s *Service) rateLimited(w http.ResponseWriter, r *http.Request, event string, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	s.refuse(w, r, event, fail(429, "rate_limited", "too many requests", nil))
}

// readCSR reads and checks the request body.
func readCSR(w http.ResponseWriter, r *http.Request, p profile) (*x509.CertificateRequest, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return nil, fail(413, "body_too_large", "request too large", nil)
	}
	if err != nil {
		return nil, fail(400, "bad_request", "could not read request", nil)
	}
	csr, err := parseCSR(body, p)
	if err != nil {
		return nil, fail(400, "bad_csr", err.Error(), nil)
	}
	return csr, nil
}

// attestationChain parses the Key-Attestation header: standard base64
// of the concatenated DER certificates, leaf first.
func attestationChain(r *http.Request) ([]*x509.Certificate, error) {
	h := r.Header.Get("Key-Attestation")
	if h == "" {
		return nil, errors.New("missing Key-Attestation header")
	}
	if len(h) > maxAttestationHeader {
		return nil, fmt.Errorf("Key-Attestation header is longer than %d bytes", maxAttestationHeader)
	}
	if strings.ContainsAny(h, "\r\n") {
		return nil, errors.New("Key-Attestation header contains a line break")
	}
	der, err := base64.StdEncoding.Strict().DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("Key-Attestation header is not standard base64: %w", err)
	}
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, fmt.Errorf("Key-Attestation header is not a certificate chain: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("Key-Attestation header has no certificates")
	}
	return certs, nil
}

func (s *Service) verifyAttestation(r *http.Request, pub crypto.PublicKey, challenge []byte) (attest.Result, error) {
	chain, err := attestationChain(r)
	if err != nil {
		return attest.Result{}, fail(400, "bad_attestation", "invalid key attestation", err)
	}
	res, err := attest.Verify(chain, pub, challenge, *s.attestation, s.attestStatus, s.now())
	if err != nil {
		if errors.Is(err, attest.ErrStatusUnavailable) {
			return attest.Result{}, fail(502, "attestation_status_unavailable",
				"key attestation status unavailable", err)
		}
		return attest.Result{}, fail(403, "attestation_refused", "key attestation refused", err)
	}
	return res, nil
}

func attestationLogAttrs(res attest.Result) []any {
	return []any{
		"attestation_security_level", res.SecurityLevel,
		"attestation_verified_boot_state", res.VerifiedBootState,
		"attestation_device_locked", res.DeviceLocked,
		"attestation_verified_boot_key", res.VerifiedBootKey,
		"attestation_version", res.AttestationVersion,
	}
}

func (s *Service) respond(w http.ResponseWriter, certs []*x509.Certificate) {
	body, err := encodeCerts(certs)
	if err != nil {
		// Can't happen for certificates that parsed; nothing sensible
		// to send.
		http.Error(w, "internal error", 500)
		return
	}
	w.Header().Set("Content-Type", pkcs7Type)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}

func bearer(r *http.Request) (string, bool) {
	scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

// codeFailed records a wrong, used or expired code and logs the one
// global warning per window when the failure count gets high.
func (s *Service) codeFailed(key string, now time.Time) {
	if s.limits.codeFailed(key, now) {
		s.log.Warn("code_failures_high", "count", globalFailLimit, "window", globalFailWindow.String())
	}
}

// refuseCode answers an unusable code after charging the per-IP limits.
func (s *Service) refuseCode(w http.ResponseWriter, r *http.Request, event, key string, now time.Time, f *Failure) {
	if ok, wait := s.limits.allow(key, now); !ok {
		s.rateLimited(w, r, event, wait)
		return
	}
	if ok, wait := s.limits.codeAllowed(key, now); !ok {
		s.rateLimited(w, r, event, wait)
		return
	}
	s.codeFailed(key, now)
	s.refuse(w, r, event, f)
}

func (s *Service) handleDeviceEnroll(w http.ResponseWriter, r *http.Request) {
	const event = "enroll_device"
	key := clientKey(r.RemoteAddr)
	now := s.now()
	code, ok := bearer(r)
	if !ok {
		// No code: the per-IP bucket still applies to this unauthenticated
		// request.
		if ok, wait := s.limits.allow(key, now); !ok {
			s.rateLimited(w, r, event, wait)
			return
		}
		s.refuse(w, r, event, fail(401, "no_code", "one-time code required", nil))
		return
	}
	switch err := s.store.CheckCode(r.Context(), hashCode(code), now); {
	case err == nil:
		// A usable code is an unguessable secret, so it bypasses the
		// per-IP limits: they would only lock out the user behind a
		// shared address.
	case errors.Is(err, store.ErrCodeInvalid):
		s.refuseCode(w, r, event, key, now, fail(401, "bad_code", "invalid code", nil))
		return
	case errors.Is(err, store.ErrCodeUsed):
		s.refuseCode(w, r, event, key, now, fail(401, "code_used", "invalid code", nil))
		return
	case errors.Is(err, store.ErrCodeExpired):
		s.refuseCode(w, r, event, key, now, fail(401, "code_expired", "invalid code", nil))
		return
	default:
		s.refuse(w, r, event, fail(500, "store_error", "internal error", err))
		return
	}
	// A bad CSR doesn't use up the code.
	csr, err := readCSR(w, r, s.deviceProfile())
	if err != nil {
		s.refuse(w, r, event, err)
		return
	}
	var attResult attest.Result
	if s.attestation != nil {
		// Checked before the code is used, so a refused attestation
		// doesn't consume it.
		attResult, err = s.verifyAttestation(r, csr.PublicKey, hashCode(code))
		if err != nil {
			s.refuse(w, r, event, err)
			return
		}
	}
	dev, certs, err := s.EnrollDevice(r.Context(), code, csr)
	if err != nil {
		var f *Failure
		if errors.As(err, &f) && f.Status == 401 {
			// The code became unusable since CheckCode: lost a race.
			s.codeFailed(key, s.now())
		}
		s.refuse(w, r, event, err, "device", dev.ID, "username", dev.Username, "label", dev.Label)
		return
	}
	attrs := []any{"remote", r.RemoteAddr, "device", dev.ID, "username", dev.Username, "label", dev.Label}
	if s.attestation != nil {
		attrs = append(attrs, attestationLogAttrs(attResult)...)
	}
	s.log.Info(event, attrs...)
	s.respond(w, certs)
}

// authenticated wraps a handler that needs the device credential:
// authentication, a per-device rate limit, the user check, and revoking
// superseded device credentials in OpenBao. next gets the device and the
// serial of the presented credential.
func (s *Service) authenticated(event string, next func(http.ResponseWriter, *http.Request, store.Device, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var chains [][]*x509.Certificate
		if r.TLS != nil {
			chains = r.TLS.VerifiedChains
		}
		dev, serial, err := s.Authenticate(r.Context(), chains)
		if err != nil {
			// Only work without a valid device credential is limited per
			// client address, so a shared address can't lock out a phone
			// that has one.
			if ok, wait := s.limits.allow(clientKey(r.RemoteAddr), s.now()); !ok {
				s.rateLimited(w, r, event, wait)
				return
			}
			s.refuse(w, r, event, err, "device", dev.ID, "username", dev.Username)
			return
		}
		if ok, wait := s.devices.allow(dev.ID, s.now()); !ok {
			s.rateLimited(w, r, event, wait)
			return
		}
		if !s.checkUser(w, r, event, dev) {
			return
		}
		// Authenticate superseded the older credentials in the database;
		// revoke them in OpenBao too. A failure is retried on the next
		// request.
		if err := s.retireSuperseded(r.Context(), dev); err != nil {
			s.log.Error("revoke_failed", "device", dev.ID, "kind", store.KindDevice, "error", err.Error())
		}
		next(w, r, dev, serial)
	}
}

// checkUser makes sure the device's user is still enabled; a disabled
// user's phone must not get Wi-Fi settings or confirm certificates. It
// answers the request itself and returns false on failure.
func (s *Service) checkUser(w http.ResponseWriter, r *http.Request, event string, dev store.Device) bool {
	_, err := s.bao.EnabledUser(r.Context(), dev.Username)
	switch {
	case errors.Is(err, openbao.ErrUserNotEnabled):
		s.refuse(w, r, event, fail(403, "user_disabled", "user is not enabled", nil),
			"device", dev.ID, "username", dev.Username)
		return false
	case err != nil:
		s.refuse(w, r, event, fail(502, "openbao_error", "certificate authority unavailable", err),
			"device", dev.ID, "username", dev.Username)
		return false
	}
	return true
}

func (s *Service) handleEnroll(event string, p profile) http.HandlerFunc {
	return s.authenticated(event, func(w http.ResponseWriter, r *http.Request, dev store.Device, serial string) {
		csr, err := readCSR(w, r, p)
		if err != nil {
			s.refuse(w, r, event, err, "device", dev.ID, "username", dev.Username)
			return
		}
		var attResult attest.Result
		if s.attestation != nil && p.kind == store.KindDevice {
			// The challenge is fixed when the new key is generated, so
			// it can only name the credential presented now.
			leaf := r.TLS.VerifiedChains[0][0]
			challenge := sha256.Sum256(leaf.Raw)
			attResult, err = s.verifyAttestation(r, csr.PublicKey, challenge[:])
			if err != nil {
				s.refuse(w, r, event, err, "device", dev.ID, "username", dev.Username)
				return
			}
		}
		var certs []*x509.Certificate
		if p.kind == store.KindDevice {
			certs, err = s.ReenrollDevice(r.Context(), dev, serial, csr)
		} else {
			certs, err = s.EnrollWifi(r.Context(), dev, csr)
		}
		if err != nil {
			s.refuse(w, r, event, err, "device", dev.ID, "username", dev.Username)
			return
		}
		attrs := []any{"remote", r.RemoteAddr, "device", dev.ID, "username", dev.Username, "label", dev.Label}
		if s.attestation != nil && p.kind == store.KindDevice {
			attrs = append(attrs, attestationLogAttrs(attResult)...)
		}
		s.log.Info(event, attrs...)
		s.respond(w, certs)
	})
}

// handleConfirm takes the serial (hex, colons allowed) of a Wi-Fi
// certificate the phone has connected with and revokes the older ones.
func (s *Service) handleConfirm(w http.ResponseWriter, r *http.Request, dev store.Device, _ string) {
	const event = "confirm_wifi"
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxConfirmBody))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		s.refuse(w, r, event, fail(413, "body_too_large", "request too large", nil), "device", dev.ID)
		return
	}
	if err != nil {
		s.refuse(w, r, event, fail(400, "bad_request", "could not read request", nil), "device", dev.ID)
		return
	}
	serial := strings.TrimSpace(string(body))
	if err := s.ConfirmWifi(r.Context(), dev, serial); err != nil {
		s.refuse(w, r, event, err, "device", dev.ID, "username", dev.Username)
		return
	}
	s.log.Info(event, "remote", r.RemoteAddr, "device", dev.ID, "username", dev.Username, "serial", normalizeSerial(serial))
	w.WriteHeader(http.StatusNoContent)
}

// wifiProfile is the body of wifi/profile.
type wifiProfile struct {
	SSID                 string   `json:"ssid"`
	ServerDomain         string   `json:"server_domain"`
	ServerCACertificates [][]byte `json:"server_ca_certificates"`
}

func profileBody(p *config.WifiProfile) ([]byte, error) {
	certs, err := config.ReadCertificates(p.ServerCAFile)
	if err != nil {
		return nil, err
	}
	body := wifiProfile{SSID: p.SSID, ServerDomain: p.ServerDomain}
	for _, c := range certs {
		body.ServerCACertificates = append(body.ServerCACertificates, c.Raw)
	}
	return json.Marshal(body)
}

// keyReloader serves the server certificate and reloads it when the
// files' modification times change, checked at most once a minute.
type keyReloader struct {
	certFile, keyFile string
	anchor            []byte // DER of the setup CA, which the chain must contain
	log               *slog.Logger

	mu        sync.Mutex
	cert      *tls.Certificate
	stamp     string
	lastCheck time.Time
}

func fileStamp(paths ...string) (string, error) {
	var parts []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		parts = append(parts, fmt.Sprintf("%d:%d", st.ModTime().UnixNano(), st.Size()))
	}
	return strings.Join(parts, "/"), nil
}

func (k *keyReloader) load() error {
	stamp, err := fileStamp(k.certFile, k.keyFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(k.certFile, k.keyFile)
	if err != nil {
		return err
	}
	// The client knows only the setup CA's fingerprint, so the served
	// chain has to include that certificate.
	if !slices.ContainsFunc(cert.Certificate, func(c []byte) bool { return bytes.Equal(c, k.anchor) }) {
		return fmt.Errorf("%s doesn't contain the setup CA certificate (setup_ca_file)", k.certFile)
	}
	k.cert, k.stamp = &cert, stamp
	return nil
}

func (k *keyReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if now := time.Now(); now.Sub(k.lastCheck) >= time.Minute {
		k.lastCheck = now
		if stamp, err := fileStamp(k.certFile, k.keyFile); err == nil && stamp != k.stamp {
			if err := k.load(); err != nil {
				k.log.Error("tls_reload_failed", "error", err.Error())
			} else {
				k.log.Info("tls_reloaded")
			}
		}
	}
	return k.cert, nil
}

// TLSConfig is the server's TLS configuration: client certificates are
// optional at the TLS level (the bearer-code and cacerts endpoints don't
// use them) and, when sent, must chain to device_ca_file.
func (s *Service) TLSConfig() (*tls.Config, error) {
	anchor, err := config.ReadCertificates(s.cfg.SetupCAFile)
	if err != nil {
		return nil, err
	}
	k := &keyReloader{certFile: s.cfg.TLSCertFile, keyFile: s.cfg.TLSKeyFile, anchor: anchor[0].Raw, log: s.log}
	if err := k.load(); err != nil {
		return nil, err
	}
	pool, err := clientCAPool(s.cfg.DeviceCAFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: k.get,
		ClientAuth:     tls.VerifyClientCertIfGiven,
		ClientCAs:      pool,
		NextProtos:     []string{"h2", "http/1.1"},
		// A resumed session carries the client certificate of its first
		// handshake, which may be a device credential the phone has
		// since replaced; presenting that is reuse.
		SessionTicketsDisabled: true,
	}, nil
}

// connOpenedKey is the context key for when a connection was accepted.
type connOpenedKey struct{}

// ConnContext records when a connection was accepted, so a device
// credential that was superseded after that can be told from one that
// was presented again later; http.Server.ConnContext.
func (s *Service) ConnContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connOpenedKey{}, s.now())
}

// connOpened returns when the request's connection was accepted, if known.
func connOpened(ctx context.Context) (time.Time, bool) {
	t, ok := ctx.Value(connOpenedKey{}).(time.Time)
	return t, ok
}

// clientCAPool loads the device CA. It refuses self-signed certificates:
// the device CA shares a root with the Wi-Fi CA, and trusting the root
// would let certificates from other intermediates through.
func clientCAPool(path string) (*x509.CertPool, error) {
	certs, err := config.ReadCertificates(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		if !c.IsCA {
			return nil, fmt.Errorf("%s: %q is not a CA certificate", path, c.Subject)
		}
		if bytes.Equal(c.RawIssuer, c.RawSubject) {
			return nil, fmt.Errorf("%s: %q is self-signed; list only the device intermediate", path, c.Subject)
		}
		pool.AddCert(c)
	}
	return pool, nil
}

// Server is the HTTP server with its timeouts.
func (s *Service) Server() (*http.Server, error) {
	handler, err := s.Handler()
	if err != nil {
		return nil, err
	}
	tlsConfig, err := s.TLSConfig()
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ConnContext:       s.ConnContext,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}, nil
}

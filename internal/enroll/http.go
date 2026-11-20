// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package enroll

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nosini/eap-enroll-server/internal/config"
)

// maxBody bounds an EST request body (a base64 CSR is well below 2 KiB).
const maxBody = 16 << 10

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
	mux.HandleFunc("POST "+estPrefix+"wifi/simpleenroll", s.handleMTLS("enroll_wifi", s.wifiProfile()))
	mux.HandleFunc("POST "+estPrefix+"device/simplereenroll", s.handleMTLS("reenroll_device", s.deviceProfile()))
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
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
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

func (s *Service) handleDeviceEnroll(w http.ResponseWriter, r *http.Request) {
	const event = "enroll_device"
	key := clientKey(r.RemoteAddr)
	now := s.now()
	if ok, wait := s.limits.allow(key, now); !ok {
		s.rateLimited(w, r, event, wait)
		return
	}
	if ok, wait := s.limits.codeAllowed(key, now); !ok {
		s.rateLimited(w, r, event, wait)
		return
	}
	code, ok := bearer(r)
	if !ok {
		s.refuse(w, r, event, fail(401, "no_code", "one-time code required", nil))
		return
	}
	// A bad CSR doesn't use up the code.
	csr, err := readCSR(w, r, s.deviceProfile())
	if err != nil {
		s.refuse(w, r, event, err)
		return
	}
	dev, certs, err := s.EnrollDevice(r.Context(), code, csr)
	if err != nil {
		var f *Failure
		if errors.As(err, &f) && f.Status == 401 {
			s.limits.codeFailed(key, s.now())
		}
		s.refuse(w, r, event, err, "device", dev.ID, "username", dev.Username, "label", dev.Label)
		return
	}
	s.log.Info(event, "remote", r.RemoteAddr, "device", dev.ID, "username", dev.Username, "label", dev.Label)
	s.respond(w, certs)
}

func (s *Service) handleMTLS(event string, p profile) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := s.limits.allow(clientKey(r.RemoteAddr), s.now()); !ok {
			s.rateLimited(w, r, event, wait)
			return
		}
		var chains [][]*x509.Certificate
		if r.TLS != nil {
			chains = r.TLS.VerifiedChains
		}
		dev, err := s.Authenticate(r.Context(), chains)
		if err != nil {
			s.refuse(w, r, event, err, "device", dev.ID, "username", dev.Username)
			return
		}
		csr, err := readCSR(w, r, p)
		if err != nil {
			s.refuse(w, r, event, err, "device", dev.ID, "username", dev.Username)
			return
		}
		certs, err := s.sign(r.Context(), p, dev, csr)
		if err != nil {
			s.refuse(w, r, event, err, "device", dev.ID, "username", dev.Username)
			return
		}
		s.log.Info(event, "remote", r.RemoteAddr, "device", dev.ID, "username", dev.Username, "label", dev.Label)
		s.respond(w, certs)
	}
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
	}, nil
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
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}, nil
}

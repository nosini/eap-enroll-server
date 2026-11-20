// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package enroll

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nosini/eap-enroll-server/internal/config"
	"github.com/nosini/eap-enroll-server/internal/openbao"
	"github.com/nosini/eap-enroll-server/internal/store"
)

// ca is a test certificate authority.
type ca struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serial(t testing.TB) *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func issue(t testing.TB, parent *ca, tmpl *x509.Certificate, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	tmpl.SerialNumber = serial(t)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	}
	signerCert, signerKey := tmpl, crypto.Signer(nil)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	if signerKey == nil {
		t.Fatal("self-signed issue needs a key")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, pub, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newRoot(t testing.TB, name string) *ca {
	key := newKey(t, elliptic.P384())
	tmpl := &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotAfter: time.Now().Add(48 * time.Hour),
	}
	self := &ca{cert: tmpl, key: key}
	return &ca{cert: issue(t, self, tmpl, key.Public()), key: key}
}

func (c *ca) intermediate(t testing.TB, name string) *ca {
	key := newKey(t, elliptic.P384())
	tmpl := &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotAfter: time.Now().Add(47 * time.Hour),
	}
	return &ca{cert: issue(t, c, tmpl, key.Public()), key: key}
}

func pemCert(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func writeFile(t testing.TB, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeBao implements the OpenBao endpoints the service calls.
type fakeBao struct {
	t      testing.TB
	server *httptest.Server
	cas    map[string]*ca // mount -> issuing CA
	root   *ca

	mu       sync.Mutex
	groups   map[string]any
	logins   int
	signs    []map[string]any
	revoked  map[string][]string // mount -> colon serials
	rotates  map[string]int
	wrongCN  bool // issue certificates with a different CN
	failSign bool
	failRot  bool
}

const (
	testRoleID   = "role-id-for-tests"
	testSecretID = "secret-id-for-tests"
	testToken    = "token-for-tests"
)

func newFakeBao(t testing.TB, root *ca, cas map[string]*ca) *fakeBao {
	f := &fakeBao{
		t: t, root: root, cas: cas,
		groups:  map[string]any{"alice": "staff", "Bob": "disabled", "carol": "guests"},
		revoked: map[string][]string{}, rotates: map[string]int{},
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeBao) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (f *fakeBao) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	var body map[string]any
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.reply(w, 400, map[string]any{"errors": []string{"bad json"}})
			return
		}
	}
	if path == "auth/approle/login" {
		if body["role_id"] != testRoleID || body["secret_id"] != testSecretID {
			f.reply(w, 400, map[string]any{"errors": []string{"invalid role or secret ID"}})
			return
		}
		f.logins++
		f.reply(w, 200, map[string]any{"auth": map[string]any{"client_token": testToken, "lease_duration": 3600}})
		return
	}
	if r.Header.Get("X-Vault-Token") != testToken {
		f.reply(w, 403, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	switch {
	case r.Method == http.MethodGet && path == "kv/data/apps/freeradius/user-groups":
		f.reply(w, 200, map[string]any{"data": map[string]any{"data": f.groups}})
	case r.Method == http.MethodPost && strings.Contains(path, "/sign/"):
		f.sign(w, strings.SplitN(path, "/", 2)[0], body)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/revoke"):
		mount := strings.TrimSuffix(path, "/revoke")
		f.revoked[mount] = append(f.revoked[mount], body["serial_number"].(string))
		f.reply(w, 200, map[string]any{"data": map[string]any{"revocation_time": time.Now().Unix()}})
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/crl/rotate"):
		if f.failRot {
			f.reply(w, 500, map[string]any{"errors": []string{"rotate failed"}})
			return
		}
		f.rotates[strings.TrimSuffix(path, "/crl/rotate")]++
		f.reply(w, 200, map[string]any{"data": map[string]any{"success": true}})
	default:
		f.reply(w, 404, map[string]any{"errors": []string{"no handler for " + path}})
	}
}

func (f *fakeBao) sign(w http.ResponseWriter, mount string, body map[string]any) {
	issuer := f.cas[mount]
	if issuer == nil || f.failSign {
		f.reply(w, 500, map[string]any{"errors": []string{"cannot sign"}})
		return
	}
	f.signs = append(f.signs, body)
	block, _ := pem.Decode([]byte(body["csr"].(string)))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		f.reply(w, 400, map[string]any{"errors": []string{"bad csr"}})
		return
	}
	ttl, err := time.ParseDuration(body["ttl"].(string))
	if err != nil {
		f.reply(w, 400, map[string]any{"errors": []string{"bad ttl"}})
		return
	}
	cn := body["common_name"].(string)
	if f.wrongCN {
		cn = "someone-else"
	}
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		NotAfter:    time.Now().Add(ttl),
	}
	if u, ok := body["uri_sans"].(string); ok && u != "" {
		parsed, _ := url.Parse(u)
		tmpl.URIs = []*url.URL{parsed}
	}
	cert := issue(f.t, issuer, tmpl, csr.PublicKey)
	f.reply(w, 200, map[string]any{"data": map[string]any{
		"certificate":   pemCert(cert),
		"issuing_ca":    pemCert(issuer.cert),
		"ca_chain":      []string{pemCert(issuer.cert), pemCert(f.root.cert)},
		"serial_number": colonHex(cert.SerialNumber),
	}})
}

func colonHex(n *big.Int) string {
	var parts []string
	for _, b := range n.Bytes() {
		parts = append(parts, strings.ToLower(hexByte(b)))
	}
	return strings.Join(parts, ":")
}

func hexByte(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&15]})
}

// env is a running service with its PKI and fake OpenBao.
type env struct {
	t        *testing.T
	root     *ca
	wifiCA   *ca
	deviceCA *ca
	otherCA  *ca // a third intermediate under the same root
	setupCA  *ca
	bao      *fakeBao
	svc      *Service
	store    *store.Store
	srv      *httptest.Server
	now      time.Time
	logs     *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{t: t, now: time.Now()}
	e.root = newRoot(t, "Test Root")
	e.wifiCA = e.root.intermediate(t, "Test Wi-Fi CA")
	e.deviceCA = e.root.intermediate(t, "Test Device CA")
	e.otherCA = e.root.intermediate(t, "Test Other CA")
	e.setupCA = newRoot(t, "Test TLS CA")
	e.bao = newFakeBao(t, e.root, map[string]*ca{"pki-radius": e.wifiCA, "pki-enroll": e.deviceCA})

	serverKey := newKey(t, elliptic.P256())
	serverCert := issue(t, e.setupCA, &x509.Certificate{
		Subject: pkix.Name{CommonName: "enroll.test"}, DNSNames: []string{"enroll.test"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}, serverKey.Public())
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	baoCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.bao.server.Certificate().Raw}))
	cfgJSON := map[string]any{
		"listen":              "127.0.0.1:0",
		"public_url":          "https://enroll.test:8443",
		"tls_cert_file":       writeFile(t, dir, "tls.pem", pemCert(serverCert)+pemCert(e.setupCA.cert)),
		"tls_key_file":        writeFile(t, dir, "tls.key", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))),
		"setup_ca_file":       writeFile(t, dir, "setup-ca.pem", pemCert(e.setupCA.cert)),
		"device_ca_file":      writeFile(t, dir, "device-ca.pem", pemCert(e.deviceCA.cert)),
		"wifi_cacerts_file":   writeFile(t, dir, "wifi-cacerts.pem", pemCert(e.wifiCA.cert)+pemCert(e.root.cert)),
		"device_cacerts_file": writeFile(t, dir, "device-cacerts.pem", pemCert(e.deviceCA.cert)+pemCert(e.root.cert)),
		"database":            filepath.Join(dir, "enroll.db"),
		"wifi_ttl":            "2160h",
		"device_ttl":          "8760h",
		"openbao": map[string]any{
			"address":        e.bao.server.URL,
			"ca_file":        writeFile(t, dir, "bao-ca.pem", baoCA),
			"role_id_file":   writeFile(t, dir, "role-id", testRoleID+"\n"),
			"secret_id_file": writeFile(t, dir, "secret-id", testSecretID+"\n"),
		},
	}
	raw, _ := json.Marshal(cfgJSON)
	cfg, err := config.Load(writeFile(t, dir, "config.json", string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	e.store, err = store.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.store.Close() })
	client, err := openbao.New(cfg.OpenBao)
	if err != nil {
		t.Fatal(err)
	}
	e.logs = &bytes.Buffer{}
	e.svc, err = New(cfg, e.store, client, slog.New(slog.NewJSONHandler(e.logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e.svc.now = func() time.Time { return e.now }
	handler, err := e.svc.Handler()
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := e.svc.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewUnstartedServer(handler)
	e.srv.TLS = tlsConfig
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)
	return e
}

// client returns an HTTPS client trusting only the setup CA, optionally
// presenting a client certificate.
func (e *env) client(cert *tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(e.setupCA.cert)
	cfg := &tls.Config{RootCAs: pool, ServerName: "enroll.test", MinVersion: tls.VersionTLS13}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func csrBody(t testing.TB, key crypto.Signer, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(der))
}

type result struct {
	status int
	body   string
	certs  []*x509.Certificate
	header http.Header
	err    error
}

// post sends an EST POST. The test clock advances by one token-bucket
// interval per request, so only tests about rate limits hit them.
func (e *env) post(client *http.Client, path, bearer string, body []byte) result {
	e.t.Helper()
	e.now = e.now.Add(time.Duration(float64(time.Second) / postRate))
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+estPrefix+path, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return e.do(client, req)
}

func (e *env) do(client *http.Client, req *http.Request) result {
	e.t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		return result{err: err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	r := result{status: resp.StatusCode, body: string(raw), header: resp.Header}
	if resp.StatusCode == 200 {
		der, err := base64.StdEncoding.DecodeString(strings.Map(func(c rune) rune {
			if c == '\r' || c == '\n' {
				return -1
			}
			return c
		}, string(raw)))
		if err != nil {
			e.t.Fatalf("response is not base64: %v", err)
		}
		if r.certs, err = parseCertsOnly(der); err != nil {
			e.t.Fatalf("response is not PKCS#7: %v", err)
		}
	}
	return r
}

// code creates a one-time code and returns it.
func (e *env) code(user, label string) string {
	e.t.Helper()
	uri, _, err := e.svc.CreateCode(context.Background(), user, label)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		e.t.Fatal(err)
	}
	return u.Query().Get("code")
}

// enrollDevice runs device/simpleenroll and returns the device
// credential as a TLS certificate.
func (e *env) enrollDevice(user string) (*tls.Certificate, *x509.Certificate) {
	e.t.Helper()
	key := newKey(e.t, elliptic.P256())
	r := e.post(e.client(nil), "device/simpleenroll", e.code(user, "Phone"), csrBody(e.t, key, "ignored"))
	if r.status != 200 {
		e.t.Fatalf("device enroll: %d %s %v", r.status, r.body, r.err)
	}
	return tlsCert(r.certs, key), r.certs[0]
}

func tlsCert(chain []*x509.Certificate, key crypto.Signer) *tls.Certificate {
	c := &tls.Certificate{PrivateKey: key, Leaf: chain[0]}
	for _, x := range chain {
		c.Certificate = append(c.Certificate, x.Raw)
	}
	return c
}

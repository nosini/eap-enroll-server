// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package enroll

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nosini/eap-enroll-server/internal/openbao"
	"github.com/nosini/eap-enroll-server/internal/store"
)

func TestFullLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// Setup URI: the code's username is matched ignoring case and stored
	// in the map's spelling.
	uri, expires, err := e.svc.CreateCode(ctx, "ALICE", "Pixel 10")
	if err != nil {
		t.Fatal(err)
	}
	if want := e.now.Add(15 * time.Minute); !expires.Equal(want) {
		t.Errorf("expires %v, want %v", expires, want)
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "eapenroll" || u.Host != "setup" {
		t.Fatalf("setup URI %q", uri)
	}
	q := u.Query()
	sum := sha256.Sum256(e.setupCA.cert.Raw)
	if q.Get("v") != "1" || q.Get("url") != "https://enroll.test:8443" || q.Get("ca") != hex.EncodeToString(sum[:]) {
		t.Errorf("setup URI fields %v", q)
	}
	code := q.Get("code")
	if len(code) != 32 {
		t.Errorf("code %q has length %d", code, len(code))
	}
	if strings.Contains(e.logs.String(), code) {
		t.Error("code appears in the log")
	}

	// Device credential. The CSR's CN is ignored.
	deviceKey := newKey(t, elliptic.P256())
	r := e.post(e.client(nil), "device/simpleenroll", code, csrBody(t, deviceKey, "mallory"))
	if r.status != 200 {
		t.Fatalf("device enroll: %d %s %v", r.status, r.body, r.err)
	}
	if ct := r.header.Get("Content-Type"); ct != pkcs7Type {
		t.Errorf("content type %q", ct)
	}
	devCert := r.certs[0]
	if devCert.Subject.CommonName != "alice" || len(devCert.URIs) != 1 {
		t.Fatalf("device cert CN %q URIs %v", devCert.Subject.CommonName, devCert.URIs)
	}
	if len(r.certs) != 3 || !r.certs[1].Equal(e.deviceCA.cert) || !r.certs[2].Equal(e.root.cert) {
		t.Errorf("chain not returned in order")
	}
	deviceID := strings.TrimPrefix(devCert.URIs[0].String(), "urn:uuid:")
	dev, err := e.store.Device(ctx, deviceID)
	if err != nil || dev.Username != "alice" || dev.Label != "Pixel 10" {
		t.Fatalf("stored device %+v, %v", dev, err)
	}
	sign := e.bao.signs[len(e.bao.signs)-1]
	if sign["ttl"] != "8760h" || sign["exclude_cn_from_sans"] != true || sign["uri_sans"] != "urn:uuid:"+deviceID {
		t.Errorf("device sign request %v", sign)
	}

	// The code is single use.
	if r := e.post(e.client(nil), "device/simpleenroll", code, csrBody(t, deviceKey, "x")); r.status != 401 {
		t.Errorf("reused code: %d", r.status)
	}

	// Wi-Fi certificate with the device credential.
	device := e.client(tlsCert(r.certs, deviceKey))
	wifiKey := newKey(t, elliptic.P384())
	r = e.post(device, "wifi/simpleenroll", "", csrBody(t, wifiKey, "CN=other"))
	if r.status != 200 {
		t.Fatalf("wifi enroll: %d %s %v", r.status, r.body, r.err)
	}
	wifi := r.certs[0]
	if wifi.Subject.CommonName != "alice" || len(wifi.URIs) != 0 {
		t.Errorf("wifi cert CN %q URIs %v", wifi.Subject.CommonName, wifi.URIs)
	}
	if err := wifi.CheckSignatureFrom(e.wifiCA.cert); err != nil {
		t.Errorf("wifi cert not from the Wi-Fi CA: %v", err)
	}
	sign = e.bao.signs[len(e.bao.signs)-1]
	if sign["ttl"] != "2160h" || sign["common_name"] != "alice" || sign["uri_sans"] != nil {
		t.Errorf("wifi sign request %v", sign)
	}

	// Wi-Fi needs P-384.
	if r := e.post(device, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P256()), "x")); r.status != 400 {
		t.Errorf("P-256 wifi CSR: %d", r.status)
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if r := e.post(device, "wifi/simpleenroll", "", csrBody(t, rsaKey, "x")); r.status != 400 {
		t.Errorf("RSA wifi CSR: %d", r.status)
	}

	// Device renewal; the old credential stays usable until disabled.
	newDeviceKey := newKey(t, elliptic.P384())
	r = e.post(device, "device/simplereenroll", "", csrBody(t, newDeviceKey, "x"))
	if r.status != 200 || r.certs[0].URIs[0].String() != "urn:uuid:"+deviceID {
		t.Fatalf("reenroll: %d %s", r.status, r.body)
	}
	renewed := e.client(tlsCert(r.certs, newDeviceKey))
	if r := e.post(renewed, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 200 {
		t.Errorf("wifi with renewed credential: %d %s", r.status, r.body)
	}

	// No client certificate.
	if r := e.post(e.client(nil), "wifi/simpleenroll", "", csrBody(t, wifiKey, "x")); r.status != 401 {
		t.Errorf("wifi without client cert: %d", r.status)
	}

	// Disable: blocks at once, revokes all four certificates, rotates both CRLs.
	remaining, err := e.svc.DisableDevice(ctx, deviceID)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("disable: %v %v", remaining, err)
	}
	if n := len(e.bao.revoked["pki-radius"]); n != 2 {
		t.Errorf("wifi revocations %d, want 2", n)
	}
	if n := len(e.bao.revoked["pki-enroll"]); n != 2 {
		t.Errorf("device revocations %d, want 2", n)
	}
	if e.bao.rotates["pki-radius"] != 1 || e.bao.rotates["pki-enroll"] != 1 {
		t.Errorf("rotates %v", e.bao.rotates)
	}
	if !contains(e.bao.revoked["pki-radius"], colonHex(wifi.SerialNumber)) {
		t.Error("first wifi cert not revoked")
	}
	if r := e.post(renewed, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 403 {
		t.Errorf("wifi after disable: %d", r.status)
	}
	// Disabling again is fine and revokes nothing new.
	if remaining, err := e.svc.DisableDevice(ctx, deviceID); err != nil || len(remaining) != 0 {
		t.Errorf("second disable: %v %v", remaining, err)
	}
	if n := len(e.bao.revoked["pki-radius"]) + len(e.bao.revoked["pki-enroll"]); n != 4 {
		t.Errorf("second disable revoked again: %d", n)
	}
	list, err := e.store.Devices(ctx)
	if err != nil || len(list) != 1 || list[0].Disabled == nil || list[0].WifiNotAfter != nil {
		t.Errorf("device list %+v %v", list, err)
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TestCodeFailures(t *testing.T) {
	e := newEnv(t)
	key := newKey(t, elliptic.P256())
	c := e.client(nil)

	if r := e.post(c, "device/simpleenroll", "", csrBody(t, key, "x")); r.status != 401 {
		t.Errorf("no code: %d", r.status)
	}

	// Expired.
	code := e.code("alice", "Phone")
	e.now = e.now.Add(16 * time.Minute)
	if r := e.post(c, "device/simpleenroll", code, csrBody(t, key, "x")); r.status != 401 {
		t.Errorf("expired code: %d", r.status)
	}

	// A bad CSR doesn't use up the code.
	code = e.code("alice", "Phone")
	bad := csrBody(t, key, "x")
	der, _ := base64.StdEncoding.DecodeString(string(bad))
	der[len(der)-3] ^= 0xff // inside the signature
	if r := e.post(c, "device/simpleenroll", code, []byte(base64.StdEncoding.EncodeToString(der))); r.status != 400 {
		t.Errorf("bad CSR signature: %d %s", r.status, r.body)
	}
	if r := e.post(c, "device/simpleenroll", code, []byte("not base64!")); r.status != 400 {
		t.Errorf("garbage body: %d", r.status)
	}
	if r := e.post(c, "device/simpleenroll", code, csrBody(t, key, "x")); r.status != 200 {
		t.Errorf("code after bad CSRs: %d %s", r.status, r.body)
	}

	// Disabled at use: the device is removed again.
	code = e.code("carol", "Phone")
	e.bao.groups["carol"] = "disabled"
	if r := e.post(c, "device/simpleenroll", code, csrBody(t, key, "x")); r.status != 403 {
		t.Errorf("disabled user: %d", r.status)
	}
	list, _ := e.store.Devices(context.Background())
	if len(list) != 1 {
		t.Errorf("devices after refused enrollment: %d", len(list))
	}

	// Codes for disabled or unknown users aren't created.
	for _, user := range []string{"bob", "nobody"} {
		if _, _, err := e.svc.CreateCode(context.Background(), user, "Phone"); !errors.Is(err, openbao.ErrUserNotEnabled) {
			t.Errorf("code for %s: %v", user, err)
		}
	}
	if _, _, err := e.svc.CreateCode(context.Background(), "alice", "bad/label"); err == nil {
		t.Error("label with / accepted")
	}
}

func TestCodeRateLimit(t *testing.T) {
	e := newEnv(t)
	c := e.client(nil)
	body := csrBody(t, newKey(t, elliptic.P256()), "x")
	good := e.code("alice", "Phone")
	for i := 0; i < codeFailLimit; i++ {
		if r := e.post(c, "device/simpleenroll", "WRONGCODE", body); r.status != 401 {
			t.Fatalf("wrong code %d: %d", i, r.status)
		}
	}
	r := e.post(c, "device/simpleenroll", good, body)
	if r.status != 429 || r.header.Get("Retry-After") == "" {
		t.Fatalf("after %d failures: %d", codeFailLimit, r.status)
	}
	e.now = e.now.Add(codeBlock)
	if r := e.post(c, "device/simpleenroll", e.code("alice", "Phone"), body); r.status != 200 {
		t.Errorf("after the block: %d %s", r.status, r.body)
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := 0; i < postBurst; i++ {
		if ok, _ := l.allow("a", now); !ok {
			t.Fatalf("request %d refused", i)
		}
	}
	if ok, wait := l.allow("a", now); ok || wait <= 0 {
		t.Error("burst exceeded but allowed")
	}
	if ok, _ := l.allow("b", now); !ok {
		t.Error("other client refused")
	}
	if ok, _ := l.allow("a", now.Add(7*time.Second)); !ok {
		t.Error("token not refilled")
	}
	// Global cap on wrong codes.
	for i := 0; i < globalFailLimit; i++ {
		l.codeFailed(clientKey("192.0.2."+string(rune('0'+i%10))+":1"), now)
	}
	if ok, _ := l.codeAllowed("fresh", now); ok {
		t.Error("global failure cap not applied")
	}
	if ok, _ := l.codeAllowed("fresh", now.Add(globalFailWindow)); !ok {
		t.Error("global cap not lifted after the window")
	}
}

func TestClientKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1:443":                 "192.0.2.1",
		"[2001:db8:1:2:3::4]:443":       "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff::1%eth0]:1": "2001:db8:1:2::/64",
		"[::ffff:192.0.2.9]:443":        "192.0.2.9",
	} {
		if got := clientKey(in); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestForeignClientCertificates(t *testing.T) {
	e := newEnv(t)
	devTLS, devCert := e.enrollDevice("alice")
	uri := devCert.URIs[0]
	body := csrBody(t, newKey(t, elliptic.P384()), "x")

	// Same root, other intermediates: refused even with the device's URI
	// and username, because only the device intermediate is trusted.
	for name, issuer := range map[string]*ca{"wifi CA": e.wifiCA, "other CA": e.otherCA} {
		key := newKey(t, elliptic.P256())
		cert := issue(t, issuer, &x509.Certificate{
			Subject: pkix.Name{CommonName: "alice"}, URIs: []*url.URL{uri},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, key.Public())
		r := e.post(e.client(tlsCert([]*x509.Certificate{cert, issuer.cert}, key)), "wifi/simpleenroll", "", body)
		if r.status == 200 {
			t.Errorf("%s: certificate accepted", name)
		}
	}

	// Right CA, but a certificate the service didn't record.
	key := newKey(t, elliptic.P256())
	forged := issue(t, e.deviceCA, &x509.Certificate{
		Subject: pkix.Name{CommonName: "alice"}, URIs: []*url.URL{uri},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, key.Public())
	if r := e.post(e.client(tlsCert([]*x509.Certificate{forged}, key)), "wifi/simpleenroll", "", body); r.status != 401 {
		t.Errorf("unrecorded device cert: %d", r.status)
	}

	// Revoked device credential.
	if err := e.store.MarkRevoked(context.Background(), store.KindDevice,
		openbao.SerialText(devCert.SerialNumber), e.now); err != nil {
		t.Fatal(err)
	}
	if r := e.post(e.client(devTLS), "wifi/simpleenroll", "", body); r.status != 401 {
		t.Errorf("revoked device cert: %d", r.status)
	}
}

func TestDisabledUserOnRenewal(t *testing.T) {
	e := newEnv(t)
	devTLS, _ := e.enrollDevice("alice")
	e.bao.groups["alice"] = "disabled"
	if r := e.post(e.client(devTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 403 {
		t.Errorf("disabled user: %d", r.status)
	}
	delete(e.bao.groups, "alice")
	if r := e.post(e.client(devTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 403 {
		t.Errorf("removed user: %d", r.status)
	}
}

func TestWrongCertificateFromOpenBao(t *testing.T) {
	e := newEnv(t)
	devTLS, _ := e.enrollDevice("alice")
	e.bao.wrongCN = true
	if r := e.post(e.client(devTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 502 {
		t.Errorf("wrong CN: %d", r.status)
	}
	if len(e.bao.revoked["pki-radius"]) != 1 || e.bao.rotates["pki-radius"] != 1 {
		t.Errorf("wrong certificate not revoked: %v %v", e.bao.revoked, e.bao.rotates)
	}
	e.bao.wrongCN = false
	e.bao.failSign = true
	if r := e.post(e.client(devTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 502 {
		t.Errorf("sign failure: %d", r.status)
	}
}

func TestDisableRetriesAfterRotateFailure(t *testing.T) {
	e := newEnv(t)
	_, devCert := e.enrollDevice("alice")
	id := strings.TrimPrefix(devCert.URIs[0].String(), "urn:uuid:")
	e.bao.failRot = true
	remaining, err := e.svc.DisableDevice(context.Background(), id)
	if err == nil || len(remaining) != 1 {
		t.Fatalf("disable with failing rotate: %v %v", remaining, err)
	}
	e.bao.failRot = false
	remaining, err = e.svc.DisableDevice(context.Background(), id)
	if err != nil || len(remaining) != 0 || e.bao.rotates["pki-enroll"] != 1 {
		t.Fatalf("retry: %v %v %v", remaining, err, e.bao.rotates)
	}
	if _, err := e.svc.DisableDevice(context.Background(), "00000000-0000-4000-8000-000000000000"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown device: %v", err)
	}
}

func TestRequestLimits(t *testing.T) {
	e := newEnv(t)
	code := e.code("alice", "Phone")
	big := bytes.Repeat([]byte("A"), maxBody+1)
	if r := e.post(e.client(nil), "device/simpleenroll", code, big); r.status != 413 {
		t.Errorf("large body: %d", r.status)
	}
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+estPrefix+"device/simpleenroll", nil)
	if r := e.do(e.client(nil), req); r.status != 405 {
		t.Errorf("GET simpleenroll: %d", r.status)
	}
	req, _ = http.NewRequest(http.MethodGet, e.srv.URL+estPrefix+"other/cacerts", nil)
	if r := e.do(e.client(nil), req); r.status != 404 {
		t.Errorf("unknown label: %d", r.status)
	}
	req, _ = http.NewRequest(http.MethodGet, e.srv.URL+estPrefix+"wifi/cacerts", nil)
	r := e.do(e.client(nil), req)
	if r.status != 200 || len(r.certs) != 2 || !r.certs[0].Equal(e.wifiCA.cert) {
		t.Errorf("wifi cacerts: %d %d", r.status, len(r.certs))
	}
}

func TestPKCS7(t *testing.T) {
	root := newRoot(t, "Root")
	inter := root.intermediate(t, "Inter")
	der, err := certsOnly([]*x509.Certificate{inter.cert, root.cert})
	if err != nil {
		t.Fatal(err)
	}
	certs, err := parseCertsOnly(der)
	if err != nil || len(certs) != 2 || !certs[0].Equal(inter.cert) || !certs[1].Equal(root.cert) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := certsOnly(nil); err == nil {
		t.Error("empty list encoded")
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	cmd := exec.Command(openssl, "pkcs7", "-inform", "DER", "-print_certs", "-noout")
	cmd.Stdin = bytes.NewReader(der)
	out, err := cmd.CombinedOutput()
	if err != nil || !regexp.MustCompile(`subject=CN ?= ?Inter`).Match(out) || !regexp.MustCompile(`subject=CN ?= ?Root`).Match(out) {
		t.Errorf("openssl: %v\n%s", err, out)
	}
}

func TestClientCAPoolRefusesRoot(t *testing.T) {
	root := newRoot(t, "Root")
	dir := t.TempDir()
	if _, err := clientCAPool(writeFile(t, dir, "ca.pem", pemCert(root.cert))); err == nil {
		t.Error("self-signed root accepted as device CA")
	}
	inter := root.intermediate(t, "Inter")
	if _, err := clientCAPool(writeFile(t, dir, "ca2.pem", pemCert(inter.cert))); err != nil {
		t.Error(err)
	}
}

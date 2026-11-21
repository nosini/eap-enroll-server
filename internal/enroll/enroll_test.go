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
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
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

	// Device renewal: the old credential works until the new one is
	// used, then it is revoked.
	newDeviceKey := newKey(t, elliptic.P384())
	r = e.post(device, "device/simplereenroll", "", csrBody(t, newDeviceKey, "x"))
	if r.status != 200 || r.certs[0].URIs[0].String() != "urn:uuid:"+deviceID {
		t.Fatalf("reenroll: %d %s", r.status, r.body)
	}
	renewed := e.client(tlsCert(r.certs, newDeviceKey))
	if r := e.post(device, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 200 {
		t.Errorf("old credential before the new one is used: %d %s", r.status, r.body)
	}
	if r := e.post(renewed, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 200 {
		t.Errorf("wifi with renewed credential: %d %s", r.status, r.body)
	}
	if !contains(e.bao.revoked["pki-enroll"], colonHex(devCert.SerialNumber)) || e.bao.rotates["pki-enroll"] != 1 {
		t.Errorf("old device credential not revoked: %v %v", e.bao.revoked, e.bao.rotates)
	}
	if r := e.post(device, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 403 || !strings.Contains(r.body, "device is disabled") {
		t.Errorf("old credential after the new one was used: %d %s", r.status, r.body)
	}
	if e.events("credential_reuse") != 1 {
		t.Errorf("credential_reuse logged %d times", e.events("credential_reuse"))
	}

	// No client certificate.
	if r := e.post(e.client(nil), "wifi/simpleenroll", "", csrBody(t, wifiKey, "x")); r.status != 401 {
		t.Errorf("wifi without client cert: %d", r.status)
	}

	// The reuse detection disabled the device and revoked the rest;
	// disabling again revokes nothing new.
	remaining, err := e.svc.DisableDevice(ctx, deviceID)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("disable: %v %v", remaining, err)
	}
	if n := len(e.bao.revoked["pki-radius"]); n != 3 {
		t.Errorf("wifi revocations %d, want 3", n)
	}
	if n := len(e.bao.revoked["pki-enroll"]); n != 2 {
		t.Errorf("device revocations %d, want 2", n)
	}
	if e.bao.rotates["pki-radius"] != 1 || e.bao.rotates["pki-enroll"] != 2 {
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
	if n := len(e.bao.revoked["pki-radius"]) + len(e.bao.revoked["pki-enroll"]); n != 5 {
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

// Every refusal names its reason in an Enroll-Error response header;
// the client uses it to tell refusals apart that share a status.
func TestEnrollErrorHeader(t *testing.T) {
	e := newEnv(t)
	key := newKey(t, elliptic.P256())
	c := e.client(nil)

	if r := e.post(c, "device/simpleenroll", "", csrBody(t, key, "x")); r.status != 401 ||
		r.header.Get("Enroll-Error") != "no_code" {
		t.Errorf("no code: %d %q", r.status, r.header.Get("Enroll-Error"))
	}
	if r := e.post(c, "device/simpleenroll", "WRONGCODE", csrBody(t, key, "x")); r.status != 401 ||
		r.header.Get("Enroll-Error") != "bad_code" {
		t.Errorf("wrong code: %d %q", r.status, r.header.Get("Enroll-Error"))
	}
	code := e.code("alice", "Phone")
	e.now = e.now.Add(16 * time.Minute)
	if r := e.post(c, "device/simpleenroll", code, csrBody(t, key, "x")); r.status != 401 ||
		r.header.Get("Enroll-Error") != "code_expired" {
		t.Errorf("expired code: %d %q", r.status, r.header.Get("Enroll-Error"))
	}
	bad := csrBody(t, key, "x")
	der, _ := base64.StdEncoding.DecodeString(string(bad))
	der[len(der)-3] ^= 0xff // inside the signature
	code = e.code("alice", "Phone")
	if r := e.post(c, "device/simpleenroll", code, []byte(base64.StdEncoding.EncodeToString(der))); r.status != 400 ||
		r.header.Get("Enroll-Error") != "bad_csr" {
		t.Errorf("bad CSR: %d %q", r.status, r.header.Get("Enroll-Error"))
	}
}

func TestCodeRateLimit(t *testing.T) {
	e := newEnv(t)
	body := csrBody(t, newKey(t, elliptic.P256()), "x")
	const remote = "192.0.2.10:1234"
	// Five wrong codes use up the burst of the client's token bucket and
	// block the key.
	for i := 0; i < codeFailLimit; i++ {
		if r := e.postDirect(remote, "device/simpleenroll", "WRONGCODE", body); r.status != 401 {
			t.Fatalf("wrong code %d: %d", i, r.status)
		}
	}
	// The bucket is empty now.
	if r := e.postDirect(remote, "device/simpleenroll", "WRONGCODE", body); r.status != 429 || r.header.Get("Retry-After") == "" {
		t.Fatalf("empty bucket: %d", r.status)
	} else if r.header.Get("Enroll-Error") != "rate_limited" {
		t.Errorf("rate limited: Enroll-Error %q", r.header.Get("Enroll-Error"))
	}
	// A valid code bypasses the block and the empty bucket.
	if r := e.postDirect(remote, "device/simpleenroll", e.code("alice", "Phone"), body); r.status != 200 {
		t.Errorf("valid code from a blocked client: %d %s", r.status, r.body)
	}
	// Once the bucket has refilled, the block still refuses wrong codes,
	// but not a valid one.
	e.now = e.now.Add(time.Minute)
	if r := e.postDirect(remote, "device/simpleenroll", "WRONGCODE", body); r.status != 429 {
		t.Errorf("blocked code: %d", r.status)
	}
	if r := e.postDirect(remote, "device/simpleenroll", e.code("alice", "Phone"), body); r.status != 200 {
		t.Errorf("valid code while blocked: %d %s", r.status, r.body)
	}
}

func TestGlobalCodeFailuresWarning(t *testing.T) {
	e := newEnv(t)
	body := csrBody(t, newKey(t, elliptic.P256()), "x")
	// Failures from many client keys only log one warning and don't stop
	// code enrollment for anyone.
	for i := 0; i < globalFailLimit+5; i++ {
		remote := "192.0.2." + strconv.Itoa(i) + ":1234"
		if r := e.postDirect(remote, "device/simpleenroll", "WRONGCODE", body); r.status != 401 {
			t.Fatalf("wrong code %d: %d", i, r.status)
		}
	}
	if n := e.events("code_failures_high"); n != 1 {
		t.Errorf("code_failures_high logged %d times, want 1", n)
	}
	if r := e.post(e.client(nil), "device/simpleenroll", e.code("alice", "Phone"), body); r.status != 200 {
		t.Errorf("valid code after many failures: %d %s", r.status, r.body)
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(postBurst)
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
	// Wrong codes from all clients only warn, once per window.
	warned := 0
	for i := 0; i < globalFailLimit+5; i++ {
		if l.codeFailed("192.0.2.5", now) {
			warned++
		}
	}
	if warned != 1 {
		t.Errorf("global warning %d times, want 1", warned)
	}
	if ok, _ := l.codeAllowed("fresh", now); !ok {
		t.Error("global failures refuse a fresh client")
	}
	warned = 0
	for i := 0; i < globalFailLimit; i++ {
		if l.codeFailed("192.0.2.6", now.Add(globalFailWindow)) {
			warned++
		}
	}
	if warned != 1 {
		t.Error("global warning not logged again in a new window")
	}
}

func TestLimiterFull(t *testing.T) {
	now := time.Now()
	l := newLimiter(postBurst)
	l.max = 3
	for _, k := range []string{"a", "b", "c"} {
		if ok, _ := l.allow(k, now); !ok {
			t.Fatalf("%s refused", k)
		}
	}
	// A full map makes room instead of refusing a new key.
	if ok, _ := l.allow("d", now); !ok {
		t.Fatal("new key refused when the map is full")
	}
	if len(l.clients) != 3 {
		t.Errorf("map holds %d entries, want 3", len(l.clients))
	}
	// Full and idle: entries are swept at once.
	now = now.Add(idleExpiry + time.Minute)
	if ok, _ := l.allow("e", now); !ok {
		t.Error("new key refused after idle sweep")
	}
	if len(l.clients) != 1 {
		t.Errorf("idle entries not swept: %d left", len(l.clients))
	}

	// Blocked entries are evicted last.
	l = newLimiter(postBurst)
	l.max = 2
	l.allow("blocked", now)
	for i := 0; i < codeFailLimit; i++ {
		l.codeFailed("blocked", now)
	}
	l.allow("idle", now)
	if ok, _ := l.allow("new", now); !ok {
		t.Fatal("new key refused")
	}
	if l.clients["blocked"] == nil {
		t.Error("blocked entry evicted")
	}
	if l.clients["idle"] != nil {
		t.Error("unblocked entry not evicted first")
	}
	if l.clients["new"] == nil {
		t.Error("new entry missing")
	}

	// Even a map full of blocked entries takes a new key.
	l = newLimiter(postBurst)
	l.max = 1
	l.allow("one", now)
	for i := 0; i < codeFailLimit; i++ {
		l.codeFailed("one", now)
	}
	if ok, _ := l.allow("two", now); !ok {
		t.Error("new key refused when all entries are blocked")
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

	// A revoked device credential of an enabled device is a superseded
	// one being reused: the device is disabled.
	if err := e.store.MarkRevoked(context.Background(), store.KindDevice,
		openbao.SerialText(devCert.SerialNumber), e.now); err != nil {
		t.Fatal(err)
	}
	if r := e.post(e.client(devTLS), "wifi/simpleenroll", "", body); r.status != 403 || !strings.Contains(r.body, "device is disabled") {
		t.Errorf("revoked device cert: %d %s", r.status, r.body)
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
	var revErr *RevocationError
	if !errors.As(err, &revErr) || len(remaining) != 1 {
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

// When the device can't be marked disabled, the error says so: it is not
// a RevocationError, and credential reuse isn't reported as disabled.
func TestDisableFailureIsNotDisabled(t *testing.T) {
	e := newEnv(t)
	oldTLS, devCert := e.enrollDevice("alice")
	id := strings.TrimPrefix(devCert.URIs[0].String(), "urn:uuid:")
	k := newKey(t, elliptic.P256())
	r := e.post(e.client(oldTLS), "device/simplereenroll", "", csrBody(t, k, "x"))
	if r.status != 200 {
		t.Fatalf("renew: %d %s", r.status, r.body)
	}
	if r := e.post(e.client(tlsCert(r.certs, k)), "wifi/confirm", "", []byte("zz")); r.status != 400 {
		t.Fatalf("renewed credential: %d %s", r.status, r.body)
	}

	// A trigger makes disabling fail while reads still work.
	db, err := sql.Open("sqlite", e.svc.cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER no_disable BEFORE UPDATE OF disabled ON devices
		BEGIN SELECT RAISE(ABORT, 'disable blocked'); END`); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.DisableDevice(context.Background(), id)
	var revErr *RevocationError
	if err == nil || errors.As(err, &revErr) {
		t.Errorf("failed disable: %v", err)
	}
	r = e.post(e.client(oldTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x"))
	if r.status != 500 || e.events("disable_failed") != 1 {
		t.Errorf("reuse while disabling fails: %d %s, disable_failed %d", r.status, r.body, e.events("disable_failed"))
	}
	if _, err := db.Exec(`DROP TRIGGER no_disable`); err != nil {
		t.Fatal(err)
	}
	if r := e.post(e.client(oldTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 403 {
		t.Errorf("reuse once disabling works: %d %s", r.status, r.body)
	}
}

func TestPruneDevices(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	devTLS, devCert := e.enrollDevice("alice")
	id := strings.TrimPrefix(devCert.URIs[0].String(), "urn:uuid:")
	other, _ := e.enrollDevice("alice")

	// A disable whose CRL rotation failed leaves the device pending.
	e.bao.failRot = true
	if _, err := e.svc.DisableDevice(ctx, id); err == nil {
		t.Fatal("disable with failing rotate succeeded")
	}
	pruned, pending, err := e.svc.PruneDevices(ctx)
	if err != nil || len(pruned) != 0 || len(pending) != 1 || pending[0].ID != id {
		t.Fatalf("prune before the revocation: %v %v %v", pruned, pending, err)
	}
	e.bao.failRot = false
	if remaining, err := e.svc.DisableDevice(ctx, id); err != nil || len(remaining) != 0 {
		t.Fatalf("disable retry: %v %v", remaining, err)
	}

	pruned, pending, err = e.svc.PruneDevices(ctx)
	if err != nil || len(pruned) != 1 || pruned[0].ID != id || len(pending) != 0 {
		t.Fatalf("prune: %v %v %v", pruned, pending, err)
	}
	if e.events("device_deleted") != 1 {
		t.Errorf("device_deleted logged %d times", e.events("device_deleted"))
	}
	// The deleted device's credential is now unknown; the other device
	// is untouched.
	r := e.post(e.client(devTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x"))
	if r.status != 401 || r.header.Get("Enroll-Error") != "unknown_cert" {
		t.Errorf("deleted device's credential: %d %q", r.status, r.header.Get("Enroll-Error"))
	}
	if r := e.post(e.client(other), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 200 {
		t.Errorf("other device after prune: %d %s", r.status, r.body)
	}
	list, err := e.store.Devices(ctx)
	if err != nil || len(list) != 1 || list[0].ID == id {
		t.Errorf("device list after prune: %+v %v", list, err)
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

func TestConfirmWifi(t *testing.T) {
	e := newEnv(t)
	devTLS, _ := e.enrollDevice("alice")
	c := e.client(devTLS)
	var wifi []*x509.Certificate
	for i := 0; i < 3; i++ {
		r := e.post(c, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x"))
		if r.status != 200 {
			t.Fatalf("wifi %d: %d", i, r.status)
		}
		wifi = append(wifi, r.certs[0])
	}
	// Confirming the second revokes only the first.
	colon := colonHex(wifi[1].SerialNumber)
	if r := e.post(c, "wifi/confirm", "", []byte(strings.ToUpper(colon)+"\n")); r.status != 204 {
		t.Fatalf("confirm: %d %s", r.status, r.body)
	}
	if got := e.bao.revoked["pki-radius"]; len(got) != 1 || got[0] != colonHex(wifi[0].SerialNumber) {
		t.Errorf("revoked %v", got)
	}
	// Again: nothing new. Then the third revokes the second.
	if r := e.post(c, "wifi/confirm", "", []byte(colon)); r.status != 204 || len(e.bao.revoked["pki-radius"]) != 1 {
		t.Errorf("repeated confirm: %d %v", r.status, e.bao.revoked)
	}
	if r := e.post(c, "wifi/confirm", "", []byte(openbao.SerialText(wifi[2].SerialNumber))); r.status != 204 {
		t.Errorf("confirm third: %d", r.status)
	}
	if n := len(e.bao.revoked["pki-radius"]); n != 2 {
		t.Errorf("revocations %d, want 2", n)
	}
	// A revoked one, someone else's, or garbage.
	if r := e.post(c, "wifi/confirm", "", []byte(colon)); r.status != 400 {
		t.Errorf("confirm revoked: %d", r.status)
	}
	otherTLS, _ := e.enrollDevice("carol")
	if r := e.post(e.client(otherTLS), "wifi/confirm", "", []byte(openbao.SerialText(wifi[2].SerialNumber))); r.status != 400 {
		t.Errorf("confirm another device's certificate: %d", r.status)
	}
	if r := e.post(c, "wifi/confirm", "", []byte("not hex")); r.status != 400 {
		t.Errorf("confirm garbage: %d", r.status)
	}
	if r := e.post(e.client(nil), "wifi/confirm", "", []byte(colon)); r.status != 401 {
		t.Errorf("confirm without client cert: %d", r.status)
	}
}

func TestWifiProfile(t *testing.T) {
	e := newEnv(t)
	devTLS, _ := e.enrollDevice("alice")
	get := func(c *http.Client) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+estPrefix+"wifi/profile", nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get(e.client(devTLS)); code != 404 {
		t.Errorf("profile without configuration: %d", code)
	}

	e = newEnvWith(t, func(cfg map[string]any, dir string) {
		cfg["wifi_profile"] = map[string]any{
			"ssid": "Home Net", "server_domain": "radius.example.org",
			"server_ca_file": writeFile(t, dir, "radius-ca.pem", pemCert(e.root.cert)),
		}
	})
	devTLS, _ = e.enrollDevice("alice")
	if code, _ := get(e.client(nil)); code != 401 {
		t.Errorf("profile without client cert: %d", code)
	}
	code, body := get(e.client(devTLS))
	var p wifiProfile
	if code != 200 || json.Unmarshal([]byte(body), &p) != nil {
		t.Fatalf("profile: %d %s", code, body)
	}
	if p.SSID != "Home Net" || p.ServerDomain != "radius.example.org" || len(p.ServerCACertificates) != 1 {
		t.Errorf("profile %+v", p)
	}
	if c, err := x509.ParseCertificate(p.ServerCACertificates[0]); err != nil || c.Subject.CommonName != "Test Root" {
		t.Errorf("profile CA: %v", err)
	}
}

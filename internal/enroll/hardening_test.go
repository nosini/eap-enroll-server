// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package enroll

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nosini/eap-enroll-server/internal/openbao"
	"github.com/nosini/eap-enroll-server/internal/store"
)

func TestAuthenticatedRateLimits(t *testing.T) {
	e := newEnv(t)
	devTLS, _ := e.enrollDevice("alice")
	body := csrBody(t, newKey(t, elliptic.P384()), "x")

	// Failed authentications use up the client address's bucket.
	for i := 0; i < postBurst; i++ {
		if r := e.postBurst(e.client(nil), "wifi/simpleenroll", "", body); r.status != 401 {
			t.Fatalf("authentication failure %d: %d", i, r.status)
		}
	}
	if r := e.postBurst(e.client(nil), "wifi/simpleenroll", "", body); r.status != 429 || r.header.Get("Retry-After") == "" {
		t.Fatalf("empty address bucket: %d", r.status)
	}

	// A valid device credential isn't limited by the address.
	device := e.client(devTLS)
	if r := e.postBurst(device, "wifi/simpleenroll", "", body); r.status != 200 {
		t.Fatalf("valid credential with an empty address bucket: %d %s", r.status, r.body)
	}
	// It has its own bucket. Bad confirmations (400) issue nothing, so
	// the per-device certificate caps don't interfere.
	for i := 1; i < deviceBurst; i++ {
		if r := e.postBurst(device, "wifi/confirm", "", []byte("zz")); r.status != 400 {
			t.Fatalf("per-device request %d: %d %s", i, r.status, r.body)
		}
	}
	r := e.postBurst(device, "wifi/confirm", "", []byte("zz"))
	if r.status != 429 || r.header.Get("Retry-After") == "" || !strings.Contains(r.body, "too many requests") {
		t.Errorf("per-device bucket: %d %s", r.status, r.body)
	}
}

func TestCredentialReuse(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	oldTLS, oldCert := e.enrollDevice("alice")
	id := strings.TrimPrefix(oldCert.URIs[0].String(), "urn:uuid:")

	renewKey := newKey(t, elliptic.P256())
	r := e.post(e.client(oldTLS), "device/simplereenroll", "", csrBody(t, renewKey, "x"))
	if r.status != 200 {
		t.Fatalf("renew: %d %s", r.status, r.body)
	}
	newCert := r.certs[0]
	newTLS := tlsCert(r.certs, renewKey)

	// Using the renewed credential retires the old one.
	if r := e.post(e.client(newTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 200 {
		t.Fatalf("wifi with the renewed credential: %d %s", r.status, r.body)
	}
	if !contains(e.bao.revoked["pki-enroll"], colonHex(oldCert.SerialNumber)) {
		t.Fatal("old credential not revoked")
	}

	// Using the old one is reuse: the device is disabled and its
	// certificates are revoked.
	r = e.post(e.client(oldTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x"))
	if r.status != 403 || !strings.Contains(r.body, "device is disabled") {
		t.Fatalf("reused credential: %d %s", r.status, r.body)
	}
	dev, err := e.store.Device(ctx, id)
	if err != nil || dev.Disabled == nil {
		t.Errorf("device after reuse: %+v %v", dev, err)
	}
	if !contains(e.bao.revoked["pki-enroll"], colonHex(newCert.SerialNumber)) {
		t.Error("current device credential not revoked")
	}
	if n := len(e.bao.revoked["pki-radius"]); n != 1 {
		t.Errorf("wifi revocations %d, want 1", n)
	}
	if n := e.events("credential_reuse"); n != 1 {
		t.Errorf("credential_reuse logged %d times", n)
	}

	// The renewed credential is refused too.
	if r := e.post(e.client(newTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 403 {
		t.Errorf("renewed credential after reuse: %d %s", r.status, r.body)
	}
}

// testMaxValidWifi mirrors the store's cap on valid Wi-Fi certificates
// per device.
const testMaxValidWifi = 5

func TestPerDeviceCertificateLimits(t *testing.T) {
	e := newEnv(t)
	devTLS, _ := e.enrollDevice("alice")
	device := e.client(devTLS)
	issueWifi := func() *x509.Certificate {
		t.Helper()
		r := e.post(device, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x"))
		if r.status != 200 {
			t.Fatalf("wifi: %d %s", r.status, r.body)
		}
		return r.certs[0]
	}
	confirm := func(c *x509.Certificate) {
		t.Helper()
		if r := e.post(device, "wifi/confirm", "", []byte(openbao.SerialText(c.SerialNumber))); r.status != 204 {
			t.Fatalf("confirm: %d %s", r.status, r.body)
		}
	}

	var wifi []*x509.Certificate
	for i := 0; i < testMaxValidWifi; i++ {
		wifi = append(wifi, issueWifi())
	}
	r := e.post(device, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x"))
	if r.status != 429 || r.header.Get("Retry-After") != "3600" {
		t.Fatalf("sixth valid wifi certificate: %d %q", r.status, r.header.Get("Retry-After"))
	}

	// Confirming frees slots, but ten certificates per 24 hours is the
	// limit, revoked ones included.
	confirm(wifi[testMaxValidWifi-1])
	for i := 0; i < 4; i++ {
		wifi = append(wifi, issueWifi())
	}
	confirm(wifi[len(wifi)-1])
	issueWifi() // the tenth in 24 hours
	r = e.post(device, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x"))
	if r.status != 429 || r.header.Get("Retry-After") != "3600" {
		t.Fatalf("eleventh wifi certificate in 24 hours: %d %q", r.status, r.header.Get("Retry-After"))
	}

	// Once the window has passed it works again.
	e.now = e.now.Add(24*time.Hour + time.Minute)
	issueWifi()
}

func TestPerDeviceCredentialLimits(t *testing.T) {
	e := newEnv(t)
	devTLS, _ := e.enrollDevice("alice")
	device := e.client(devTLS)
	// Two renewals leave three valid device credentials; using none of
	// them retires the older ones.
	for i := 0; i < 2; i++ {
		if r := e.post(device, "device/simplereenroll", "", csrBody(t, newKey(t, elliptic.P256()), "x")); r.status != 200 {
			t.Fatalf("renewal %d: %d %s", i, r.status, r.body)
		}
	}
	r := e.post(device, "device/simplereenroll", "", csrBody(t, newKey(t, elliptic.P256()), "x"))
	if r.status != 429 || r.header.Get("Retry-After") != "3600" {
		t.Errorf("fourth valid device credential: %d %q", r.status, r.header.Get("Retry-After"))
	}
}

func TestDisabledUserOnEveryEndpoint(t *testing.T) {
	radiusCA := newRoot(t, "Test RADIUS CA")
	e := newEnvWith(t, func(cfg map[string]any, dir string) {
		cfg["wifi_profile"] = map[string]any{
			"ssid": "Home Net", "server_domain": "radius.example.org",
			"server_ca_file": writeFile(t, dir, "radius-ca.pem", pemCert(radiusCA.cert)),
		}
	})
	devTLS, _ := e.enrollDevice("alice")
	device := e.client(devTLS)
	r := e.post(device, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x"))
	if r.status != 200 {
		t.Fatalf("wifi enroll: %d %s", r.status, r.body)
	}
	serial := openbao.SerialText(r.certs[0].SerialNumber)

	e.bao.groups["alice"] = "disabled"
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+estPrefix+"wifi/profile", nil)
	profile := e.do(device, req)
	confirm := e.post(device, "wifi/confirm", "", []byte(serial))
	enroll := e.post(device, "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x"))
	if profile.status != 403 || !strings.Contains(profile.body, "user is not enabled") {
		t.Errorf("profile: %d %s", profile.status, profile.body)
	}
	if confirm.status != 403 {
		t.Errorf("confirm: %d %s", confirm.status, confirm.body)
	}
	if enroll.status != 403 {
		t.Errorf("simpleenroll: %d %s", enroll.status, enroll.body)
	}
	for _, r := range []result{profile, confirm, enroll} {
		if re := r.header.Get("Enroll-Error"); re != "user_disabled" {
			t.Errorf("%d: Enroll-Error %q, want user_disabled", r.status, re)
		}
	}
	if !strings.Contains(e.logs.String(), `"reason":"user_disabled"`) {
		t.Error("user_disabled not logged")
	}
}

// testCSR builds and parses a CSR for key.
func testCSR(t testing.TB, key crypto.Signer) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "alice"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestCheckIssued(t *testing.T) {
	root := newRoot(t, "Root")
	wifiCA := root.intermediate(t, "Wi-Fi CA")
	deviceCA := root.intermediate(t, "Device CA")
	otherCA := root.intermediate(t, "Other CA")
	now := time.Now()
	key := newKey(t, elliptic.P384())
	csr := testCSR(t, key)

	wifi := profile{kind: store.KindWifi, ttlD: 24 * time.Hour, issuers: []*x509.Certificate{wifiCA.cert}}
	device := profile{kind: store.KindDevice, ttlD: 24 * time.Hour, issuers: []*x509.Certificate{deviceCA.cert}}
	base := func() *x509.Certificate {
		return &x509.Certificate{
			Subject:     pkix.Name{CommonName: "alice"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			NotAfter:    now.Add(time.Hour),
		}
	}
	issued := func(issuer *ca, tmpl *x509.Certificate, chain bool) *openbao.Signed {
		s := &openbao.Signed{Certificate: issue(t, issuer, tmpl, key.Public())}
		if chain {
			s.Chain = []*x509.Certificate{issuer.cert}
		}
		return s
	}
	withSAN := func(value []byte) *x509.Certificate {
		tmpl := base()
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidSubjectAltName, Value: value}}
		return tmpl
	}
	// An empty GeneralNames SEQUENCE holding one otherName.
	otherName := []byte{0x30, 0x02, 0xa0, 0x00}

	if err := checkIssued(issued(wifiCA, base(), true), csr, "alice", "", wifi, now); err != nil {
		t.Fatalf("good certificate: %v", err)
	}
	if err := checkIssued(issued(otherCA, base(), false), csr, "alice", "", wifi, now); err == nil {
		t.Error("certificate from another CA accepted")
	}
	if err := checkIssued(issued(wifiCA, withSAN(otherName), true), csr, "alice", "", wifi, now); err == nil {
		t.Error("otherName SAN accepted")
	}

	twoCN := base()
	twoCN.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: oidCommonName, Value: "mallory"}}
	if err := checkIssued(issued(wifiCA, twoCN, true), csr, "alice", "", wifi, now); err == nil {
		t.Error("two CN attributes accepted")
	}
	uid := base()
	uid.Subject.ExtraNames = []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "alice"},
	}
	if err := checkIssued(issued(wifiCA, uid, true), csr, "alice", "", wifi, now); err == nil {
		t.Error("UID subject attribute accepted")
	}
	long := base()
	long.NotAfter = now.Add(24*time.Hour + 10*time.Minute)
	if err := checkIssued(issued(wifiCA, long, true), csr, "alice", "", wifi, now); err == nil {
		t.Error("certificate that outlives the TTL accepted")
	}
	certSign := base()
	certSign.KeyUsage |= x509.KeyUsageCertSign
	if err := checkIssued(issued(wifiCA, certSign, true), csr, "alice", "", wifi, now); err == nil {
		t.Error("keyCertSign without basicConstraints accepted")
	}
	crlSign := base()
	crlSign.KeyUsage |= x509.KeyUsageCRLSign
	if err := checkIssued(issued(wifiCA, crlSign, true), csr, "alice", "", wifi, now); err == nil {
		t.Error("cRLSign accepted")
	}
	isCA := base()
	isCA.BasicConstraintsValid, isCA.IsCA = true, true
	if err := checkIssued(issued(wifiCA, isCA, true), csr, "alice", "", wifi, now); err == nil {
		t.Error("CA certificate accepted")
	}
	for name, ekus := range map[string][]x509.ExtKeyUsage{
		"no EKU":       nil,
		"serverAuth":   {x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		"anyEKU":       {x509.ExtKeyUsageAny},
		"OCSP signing": {x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageOCSPSigning},
		"code signing": {x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning},
	} {
		tmpl := base()
		tmpl.ExtKeyUsage = ekus
		if err := checkIssued(issued(wifiCA, tmpl, true), csr, "alice", "", wifi, now); err == nil {
			t.Errorf("EKU %s accepted", name)
		}
	}
	unknownEKU := base()
	unknownEKU.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}} // smartcard logon
	if err := checkIssued(issued(wifiCA, unknownEKU, true), csr, "alice", "", wifi, now); err == nil {
		t.Error("unknown extra EKU accepted")
	}
	otherKey := newKey(t, elliptic.P384())
	if err := checkIssued(&openbao.Signed{Certificate: issue(t, wifiCA, base(), otherKey.Public())},
		csr, "alice", "", wifi, now); err == nil {
		t.Error("certificate for another key accepted")
	}
	expired := base()
	expired.NotBefore, expired.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Minute)
	if err := checkIssued(issued(wifiCA, expired, true), csr, "alice", "", wifi, now); err == nil {
		t.Error("expired certificate accepted")
	}
	wrongChain := issued(wifiCA, base(), false)
	wrongChain.Chain = []*x509.Certificate{otherCA.cert}
	if err := checkIssued(wrongChain, csr, "alice", "", wifi, now); err == nil {
		t.Error("certificate not signed by the first CA of the returned chain accepted")
	}
	critical := base()
	critical.ExtraExtensions = []pkix.Extension{
		{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0x00}},
	}
	if err := checkIssued(issued(wifiCA, critical, true), csr, "alice", "", wifi, now); err == nil {
		t.Error("unhandled critical extension accepted")
	}

	// Device credentials: exactly one URI SAN, the device's.
	const uri = "urn:uuid:00000000-0000-4000-8000-000000000001"
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	withURI := base()
	withURI.URIs = []*url.URL{u}
	if err := checkIssued(issued(deviceCA, withURI, true), csr, "alice", uri, device, now); err != nil {
		t.Fatalf("good device credential: %v", err)
	}
	if err := checkIssued(issued(deviceCA, withSAN(otherName), true), csr, "alice", uri, device, now); err == nil {
		t.Error("device credential with an otherName SAN accepted")
	}
	if err := checkIssued(issued(deviceCA, base(), true), csr, "alice", uri, device, now); err == nil {
		t.Error("device credential without a URI SAN accepted")
	}
	if err := checkIssued(issued(deviceCA, withURI, true), csr, "alice", uri+"0", device, now); err == nil {
		t.Error("device credential with the wrong URI accepted")
	}
}

func TestWrongSANFromOpenBao(t *testing.T) {
	e := newEnv(t)
	devTLS, _ := e.enrollDevice("alice")
	e.bao.mutate = func(tmpl *x509.Certificate) {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions,
			pkix.Extension{Id: oidSubjectAltName, Value: []byte{0x30, 0x02, 0xa0, 0x00}})
	}
	if r := e.post(e.client(devTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 502 {
		t.Errorf("otherName SAN: %d %s", r.status, r.body)
	}
	if len(e.bao.revoked["pki-radius"]) != 1 || e.bao.rotates["pki-radius"] != 1 {
		t.Errorf("wrong certificate not revoked: %v %v", e.bao.revoked, e.bao.rotates)
	}
}

func TestWrongIssuerFromOpenBao(t *testing.T) {
	e := newEnv(t)
	devTLS, _ := e.enrollDevice("alice")
	// Another CA signs and no chain is returned, so only the configured
	// issuers can catch it.
	e.bao.signCA = e.otherCA
	e.bao.emptyChain = true
	if r := e.post(e.client(devTLS), "wifi/simpleenroll", "", csrBody(t, newKey(t, elliptic.P384()), "x")); r.status != 502 {
		t.Errorf("wrong issuer: %d %s", r.status, r.body)
	}
	if len(e.bao.revoked["pki-radius"]) != 1 || e.bao.rotates["pki-radius"] != 1 {
		t.Errorf("wrong certificate not revoked: %v %v", e.bao.revoked, e.bao.rotates)
	}
}

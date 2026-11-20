// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package enroll

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

var testAttestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

func attLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func attTLV(first byte, content []byte) []byte {
	return append([]byte{first}, append(attLength(len(content)), content...)...)
}

func attSequence(parts ...[]byte) []byte {
	return attTLV(0x30, bytes.Join(parts, nil))
}

func attSet(parts ...[]byte) []byte {
	return attTLV(0x31, bytes.Join(parts, nil))
}

func attOctets(b []byte) []byte {
	return attTLV(0x04, b)
}

func attInteger(n int) []byte {
	b, _ := asn1.Marshal(n)
	return b
}

func attEnumerated(n int) []byte {
	b, _ := asn1.Marshal(asn1.Enumerated(n))
	return b
}

func attBoolean(v bool) []byte {
	b, _ := asn1.Marshal(v)
	return b
}

// attContextField encodes an EXPLICIT context-specific tagged field with
// the high-tag-number form for tags above 30.
func attContextField(tag int, inner []byte) []byte {
	var header []byte
	if tag < 31 {
		header = []byte{0xa0 | byte(tag)}
	} else {
		header = []byte{0xbf}
		var enc []byte
		for n := tag; ; n >>= 7 {
			enc = append([]byte{byte(n & 0x7f)}, enc...)
			if n < 0x80 {
				break
			}
		}
		for i := 0; i < len(enc)-1; i++ {
			enc[i] |= 0x80
		}
		header = append(header, enc...)
	}
	return append(header, append(attLength(len(inner)), inner...)...)
}

type attField struct {
	tag   int
	value []byte
}

func attAuthorizationList(fields ...attField) []byte {
	var parts [][]byte
	for _, f := range fields {
		parts = append(parts, attContextField(f.tag, f.value))
	}
	return attSequence(parts...)
}

// attKeyDescription builds a valid TEE key description: generated, SIGN,
// locked, SelfSigned verified boot.
func attKeyDescription(challenge []byte) []byte {
	bootKey := bytes.Repeat([]byte{0x5a}, 32)
	rootOfTrust := attSequence(attOctets(bootKey), attBoolean(true), attEnumerated(1))
	hardware := attAuthorizationList(
		attField{1, attSet(attInteger(2))},
		attField{702, attInteger(0)},
		attField{704, rootOfTrust},
	)
	return attSequence(
		attInteger(200),
		attEnumerated(1),
		attInteger(300),
		attEnumerated(1),
		attOctets(challenge),
		attOctets(nil),
		attAuthorizationList(),
		hardware,
	)
}

// attestationHeader returns the Key-Attestation header for key: the leaf
// first, then the intermediate and the pinned root.
func attestationHeader(t testing.TB, root, inter *ca, key crypto.Signer, challenge []byte) string {
	t.Helper()
	leaf := issue(t, inter, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Android key attestation"},
		ExtraExtensions: []pkix.Extension{{
			Id: testAttestationOID, Value: attKeyDescription(challenge),
		}},
	}, key.Public())
	raw := append(append(append([]byte{}, leaf.Raw...), inter.cert.Raw...), root.cert.Raw...)
	return base64.StdEncoding.EncodeToString(raw)
}

func newAttestationEnv(t *testing.T, change func(map[string]any, string)) (*env, *ca, *ca) {
	t.Helper()
	root := newRoot(t, "Attestation Root")
	inter := root.intermediate(t, "Attestation Intermediate")
	e := newEnvWith(t, func(cfg map[string]any, dir string) {
		cfg["key_attestation"] = map[string]any{
			"roots_file": writeFile(t, dir, "att-roots.pem", pemCert(root.cert)),
		}
		if change != nil {
			change(cfg, dir)
		}
	})
	return e, root, inter
}

// postAttested is post with a Key-Attestation header.
func (e *env) postAttested(client *http.Client, path, bearer string, body []byte, header string) result {
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
	req.Header.Set("Key-Attestation", header)
	return e.do(client, req)
}

func TestAttestationEnroll(t *testing.T) {
	e, root, inter := newAttestationEnv(t, nil)
	code := e.code("alice", "Phone")
	key := newKey(t, elliptic.P256())
	challenge := sha256.Sum256([]byte(code))
	header := attestationHeader(t, root, inter, key, challenge[:])

	r := e.postAttested(e.client(nil), "device/simpleenroll", code, csrBody(t, key, "x"), header)
	if r.status != 200 {
		t.Fatalf("attested enroll: %d %s", r.status, r.body)
	}
	for _, want := range []string{
		`"attestation_security_level":"TrustedEnvironment"`,
		`"attestation_verified_boot_state":"SelfSigned"`,
		`"attestation_device_locked":true`,
		`"attestation_version":200`,
	} {
		if !strings.Contains(e.logs.String(), want) {
			t.Errorf("log lacks %s", want)
		}
	}
}

func TestAttestationDoesNotConsumeCode(t *testing.T) {
	e, root, inter := newAttestationEnv(t, nil)
	c := e.client(nil)

	// Missing header: 400, and the code is still usable.
	code := e.code("alice", "Phone")
	key := newKey(t, elliptic.P256())
	if r := e.post(c, "device/simpleenroll", code, csrBody(t, key, "x")); r.status != 400 ||
		!strings.Contains(r.body, "key attestation") {
		t.Fatalf("missing attestation: %d %s", r.status, r.body)
	}
	challenge := sha256.Sum256([]byte(code))
	if r := e.postAttested(c, "device/simpleenroll", code, csrBody(t, key, "x"),
		attestationHeader(t, root, inter, key, challenge[:])); r.status != 200 {
		t.Errorf("code after missing attestation: %d %s", r.status, r.body)
	}

	// Refused attestation: 403, and the code is still usable.
	code = e.code("alice", "Phone 2")
	key = newKey(t, elliptic.P256())
	wrong := sha256.Sum256([]byte("wrong challenge"))
	if r := e.postAttested(c, "device/simpleenroll", code, csrBody(t, key, "x"),
		attestationHeader(t, root, inter, key, wrong[:])); r.status != 403 ||
		!strings.Contains(r.body, "key attestation refused") {
		t.Fatalf("refused attestation: %d %s", r.status, r.body)
	}
	challenge = sha256.Sum256([]byte(code))
	if r := e.postAttested(c, "device/simpleenroll", code, csrBody(t, key, "x"),
		attestationHeader(t, root, inter, key, challenge[:])); r.status != 200 {
		t.Errorf("code after refused attestation: %d %s", r.status, r.body)
	}
}

func TestAttestationReenroll(t *testing.T) {
	e, root, inter := newAttestationEnv(t, nil)
	code := e.code("alice", "Phone")
	oldKey := newKey(t, elliptic.P256())
	challenge := sha256.Sum256([]byte(code))
	r := e.postAttested(e.client(nil), "device/simpleenroll", code, csrBody(t, oldKey, "x"),
		attestationHeader(t, root, inter, oldKey, challenge[:]))
	if r.status != 200 {
		t.Fatalf("attested enroll: %d %s", r.status, r.body)
	}
	oldDevice := e.client(tlsCert(r.certs, oldKey))

	// Renewal needs a new key whose challenge is the presented
	// credential, not the code.
	renewKey := newKey(t, elliptic.P256())
	newChallenge := sha256.Sum256(r.certs[0].Raw)
	r = e.postAttested(oldDevice, "device/simplereenroll", "", csrBody(t, renewKey, "x"),
		attestationHeader(t, root, inter, renewKey, newChallenge[:]))
	if r.status != 200 {
		t.Fatalf("attested reenroll: %d %s", r.status, r.body)
	}
	if !strings.Contains(e.logs.String(), `"msg":"reenroll_device"`) {
		t.Error("reenroll_device not logged")
	}

	// The old enrollment challenge no longer works.
	anotherKey := newKey(t, elliptic.P256())
	challenge = sha256.Sum256([]byte(code))
	if r := e.postAttested(oldDevice, "device/simplereenroll", "", csrBody(t, anotherKey, "x"),
		attestationHeader(t, root, inter, anotherKey, challenge[:])); r.status != 403 {
		t.Errorf("old challenge on reenroll: %d %s", r.status, r.body)
	}
}

func TestAttestationHeaderIgnoredWhenOff(t *testing.T) {
	e := newEnv(t)
	code := e.code("alice", "Phone")
	key := newKey(t, elliptic.P256())
	header := base64.StdEncoding.EncodeToString([]byte("not a certificate chain"))
	if r := e.postAttested(e.client(nil), "device/simpleenroll", code, csrBody(t, key, "x"), header); r.status != 200 {
		t.Errorf("header with the feature off: %d %s", r.status, r.body)
	}
}

func TestAttestationStatusUnavailable(t *testing.T) {
	e, root, inter := newAttestationEnv(t, func(cfg map[string]any, _ string) {
		cfg["key_attestation"].(map[string]any)["status_url"] =
			"https://status.example.org/attestation/status"
	})
	code := e.code("alice", "Phone")
	key := newKey(t, elliptic.P256())
	challenge := sha256.Sum256([]byte(code))
	r := e.postAttested(e.client(nil), "device/simpleenroll", code, csrBody(t, key, "x"),
		attestationHeader(t, root, inter, key, challenge[:]))
	if r.status != 502 || !strings.Contains(r.body, "status unavailable") {
		t.Errorf("missing status list: %d %s", r.status, r.body)
	}
	if !strings.Contains(e.logs.String(), `"reason":"attestation_status_unavailable"`) {
		t.Error("attestation_status_unavailable not logged")
	}
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package attest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func newTestCA(t *testing.T, parent *testCA, name string, extras []pkix.Extension) *testCA {
	t.Helper()
	key := testKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtraExtensions:       extras,
	}
	signerCert, signerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func newLeaf(t *testing.T, issuer *testCA, pub crypto.PublicKey, kd []byte) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: testSerial(t),
		Subject:      pkix.Name{CommonName: "Android key attestation"},
		// Android's leaf dates are unreliable; Verify must ignore them.
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id: oidKeyDescription, Value: kd,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.cert, pub, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func derLength(n int) []byte {
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

func tlv(first byte, content []byte) []byte {
	return append([]byte{first}, append(derLength(len(content)), content...)...)
}

func sequence(parts ...[]byte) []byte {
	return tlv(0x30, bytes.Join(parts, nil))
}

func setOf(parts ...[]byte) []byte {
	return tlv(0x31, bytes.Join(parts, nil))
}

func octets(b []byte) []byte {
	return tlv(0x04, b)
}

func integer(n int) []byte {
	b, _ := asn1.Marshal(n)
	return b
}

func enumerated(n int) []byte {
	b, _ := asn1.Marshal(asn1.Enumerated(n))
	return b
}

func boolean(v bool) []byte {
	b, _ := asn1.Marshal(v)
	return b
}

// contextField encodes an EXPLICIT context-specific tagged field, using
// the high-tag-number form above 30.
func contextField(tag int, inner []byte) []byte {
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
	return append(header, append(derLength(len(inner)), inner...)...)
}

type field struct {
	tag   int
	value []byte // DER of the field's value, without the explicit tag
}

func authorizationList(fields ...field) []byte {
	var parts [][]byte
	for _, f := range fields {
		parts = append(parts, contextField(f.tag, f.value))
	}
	return sequence(parts...)
}

func rootOfTrustDER(key []byte, locked bool, state int) []byte {
	return sequence(octets(key), boolean(locked), enumerated(state))
}

func applicationIDDER(pkg string, version int, digests ...[]byte) []byte {
	var signatures [][]byte
	for _, d := range digests {
		signatures = append(signatures, octets(d))
	}
	return sequence(
		setOf(sequence(octets([]byte(pkg)), integer(version))),
		setOf(signatures...),
	)
}

type keyDesc struct {
	attestationVersion int
	attestationLevel   int
	keyMintVersion     int
	keyMintLevel       int
	challenge          []byte
	uniqueID           []byte
	software           []field
	hardware           []field
}

func (k keyDesc) encode() []byte {
	return sequence(
		integer(k.attestationVersion),
		enumerated(k.attestationLevel),
		integer(k.keyMintVersion),
		enumerated(k.keyMintLevel),
		octets(k.challenge),
		octets(k.uniqueID),
		authorizationList(k.software...),
		authorizationList(k.hardware...),
	)
}

var testBootKey = bytes.Repeat([]byte{0x42}, 32)

func goodDescription(challenge []byte) keyDesc {
	return keyDesc{
		attestationVersion: 200,
		attestationLevel:   securityTrustedEnvironment,
		keyMintVersion:     300,
		keyMintLevel:       securityTrustedEnvironment,
		challenge:          challenge,
		uniqueID:           []byte{},
		hardware: []field{
			{authPurpose, setOf(integer(purposeSign))},
			{authOrigin, integer(originCreated)},
			{authRootOfTrust, rootOfTrustDER(testBootKey, true, bootSelfSigned)},
		},
	}
}

func setField(fields []field, tag int, value []byte) []field {
	for i := range fields {
		if fields[i].tag == tag {
			fields[i].value = value
			return fields
		}
	}
	return append(fields, field{tag, value})
}

func removeField(fields []field, tag int) []field {
	var out []field
	for _, f := range fields {
		if f.tag != tag {
			out = append(out, f)
		}
	}
	return out
}

type fixture struct {
	root   *testCA
	inter  *testCA
	key    *ecdsa.PrivateKey
	chain  []*x509.Certificate
	policy Policy
}

func newFixture(t *testing.T, kd keyDesc) fixture {
	t.Helper()
	root := newTestCA(t, nil, "Attestation Root", nil)
	inter := newTestCA(t, root, "Attestation Intermediate", nil)
	key := testKey(t)
	leaf := newLeaf(t, inter, key.Public(), kd.encode())
	return fixture{
		root: root, inter: inter, key: key,
		chain:  []*x509.Certificate{leaf, inter.cert, root.cert},
		policy: Policy{Roots: []*x509.Certificate{root.cert}},
	}
}

func TestVerifyValid(t *testing.T) {
	challenge := sha256.Sum256([]byte("one-time code"))
	f := newFixture(t, goodDescription(challenge[:]))
	res, err := Verify(f.chain, f.key.Public(), challenge[:], f.policy, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.SecurityLevel != "TrustedEnvironment" || res.VerifiedBootState != "SelfSigned" ||
		!res.DeviceLocked || res.VerifiedBootKey != hex.EncodeToString(testBootKey) ||
		res.AttestationVersion != 200 {
		t.Errorf("result %+v", res)
	}
}

func TestVerifyPolicy(t *testing.T) {
	challenge := []byte("expected challenge")
	appDigest := sha256.Sum256([]byte("app signing certificate"))
	otherDigest := sha256.Sum256([]byte("another app signing certificate"))
	cases := []struct {
		name   string
		want   string
		change func(*keyDesc, *Policy)
	}{
		{"StrongBox required but TEE", "StrongBox is required", func(_ *keyDesc, p *Policy) { p.RequireStrongBox = true }},
		{"software attestation level", "TEE or StrongBox", func(k *keyDesc, _ *Policy) { k.attestationLevel = securitySoftware }},
		{"software KeyMint level", "TEE or StrongBox", func(k *keyDesc, _ *Policy) { k.keyMintLevel = securitySoftware }},
		{"unknown attestation level", "TEE or StrongBox", func(k *keyDesc, _ *Policy) { k.attestationLevel = 99 }},
		{"unknown KeyMint level", "TEE or StrongBox", func(k *keyDesc, _ *Policy) { k.keyMintLevel = 3 }},
		{"wrong challenge", "challenge", func(k *keyDesc, _ *Policy) { k.challenge = []byte("old challenge") }},
		{"imported origin", "not GENERATED", func(k *keyDesc, _ *Policy) {
			k.hardware = setField(k.hardware, authOrigin, integer(1))
		}},
		{"missing origin", "origin is missing", func(k *keyDesc, _ *Policy) {
			k.hardware = removeField(k.hardware, authOrigin)
		}},
		{"no SIGN purpose", "purpose does not include SIGN", func(k *keyDesc, _ *Policy) {
			k.hardware = setField(k.hardware, authPurpose, setOf(integer(1)))
		}},
		{"missing purpose", "purpose is missing", func(k *keyDesc, _ *Policy) {
			k.hardware = removeField(k.hardware, authPurpose)
		}},
		{"unlocked", "not locked", func(k *keyDesc, _ *Policy) {
			k.hardware = setField(k.hardware, authRootOfTrust, rootOfTrustDER(testBootKey, false, bootSelfSigned))
		}},
		{"unverified boot", "not Verified or SelfSigned", func(k *keyDesc, _ *Policy) {
			k.hardware = setField(k.hardware, authRootOfTrust, rootOfTrustDER(testBootKey, true, bootUnverified))
		}},
		{"boot key not pinned", "is not pinned", func(_ *keyDesc, p *Policy) {
			p.VerifiedBootKeys = []string{hex.EncodeToString(bytes.Repeat([]byte{0x24}, 32))}
		}},
		{"app package match but digest mismatch", "no pinned signing certificate", func(k *keyDesc, p *Policy) {
			k.software = setField(k.software, authAttestationApplication,
				octets(applicationIDDER("org.example.eapenroll", 1, appDigest[:])))
			p.AppPackage = "org.example.eapenroll"
			p.AppSigningCerts = []string{hex.EncodeToString(otherDigest[:])}
		}},
		{"app package mismatch", "does not contain package", func(k *keyDesc, p *Policy) {
			k.software = setField(k.software, authAttestationApplication,
				octets(applicationIDDER("org.example.eapenroll", 1, appDigest[:])))
			p.AppPackage = "org.example.other"
			p.AppSigningCerts = []string{hex.EncodeToString(appDigest[:])}
		}},
		{"app ID missing", "application ID is missing", func(_ *keyDesc, p *Policy) {
			p.AppPackage = "org.example.eapenroll"
			p.AppSigningCerts = []string{hex.EncodeToString(appDigest[:])}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kd := goodDescription(challenge)
			policy := Policy{}
			tc.change(&kd, &policy)
			f := newFixture(t, kd)
			policy.Roots = f.policy.Roots
			_, err := Verify(f.chain, f.key.Public(), challenge, policy, nil, time.Now())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}

	// StrongBox end to end, and an application ID in hardwareEnforced.
	t.Run("StrongBox and app match", func(t *testing.T) {
		kd := goodDescription(challenge)
		kd.attestationLevel = securityStrongBox
		kd.keyMintLevel = securityStrongBox
		kd.hardware = setField(kd.hardware, authAttestationApplication,
			octets(applicationIDDER("org.example.eapenroll", 1, appDigest[:])))
		f := newFixture(t, kd)
		f.policy.RequireStrongBox = true
		f.policy.AppPackage = "org.example.eapenroll"
		f.policy.AppSigningCerts = []string{strings.ToUpper(hex.EncodeToString(appDigest[:]))}
		res, err := Verify(f.chain, f.key.Public(), challenge, f.policy, nil, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if res.SecurityLevel != "StrongBox" {
			t.Errorf("security level %q", res.SecurityLevel)
		}
	})

	// Pinned boot key, case-insensitive.
	t.Run("pinned boot key", func(t *testing.T) {
		f := newFixture(t, goodDescription(challenge))
		f.policy.VerifiedBootKeys = []string{strings.ToUpper(hex.EncodeToString(testBootKey))}
		if _, err := Verify(f.chain, f.key.Public(), challenge, f.policy, nil, time.Now()); err != nil {
			t.Error(err)
		}
	})
}

func TestVerifyChain(t *testing.T) {
	challenge := []byte("challenge")

	t.Run("unpinned root", func(t *testing.T) {
		f := newFixture(t, goodDescription(challenge))
		other := newTestCA(t, nil, "Other Root", nil)
		f.policy.Roots = []*x509.Certificate{other.cert}
		if _, err := Verify(f.chain, f.key.Public(), challenge, f.policy, nil, time.Now()); err == nil ||
			!strings.Contains(err.Error(), "pinned root") {
			t.Errorf("error %v", err)
		}
	})

	t.Run("chain ends at a pinned root signed by it", func(t *testing.T) {
		f := newFixture(t, goodDescription(challenge))
		// Drop the root from the chain: the intermediate is signed by the
		// pinned root.
		chain := f.chain[:2]
		if _, err := Verify(chain, f.key.Public(), challenge, f.policy, nil, time.Now()); err != nil {
			t.Error(err)
		}
	})

	t.Run("extension on intermediate", func(t *testing.T) {
		root := newTestCA(t, nil, "Attestation Root", nil)
		inter := newTestCA(t, root, "Attestation Intermediate", []pkix.Extension{{
			Id: oidKeyDescription, Value: goodDescription(challenge).encode(),
		}})
		key := testKey(t)
		leaf := newLeaf(t, inter, key.Public(), goodDescription(challenge).encode())
		chain := []*x509.Certificate{leaf, inter.cert, root.cert}
		_, err := Verify(chain, key.Public(), challenge, Policy{Roots: []*x509.Certificate{root.cert}}, nil, time.Now())
		if err == nil || !strings.Contains(err.Error(), "only the leaf") {
			t.Errorf("error %v", err)
		}
	})

	t.Run("leaf key is not the CSR key", func(t *testing.T) {
		f := newFixture(t, goodDescription(challenge))
		other := testKey(t)
		if _, err := Verify(f.chain, other.Public(), challenge, f.policy, nil, time.Now()); err == nil ||
			!strings.Contains(err.Error(), "does not match the CSR key") {
			t.Errorf("error %v", err)
		}
	})

	t.Run("too many certificates", func(t *testing.T) {
		f := newFixture(t, goodDescription(challenge))
		for len(f.chain) <= maxChainLength {
			f.chain = append(f.chain, f.root.cert)
		}
		if _, err := Verify(f.chain, f.key.Public(), challenge, f.policy, nil, time.Now()); err == nil ||
			!strings.Contains(err.Error(), "expected 1..") {
			t.Errorf("error %v", err)
		}
	})
}

func TestVerifyRevocation(t *testing.T) {
	challenge := []byte("challenge")
	now := time.Now()
	status := func(entries map[string]string, loaded bool, fetched time.Time) *StatusList {
		return &StatusList{
			url:     "https://android.googleapis.com/attestation/status",
			entries: entries, loaded: loaded, fetched: fetched,
		}
	}

	for _, tc := range []struct {
		name   string
		serial func(fixture) string
	}{
		{"leaf", func(f fixture) string { return f.chain[0].SerialNumber.Text(16) }},
		{"intermediate", func(f fixture) string { return f.chain[1].SerialNumber.Text(16) }},
	} {
		t.Run("revoked "+tc.name, func(t *testing.T) {
			f := newFixture(t, goodDescription(challenge))
			entries := map[string]string{tc.serial(f): "REVOKED"}
			_, err := Verify(f.chain, f.key.Public(), challenge, f.policy, status(entries, true, now), now)
			if err == nil || !strings.Contains(err.Error(), "is revoked") {
				t.Errorf("error %v", err)
			}
		})
	}

	t.Run("suspended leaf", func(t *testing.T) {
		f := newFixture(t, goodDescription(challenge))
		entries := map[string]string{f.chain[0].SerialNumber.Text(16): "SUSPENDED"}
		_, err := Verify(f.chain, f.key.Public(), challenge, f.policy, status(entries, true, now), now)
		if err == nil || !strings.Contains(err.Error(), "is suspended") {
			t.Errorf("error %v", err)
		}
	})

	t.Run("missing list", func(t *testing.T) {
		f := newFixture(t, goodDescription(challenge))
		_, err := Verify(f.chain, f.key.Public(), challenge, f.policy, status(nil, false, time.Time{}), now)
		if !errors.Is(err, ErrStatusUnavailable) {
			t.Errorf("error %v", err)
		}
	})

	t.Run("stale list", func(t *testing.T) {
		f := newFixture(t, goodDescription(challenge))
		_, err := Verify(f.chain, f.key.Public(), challenge, f.policy, status(nil, true, now.Add(-8*24*time.Hour)), now)
		if !errors.Is(err, ErrStatusUnavailable) {
			t.Errorf("error %v", err)
		}
	})
}

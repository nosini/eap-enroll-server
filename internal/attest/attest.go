// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package attest verifies Android Keystore key attestation certificate
// chains offline. It doesn't call Google (except for the optional public
// revocation list) and it is not Play Integrity.
package attest

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
)

// oidKeyDescription is the Android key description extension.
var oidKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

const maxChainLength = 10

// AuthorizationList tags used by the policy.
const (
	authPurpose                = 1
	authOrigin                 = 702
	authRootOfTrust            = 704
	authAttestationApplication = 709
)

const (
	securitySoftware           = 0
	securityTrustedEnvironment = 1
	securityStrongBox          = 2
)

const (
	purposeSign   = 2
	originCreated = 0
)

const (
	bootVerified   = 0
	bootSelfSigned = 1
	bootUnverified = 2
	bootFailed     = 3
)

// Policy is what a verified chain has to satisfy.
type Policy struct {
	// Roots are the pinned attestation roots. The last certificate of a
	// chain must be one of them or be signed by one of them.
	Roots []*x509.Certificate
	// RequireStrongBox also requires both security levels to be StrongBox.
	RequireStrongBox bool
	// VerifiedBootKeys, if non-empty, are the allowed verifiedBootKey
	// values as hex, compared case-insensitively.
	VerifiedBootKeys []string
	// AppPackage and AppSigningCerts, if set, require the attestation to
	// name the app and one of its signing certificate digests (hex
	// SHA-256).
	AppPackage      string
	AppSigningCerts []string
}

// Result is what the audit log records about a successful verification.
type Result struct {
	SecurityLevel      string
	VerifiedBootState  string
	DeviceLocked       bool
	VerifiedBootKey    string
	AttestationVersion int
}

// keyDescription is the DER structure in the leaf's key description
// extension.
type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeyMintVersion           int
	KeyMintSecurityLevel     asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	HardwareEnforced         asn1.RawValue
}

type rootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

type applicationID struct {
	Packages []string
	Digests  [][]byte
}

// Verify checks a chain (leaf first), the CSR key and the attestation
// policy. status may be nil when the revocation list is not configured.
func Verify(chain []*x509.Certificate, pub crypto.PublicKey, challenge []byte, p Policy, status *StatusList, now time.Time) (Result, error) {
	var res Result
	if len(chain) == 0 || len(chain) > maxChainLength {
		return res, fmt.Errorf("attestation chain has %d certificates, expected 1..%d", len(chain), maxChainLength)
	}
	if len(p.Roots) == 0 {
		return res, errors.New("no attestation roots are configured")
	}

	// The chain ends at its first certificate that is a pinned root or
	// has a pinned root's subject and key: devices may carry an older,
	// even expired, certificate for the same root key. Certificates after
	// it are ignored, and only the pinned root's validity counts.
	// Otherwise the last certificate must be signed by a pinned root.
	var anchor *x509.Certificate
	for i, c := range chain {
		root, err := pinnedRoot(p.Roots, now, func(root *x509.Certificate) bool {
			return bytes.Equal(c.Raw, root.Raw) ||
				(bytes.Equal(c.RawSubject, root.RawSubject) && publicKeyEqual(c.PublicKey, root.PublicKey))
		})
		if err != nil {
			return res, err
		}
		if root != nil {
			if i == 0 {
				return res, errors.New("attestation leaf is a pinned root")
			}
			anchor, chain = root, chain[:i]
			break
		}
	}

	// Attestation chains often lack CA flags, so only signatures are
	// checked, not basic constraints. CheckSignature still accepts SHA-1,
	// so weak algorithms are refused here.
	for i, c := range chain {
		if !strongSignature[c.SignatureAlgorithm] {
			return res, fmt.Errorf("attestation certificate %d is signed with %v", i, c.SignatureAlgorithm)
		}
	}
	for i := 0; i+1 < len(chain); i++ {
		child, parent := chain[i], chain[i+1]
		if err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature); err != nil {
			return res, fmt.Errorf("attestation certificate %d is not signed by certificate %d: %w", i, i+1, err)
		}
	}
	// The leaf's dates are unreliable; intermediates must be valid now.
	for i := 1; i < len(chain); i++ {
		if err := checkValidity(chain[i], now); err != nil {
			return res, fmt.Errorf("attestation certificate %d: %w", i, err)
		}
	}
	last := chain[len(chain)-1]
	signedBy := func(root *x509.Certificate) bool {
		return root.CheckSignature(last.SignatureAlgorithm, last.RawTBSCertificate, last.Signature) == nil
	}
	if anchor != nil {
		if !signedBy(anchor) {
			return res, fmt.Errorf("attestation certificate %d is not signed by the pinned root %q", len(chain)-1, anchor.Subject)
		}
	} else {
		root, err := pinnedRoot(p.Roots, now, signedBy)
		if err != nil {
			return res, err
		}
		if root == nil {
			return res, errors.New("attestation chain is not signed by a pinned root")
		}
	}

	if err := status.Check(chain, now); err != nil {
		return res, err
	}

	leaf := chain[0]
	ext := -1
	for i := range leaf.Extensions {
		if leaf.Extensions[i].Id.Equal(oidKeyDescription) {
			ext = i
			break
		}
	}
	if ext < 0 {
		return res, errors.New("leaf certificate has no Android key description extension")
	}
	for i := 1; i < len(chain); i++ {
		for _, e := range chain[i].Extensions {
			if e.Id.Equal(oidKeyDescription) {
				return res, fmt.Errorf("attestation certificate %d has a key description extension; only the leaf may", i)
			}
		}
	}
	if !publicKeyEqual(leaf.PublicKey, pub) {
		return res, errors.New("leaf certificate public key does not match the CSR key")
	}

	var kd keyDescription
	rest, err := asn1.Unmarshal(leaf.Extensions[ext].Value, &kd)
	if err != nil {
		return res, fmt.Errorf("malformed Android key description: %w", err)
	}
	if len(rest) != 0 {
		return res, errors.New("malformed Android key description: trailing data")
	}
	software, err := parseAuthorizationList(kd.SoftwareEnforced)
	if err != nil {
		return res, fmt.Errorf("malformed software-enforced authorization list: %w", err)
	}
	hardware, err := parseAuthorizationList(kd.HardwareEnforced)
	if err != nil {
		return res, fmt.Errorf("malformed hardware-enforced authorization list: %w", err)
	}

	res.AttestationVersion = kd.AttestationVersion
	res.SecurityLevel = securityLevelName(int(kd.AttestationSecurityLevel))
	keyMintLevel := securityLevelName(int(kd.KeyMintSecurityLevel))
	// Only the two known hardware levels count; an unknown value is no
	// proof of anything.
	hardwareLevel := func(l asn1.Enumerated) bool {
		return l == securityTrustedEnvironment || l == securityStrongBox
	}
	if !hardwareLevel(kd.AttestationSecurityLevel) || !hardwareLevel(kd.KeyMintSecurityLevel) {
		return res, fmt.Errorf("attestation security levels are %s and %s; a TEE or StrongBox is required",
			res.SecurityLevel, keyMintLevel)
	}
	if p.RequireStrongBox &&
		(int(kd.AttestationSecurityLevel) != securityStrongBox || int(kd.KeyMintSecurityLevel) != securityStrongBox) {
		return res, fmt.Errorf("StrongBox is required but security levels are %s and %s",
			res.SecurityLevel, keyMintLevel)
	}
	if subtle.ConstantTimeCompare(kd.AttestationChallenge, challenge) != 1 {
		return res, errors.New("attestation challenge does not match")
	}

	field, ok := hardware[authOrigin]
	if !ok {
		return res, errors.New("hardware-enforced origin is missing")
	}
	origin, err := decodeInteger(field)
	if err != nil {
		return res, fmt.Errorf("hardware-enforced origin: %w", err)
	}
	if origin != originCreated {
		return res, fmt.Errorf("key origin is %d, not GENERATED", origin)
	}

	field, ok = hardware[authPurpose]
	if !ok {
		return res, errors.New("hardware-enforced purpose is missing")
	}
	purposes, err := decodeIntegerSet(field)
	if err != nil {
		return res, fmt.Errorf("hardware-enforced purpose: %w", err)
	}
	if !slices.Contains(purposes, purposeSign) {
		return res, errors.New("key purpose does not include SIGN")
	}

	field, ok = hardware[authRootOfTrust]
	if !ok {
		return res, errors.New("hardware-enforced root of trust is missing")
	}
	rt, err := decodeRootOfTrust(field)
	if err != nil {
		return res, fmt.Errorf("hardware-enforced root of trust: %w", err)
	}
	res.DeviceLocked = rt.DeviceLocked
	res.VerifiedBootState = bootStateName(int(rt.VerifiedBootState))
	res.VerifiedBootKey = hex.EncodeToString(rt.VerifiedBootKey)
	if !rt.DeviceLocked {
		return res, errors.New("device is not locked")
	}
	if rt.VerifiedBootState != bootVerified && rt.VerifiedBootState != bootSelfSigned {
		return res, fmt.Errorf("verified boot state is %s, not Verified or SelfSigned", res.VerifiedBootState)
	}
	if len(p.VerifiedBootKeys) != 0 &&
		!slices.ContainsFunc(p.VerifiedBootKeys, func(k string) bool { return strings.EqualFold(k, res.VerifiedBootKey) }) {
		return res, fmt.Errorf("verified boot key %s is not pinned", res.VerifiedBootKey)
	}

	if p.AppPackage != "" {
		app, err := attestationApplicationID(software, hardware)
		if err != nil {
			return res, fmt.Errorf("attestation application ID: %w", err)
		}
		if !slices.Contains(app.Packages, p.AppPackage) {
			return res, fmt.Errorf("attestation application ID does not contain package %q", p.AppPackage)
		}
		matched := slices.ContainsFunc(app.Digests, func(digest []byte) bool {
			got := hex.EncodeToString(digest)
			return slices.ContainsFunc(p.AppSigningCerts, func(want string) bool { return strings.EqualFold(want, got) })
		})
		if !matched {
			return res, errors.New("attestation application ID has no pinned signing certificate digest")
		}
	}
	return res, nil
}

// strongSignature lists the signature algorithms accepted in attestation
// chains (the leaf and the certificates up to the pinned root).
var strongSignature = map[x509.SignatureAlgorithm]bool{
	x509.SHA256WithRSA:    true,
	x509.SHA384WithRSA:    true,
	x509.SHA512WithRSA:    true,
	x509.SHA256WithRSAPSS: true,
	x509.SHA384WithRSAPSS: true,
	x509.SHA512WithRSAPSS: true,
	x509.ECDSAWithSHA256:  true,
	x509.ECDSAWithSHA384:  true,
	x509.ECDSAWithSHA512:  true,
	x509.PureEd25519:      true,
}

// pinnedRoot returns the first pinned root that matches and is valid at
// now. If roots match but none is valid, it returns the error; if none
// matches, nil and no error.
func pinnedRoot(roots []*x509.Certificate, now time.Time, match func(*x509.Certificate) bool) (*x509.Certificate, error) {
	var invalid error
	for _, root := range roots {
		if !match(root) {
			continue
		}
		if err := checkValidity(root, now); err != nil {
			if invalid == nil {
				invalid = fmt.Errorf("attestation root %q: %w", root.Subject, err)
			}
			continue
		}
		return root, nil
	}
	return nil, invalid
}

func checkValidity(c *x509.Certificate, now time.Time) error {
	if now.Before(c.NotBefore) {
		return fmt.Errorf("not valid before %s", c.NotBefore.UTC())
	}
	if !now.Before(c.NotAfter) {
		return fmt.Errorf("expired at %s", c.NotAfter.UTC())
	}
	return nil
}

func publicKeyEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return reflect.DeepEqual(a, b)
}

func parseAuthorizationList(raw asn1.RawValue) (map[int]asn1.RawValue, error) {
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
		return nil, errors.New("not a SEQUENCE")
	}
	fields := make(map[int]asn1.RawValue)
	rest := raw.Bytes
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			return nil, err
		}
		if field.Class == asn1.ClassContextSpecific {
			fields[field.Tag] = field
		}
	}
	return fields, nil
}

func decodeInteger(field asn1.RawValue) (int, error) {
	var v int
	rest, err := asn1.Unmarshal(field.Bytes, &v)
	if err != nil {
		return 0, fmt.Errorf("not an INTEGER: %w", err)
	}
	if len(rest) != 0 {
		return 0, errors.New("not an INTEGER: trailing data")
	}
	return v, nil
}

func decodeIntegerSet(field asn1.RawValue) ([]int, error) {
	var set asn1.RawValue
	rest, err := asn1.Unmarshal(field.Bytes, &set)
	if err != nil {
		return nil, fmt.Errorf("not a SET OF INTEGER: %w", err)
	}
	if len(rest) != 0 || set.Class != asn1.ClassUniversal || set.Tag != asn1.TagSet {
		return nil, errors.New("not a SET OF INTEGER")
	}
	var values []int
	b := set.Bytes
	for len(b) > 0 {
		var v int
		if b, err = asn1.Unmarshal(b, &v); err != nil {
			return nil, fmt.Errorf("not a SET OF INTEGER: %w", err)
		}
		values = append(values, v)
	}
	return values, nil
}

func decodeRootOfTrust(field asn1.RawValue) (rootOfTrust, error) {
	var rt rootOfTrust
	rest, err := asn1.Unmarshal(field.Bytes, &rt)
	if err != nil {
		return rt, err
	}
	if len(rest) != 0 {
		return rt, errors.New("trailing data after root of trust")
	}
	return rt, nil
}

func attestationApplicationID(software, hardware map[int]asn1.RawValue) (applicationID, error) {
	field, ok := software[authAttestationApplication]
	if !ok {
		field, ok = hardware[authAttestationApplication]
	}
	if !ok {
		return applicationID{}, errors.New("attestation application ID is missing")
	}
	var der []byte
	rest, err := asn1.Unmarshal(field.Bytes, &der)
	if err != nil {
		return applicationID{}, fmt.Errorf("not an OCTET STRING: %w", err)
	}
	if len(rest) != 0 {
		return applicationID{}, errors.New("not an OCTET STRING: trailing data")
	}
	var raw struct {
		PackageInfos     asn1.RawValue
		SignatureDigests asn1.RawValue
	}
	rest, err = asn1.Unmarshal(der, &raw)
	if err != nil {
		return applicationID{}, fmt.Errorf("not a SEQUENCE: %w", err)
	}
	if len(rest) != 0 {
		return applicationID{}, errors.New("not a SEQUENCE: trailing data")
	}
	if raw.PackageInfos.Class != asn1.ClassUniversal || raw.PackageInfos.Tag != asn1.TagSet ||
		raw.SignatureDigests.Class != asn1.ClassUniversal || raw.SignatureDigests.Tag != asn1.TagSet {
		return applicationID{}, errors.New("package information or signature digests are not SETs")
	}
	var app applicationID
	b := raw.PackageInfos.Bytes
	for len(b) > 0 {
		var info struct {
			PackageName []byte
			Version     int
		}
		if b, err = asn1.Unmarshal(b, &info); err != nil {
			return applicationID{}, fmt.Errorf("package information: %w", err)
		}
		app.Packages = append(app.Packages, string(info.PackageName))
	}
	b = raw.SignatureDigests.Bytes
	for len(b) > 0 {
		var digest []byte
		if b, err = asn1.Unmarshal(b, &digest); err != nil {
			return applicationID{}, fmt.Errorf("signature digest: %w", err)
		}
		app.Digests = append(app.Digests, digest)
	}
	return app, nil
}

func securityLevelName(level int) string {
	switch level {
	case securitySoftware:
		return "Software"
	case securityTrustedEnvironment:
		return "TrustedEnvironment"
	case securityStrongBox:
		return "StrongBox"
	default:
		return fmt.Sprintf("Unknown(%d)", level)
	}
}

func bootStateName(state int) string {
	switch state {
	case bootVerified:
		return "Verified"
	case bootSelfSigned:
		return "SelfSigned"
	case bootUnverified:
		return "Unverified"
	case bootFailed:
		return "Failed"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

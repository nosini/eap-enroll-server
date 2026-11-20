// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package enroll

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      struct{ ContentType asn1.ObjectIdentifier }
	Certificates     asn1.RawValue
	SignerInfos      asn1.RawValue
}

func emptySet() asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: []byte{}}
}

// certsOnly encodes certificates as a degenerate PKCS#7 SignedData
// (RFC 2315/5652: no content, no signers, no CRLs), the "certs-only"
// format EST returns. The order of certs is kept.
func certsOnly(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("no certificates")
	}
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: emptySet(),
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: raw},
		SignerInfos:      emptySet(),
	}
	sd.ContentInfo.ContentType = oidData
	inner, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner},
	})
}

// parseCertsOnly is the inverse of certsOnly; used by tests and kept
// strict.
func parseCertsOnly(der []byte) ([]*x509.Certificate, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil || len(rest) != 0 || !ci.ContentType.Equal(oidSignedData) ||
		ci.Content.Class != asn1.ClassContextSpecific || ci.Content.Tag != 0 {
		return nil, errors.New("not a PKCS#7 SignedData")
	}
	var sd signedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("bad SignedData: %v", err)
	}
	if sd.Certificates.Class != asn1.ClassContextSpecific || sd.Certificates.Tag != 0 {
		return nil, errors.New("SignedData has no certificates")
	}
	return x509.ParseCertificates(sd.Certificates.Bytes)
}

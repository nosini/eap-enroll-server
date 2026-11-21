// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package openbao

import (
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
)

func TestEnabledUser(t *testing.T) {
	groups := map[string]any{"Alice": "staff", "bob": "disabled", "carol": 3}
	if name, err := enabledUser(groups, "alice"); err != nil || name != "Alice" {
		t.Errorf("alice: %q %v", name, err)
	}
	for _, user := range []string{"bob", "BOB", "carol", "dave", ""} {
		if _, err := enabledUser(groups, user); !errors.Is(err, ErrUserNotEnabled) {
			t.Errorf("%q: %v", user, err)
		}
	}
	for name, bad := range map[string]map[string]any{
		"empty":     {},
		"case dup":  {"alice": "a", "ALICE": "b"},
		"bad chars": {"a b": "staff"},
	} {
		if _, err := enabledUser(bad, "alice"); err == nil || errors.Is(err, ErrUserNotEnabled) {
			t.Errorf("%s map: %v", name, err)
		}
	}
}

func TestSerials(t *testing.T) {
	n, _ := new(big.Int).SetString("00ab0c", 16)
	if s := SerialText(n); s != "ab0c" {
		t.Errorf("SerialText %q", s)
	}
	if c, err := colonSerial("ab0c"); err != nil || c != "ab:0c" {
		t.Errorf("colonSerial %q %v", c, err)
	}
	for _, bad := range []string{"", "abc", "zz"} {
		if _, err := colonSerial(bad); err == nil {
			t.Errorf("colonSerial(%q) accepted", bad)
		}
	}
}

func TestSerialFromAnswer(t *testing.T) {
	parsed := []*x509.Certificate{{SerialNumber: big.NewInt(0x1234)}}
	for _, tc := range []struct {
		serial string
		parsed []*x509.Certificate
		want   string
	}{
		{"00:ab:0c", nil, "ab0c"},
		{"ab:0c", parsed, "ab0c"},
		{"", parsed, "1234"},
		{"zz", parsed, "1234"},
		{"00:00", parsed, "1234"},
		{"", append(parsed, parsed[0]), ""},
		{"", nil, ""},
	} {
		if got := serialFromAnswer(tc.serial, tc.parsed); got != tc.want {
			t.Errorf("serialFromAnswer(%q, %d certificates) = %q, want %q", tc.serial, len(tc.parsed), got, tc.want)
		}
	}
}

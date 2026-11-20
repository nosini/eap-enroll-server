// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package openbao

import (
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

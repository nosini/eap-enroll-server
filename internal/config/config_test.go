// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir string, v map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(v)
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func valid(t *testing.T) (string, map[string]any) {
	dir := t.TempDir()
	f := func(name string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("x"), 0o600)
		return p
	}
	return dir, map[string]any{
		"listen": ":8443", "public_url": "https://enroll.example.org:8443",
		"tls_cert_file": f("c"), "tls_key_file": f("k"), "setup_ca_file": f("s"),
		"device_ca_file": f("d"), "wifi_cacerts_file": f("w"), "device_cacerts_file": f("dc"),
		"database": filepath.Join(dir, "db"), "wifi_ttl": "2160h", "device_ttl": "8760h",
		"openbao": map[string]any{
			"address": "https://openbao.example.org:8200", "ca_file": f("ca"),
			"role_id_file": f("r"), "secret_id_file": f("sec"),
		},
	}
}

func TestLoad(t *testing.T) {
	dir, v := valid(t)
	c, err := Load(write(t, dir, v))
	if err != nil {
		t.Fatal(err)
	}
	if c.WifiTTL.Text != "2160h" || c.CodeTTL.Text != "15m" || c.OpenBao.WifiMount != "pki-radius" ||
		c.OpenBao.DeviceRole != "device" || c.OpenBao.UserGroupsPath != "apps/freeradius/user-groups" {
		t.Errorf("defaults: %+v", c)
	}
}

func TestKeyAttestation(t *testing.T) {
	dir, v := valid(t)
	roots := filepath.Join(dir, "att-roots.pem")
	if err := os.WriteFile(roots, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("ab", 32)
	v["key_attestation"] = map[string]any{
		"roots_file":         roots,
		"status_url":         "https://android.googleapis.com/attestation/status",
		"require_strongbox":  true,
		"verified_boot_keys": []string{"AABB", "ccdd"},
		"app_package":        "org.example.eapenroll",
		"app_signing_certs":  []string{digest},
	}
	c, err := Load(write(t, dir, v))
	if err != nil {
		t.Fatal(err)
	}
	a := c.KeyAttestation
	if a == nil || a.RootsFile != roots || !a.RequireStrongBox || a.AppPackage != "org.example.eapenroll" ||
		len(a.VerifiedBootKeys) != 2 || len(a.AppSigningCerts) != 1 {
		t.Fatalf("key_attestation: %+v", a)
	}

	for name, change := range map[string]func(a map[string]any){
		"missing roots":         func(a map[string]any) { delete(a, "roots_file") },
		"http status url":       func(a map[string]any) { a["status_url"] = "http://enroll.example.org/status" },
		"invalid boot key":      func(a map[string]any) { a["verified_boot_keys"] = []string{"not-hex"} },
		"empty boot key":        func(a map[string]any) { a["verified_boot_keys"] = []string{""} },
		"package without certs": func(a map[string]any) { a["app_package"] = "org.example.eapenroll" },
		"certs without package": func(a map[string]any) { a["app_signing_certs"] = []string{digest} },
		"short app digest": func(a map[string]any) {
			a["app_package"] = "org.example.eapenroll"
			a["app_signing_certs"] = []string{"ab"}
		},
	} {
		dir, v := valid(t)
		roots := filepath.Join(dir, "att-roots.pem")
		if err := os.WriteFile(roots, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		a := map[string]any{"roots_file": roots}
		change(a)
		v["key_attestation"] = a
		if _, err := Load(write(t, dir, v)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"unknown field":   func(v map[string]any) { v["extra"] = 1 },
		"http public url": func(v map[string]any) { v["public_url"] = "http://enroll.example.org" },
		"url with path":   func(v map[string]any) { v["public_url"] = "https://enroll.example.org/x" },
		"trailing slash":  func(v map[string]any) { v["public_url"] = "https://enroll.example.org:8443/" },
		"empty query":     func(v map[string]any) { v["public_url"] = "https://enroll.example.org?" },
		"fragment":        func(v map[string]any) { v["public_url"] = "https://enroll.example.org#x" },
		"missing file":    func(v map[string]any) { v["device_ca_file"] = "/nonexistent" },
		"no wifi ttl":     func(v map[string]any) { delete(v, "wifi_ttl") },
		"bad duration":    func(v map[string]any) { v["device_ttl"] = "1 year" },
		"long code ttl":   func(v map[string]any) { v["code_ttl"] = "48h" },
		"path traversal":  func(v map[string]any) { v["openbao"].(map[string]any)["wifi_mount"] = "../sys" },
		"same mounts":     func(v map[string]any) { v["openbao"].(map[string]any)["device_mount"] = "pki-radius" },
		"http openbao":    func(v map[string]any) { v["openbao"].(map[string]any)["address"] = "http://openbao:8200" },
		"no openbao ca":   func(v map[string]any) { delete(v["openbao"].(map[string]any), "ca_file") },
	} {
		dir, v := valid(t)
		change(v)
		if _, err := Load(write(t, dir, v)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

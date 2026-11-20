// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
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
			"address": "https://openbao.example.org:8200", "role_id_file": f("r"), "secret_id_file": f("sec"),
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

func TestLoadErrors(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"unknown field":   func(v map[string]any) { v["extra"] = 1 },
		"http public url": func(v map[string]any) { v["public_url"] = "http://enroll.example.org" },
		"url with path":   func(v map[string]any) { v["public_url"] = "https://enroll.example.org/x" },
		"missing file":    func(v map[string]any) { v["device_ca_file"] = "/nonexistent" },
		"no wifi ttl":     func(v map[string]any) { delete(v, "wifi_ttl") },
		"bad duration":    func(v map[string]any) { v["device_ttl"] = "1 year" },
		"long code ttl":   func(v map[string]any) { v["code_ttl"] = "48h" },
		"path traversal":  func(v map[string]any) { v["openbao"].(map[string]any)["wifi_mount"] = "../sys" },
		"same mounts":     func(v map[string]any) { v["openbao"].(map[string]any)["device_mount"] = "pki-radius" },
		"http openbao":    func(v map[string]any) { v["openbao"].(map[string]any)["address"] = "http://openbao:8200" },
	} {
		dir, v := valid(t)
		change(v)
		if _, err := Load(write(t, dir, v)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

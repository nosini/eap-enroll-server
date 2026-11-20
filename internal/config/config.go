// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package config loads and validates the service's JSON configuration.
package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"time"
	"unicode/utf8"
)

// Duration is a Go duration string ("2160h"). Text keeps the spelling
// from the file, because it is sent to OpenBao as is and an AppRole
// policy can pin that exact value.
type Duration struct {
	D    time.Duration
	Text string
}

// UnmarshalJSON accepts a Go duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"720h\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration{D: v, Text: s}
	return nil
}

// OpenBao holds the connection to OpenBao and the paths the service uses.
type OpenBao struct {
	Address        string `json:"address"`
	CAFile         string `json:"ca_file"`
	TLSServerName  string `json:"tls_server_name"`
	RoleIDFile     string `json:"role_id_file"`
	SecretIDFile   string `json:"secret_id_file"`
	AppRoleMount   string `json:"approle_mount"`
	WifiMount      string `json:"wifi_mount"`
	WifiRole       string `json:"wifi_role"`
	DeviceMount    string `json:"device_mount"`
	DeviceRole     string `json:"device_role"`
	KVMount        string `json:"kv_mount"`
	UserGroupsPath string `json:"user_groups_path"`
}

// WifiProfile is the network the phones configure: SSID (kept exactly,
// spaces included), the RADIUS server's name and the CA that issued the
// RADIUS server certificate.
type WifiProfile struct {
	SSID         string `json:"ssid"`
	ServerDomain string `json:"server_domain"`
	ServerCAFile string `json:"server_ca_file"`
}

// Config is the whole configuration file.
type Config struct {
	Listen            string   `json:"listen"`
	PublicURL         string   `json:"public_url"`
	TLSCertFile       string   `json:"tls_cert_file"`
	TLSKeyFile        string   `json:"tls_key_file"`
	SetupCAFile       string   `json:"setup_ca_file"`
	DeviceCAFile      string   `json:"device_ca_file"`
	WifiCACertsFile   string   `json:"wifi_cacerts_file"`
	DeviceCACertsFile string   `json:"device_cacerts_file"`
	Database          string   `json:"database"`
	CodeTTL           Duration `json:"code_ttl"`
	WifiTTL           Duration `json:"wifi_ttl"`
	DeviceTTL         Duration `json:"device_ttl"`
	OpenBao           OpenBao  `json:"openbao"`
	// WifiProfile is optional; without it wifi/profile answers 404.
	WifiProfile *WifiProfile `json:"wifi_profile"`
}

// hostname matches a DNS name (letters, digits, hyphens, dots).
var hostname = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// pathSegment matches a mount, role or KV path: no empty segments, no "..".
var pathSegment = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)

// Load reads, defaults and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: trailing data after the JSON object", path)
	}
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) defaults() {
	if c.CodeTTL.Text == "" {
		c.CodeTTL = Duration{D: 15 * time.Minute, Text: "15m"}
	}
	o := &c.OpenBao
	set := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	set(&o.AppRoleMount, "approle")
	set(&o.WifiMount, "pki-radius")
	set(&o.WifiRole, "eap-client")
	set(&o.DeviceMount, "pki-enroll")
	set(&o.DeviceRole, "device")
	set(&o.KVMount, "kv")
	set(&o.UserGroupsPath, "apps/freeradius/user-groups")
}

func (c *Config) validate() error {
	var errs []error
	need := func(name, v string) {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	file := func(name, v string, optional bool) {
		if v == "" {
			if !optional {
				errs = append(errs, fmt.Errorf("%s is required", name))
			}
			return
		}
		if st, err := os.Stat(v); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		} else if !st.Mode().IsRegular() {
			errs = append(errs, fmt.Errorf("%s: %s is not a regular file", name, v))
		}
	}
	need("listen", c.Listen)
	need("database", c.Database)
	if u, err := url.Parse(c.PublicURL); err != nil || u.Scheme != "https" || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		errs = append(errs, errors.New("public_url must be https://host[:port] without path or query"))
	}
	file("tls_cert_file", c.TLSCertFile, false)
	file("tls_key_file", c.TLSKeyFile, false)
	file("setup_ca_file", c.SetupCAFile, false)
	file("device_ca_file", c.DeviceCAFile, false)
	file("wifi_cacerts_file", c.WifiCACertsFile, false)
	file("device_cacerts_file", c.DeviceCACertsFile, false)
	if c.WifiTTL.D < time.Hour {
		errs = append(errs, errors.New("wifi_ttl is required and at least 1h"))
	}
	if c.DeviceTTL.D < time.Hour {
		errs = append(errs, errors.New("device_ttl is required and at least 1h"))
	}
	if c.CodeTTL.D < time.Minute || c.CodeTTL.D > 24*time.Hour {
		errs = append(errs, errors.New("code_ttl must be between 1m and 24h"))
	}
	o := c.OpenBao
	if u, err := url.Parse(o.Address); err != nil || u.Scheme != "https" || u.Host == "" {
		errs = append(errs, errors.New("openbao.address must be an https URL"))
	}
	file("openbao.ca_file", o.CAFile, true)
	file("openbao.role_id_file", o.RoleIDFile, false)
	file("openbao.secret_id_file", o.SecretIDFile, false)
	for name, v := range map[string]string{
		"approle_mount": o.AppRoleMount, "wifi_mount": o.WifiMount, "wifi_role": o.WifiRole,
		"device_mount": o.DeviceMount, "device_role": o.DeviceRole, "kv_mount": o.KVMount,
		"user_groups_path": o.UserGroupsPath,
	} {
		if !pathSegment.MatchString(v) {
			errs = append(errs, fmt.Errorf("openbao.%s %q is not a valid path", name, v))
		}
	}
	if p := c.WifiProfile; p != nil {
		if len(p.SSID) == 0 || len(p.SSID) > 32 || !utf8.ValidString(p.SSID) {
			errs = append(errs, errors.New("wifi_profile.ssid must be 1-32 bytes of UTF-8"))
		}
		if !hostname.MatchString(p.ServerDomain) {
			errs = append(errs, errors.New("wifi_profile.server_domain must be a DNS name"))
		}
		file("wifi_profile.server_ca_file", p.ServerCAFile, false)
	}
	if o.WifiMount == o.DeviceMount {
		errs = append(errs, errors.New("openbao.wifi_mount and device_mount must differ"))
	}
	return errors.Join(errs...)
}

// ReadCertificates reads all certificates from a PEM file; it fails on
// anything else in the file and on an empty file.
func ReadCertificates(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s: unexpected PEM block %q", path, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(bytes.TrimSpace(raw)) != 0 {
		return nil, fmt.Errorf("%s: data that is not PEM", path)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s: no certificates", path)
	}
	return certs, nil
}

// SetupFingerprint is the lowercase hex SHA-256 of the setup CA's DER
// encoding; the file must hold exactly one certificate, which must be a CA.
func (c *Config) SetupFingerprint() (string, error) {
	certs, err := ReadCertificates(c.SetupCAFile)
	if err != nil {
		return "", err
	}
	if len(certs) != 1 {
		return "", fmt.Errorf("%s: expected exactly one certificate, found %d", c.SetupCAFile, len(certs))
	}
	if !certs[0].IsCA {
		return "", fmt.Errorf("%s: not a CA certificate", c.SetupCAFile)
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

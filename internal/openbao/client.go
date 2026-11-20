// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package openbao is a minimal OpenBao client for the calls the service
// makes: AppRole login, PKI sign/revoke/crl rotate and one KV v2 read.
package openbao

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nosini/eap-enroll-server/internal/config"
)

// requestTimeout bounds every single OpenBao request.
const requestTimeout = 20 * time.Second

// maxResponse bounds the size of a response body that is read.
const maxResponse = 1 << 20

// ErrUserNotEnabled means the user is missing from the user-groups map or
// is in the disabled group.
var ErrUserNotEnabled = errors.New("user is not enabled")

// disabledGroup is the group name that disables a user.
const disabledGroup = "disabled"

// usernamePattern is what FreeRADIUS's deployment accepts as a username.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9._@-]+$`)

// Error is a non-2xx answer from OpenBao. Messages are OpenBao's "errors"
// strings, which don't contain secrets.
type Error struct {
	Method   string
	Path     string
	Status   int
	Messages []string
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("openbao %s %s: HTTP %d", e.Method, e.Path, e.Status)
	if len(e.Messages) > 0 {
		msg += ": " + strings.Join(e.Messages, "; ")
	}
	return msg
}

// Client talks to OpenBao with an AppRole token it obtains and renews by
// logging in again.
type Client struct {
	cfg  config.OpenBao
	base *url.URL
	http *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// New creates a client; it doesn't contact OpenBao yet.
func New(cfg config.OpenBao) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(cfg.Address, "/"))
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.TLSServerName}
	if cfg.CAFile != "" {
		certs, err := config.ReadCertificates(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        4,
		IdleConnTimeout:     60 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &Client{
		cfg:  cfg,
		base: base,
		http: &http.Client{
			Transport: transport,
			// OpenBao doesn't redirect these calls; a redirect would
			// send the token elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func readSecretFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return v, nil
}

// raw sends one request and decodes a JSON answer into out (if not nil).
func (c *Client) raw(ctx context.Context, method, path, token string, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	u := *c.base
	u.Path = c.base.Path + "/v1/" + path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// The URL holds no secrets; the error may name it.
		return fmt.Errorf("openbao %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("openbao %s %s: %w", method, path, err)
	}
	if len(data) > maxResponse {
		return fmt.Errorf("openbao %s %s: response too large", method, path)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &Error{Method: method, Path: path, Status: resp.StatusCode}
		var body struct {
			Errors []string `json:"errors"`
		}
		if json.Unmarshal(data, &body) == nil {
			e.Messages = body.Errors
		}
		return e
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("openbao %s %s: invalid JSON answer", method, path)
	}
	return nil
}

// currentToken returns a valid token, logging in when there is none or it
// is about to expire. force discards the cached token.
func (c *Client) currentToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	c.token = ""
	roleID, err := readSecretFile(c.cfg.RoleIDFile)
	if err != nil {
		return "", fmt.Errorf("role ID: %w", err)
	}
	secretID, err := readSecretFile(c.cfg.SecretIDFile)
	if err != nil {
		return "", fmt.Errorf("secret ID: %w", err)
	}
	var resp struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	err = c.raw(ctx, http.MethodPost, "auth/"+c.cfg.AppRoleMount+"/login", "",
		map[string]string{"role_id": roleID, "secret_id": secretID}, &resp)
	if err != nil {
		return "", err
	}
	if resp.Auth.ClientToken == "" {
		return "", errors.New("openbao login: no token in the answer")
	}
	lease := time.Duration(resp.Auth.LeaseDuration) * time.Second
	// Log in again well before the token expires; a token without a
	// lease (0) is still renewed every few minutes.
	margin := min(lease/5, 5*time.Minute)
	if lease <= 0 {
		lease, margin = 5*time.Minute, 0
	}
	c.token = resp.Auth.ClientToken
	c.expires = time.Now().Add(lease - margin)
	return c.token, nil
}

// call sends an authenticated request; on 403 it logs in again once and
// retries, since an expired or revoked token also answers 403.
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	token, err := c.currentToken(ctx, false)
	if err != nil {
		return err
	}
	err = c.raw(ctx, method, path, token, body, out)
	var e *Error
	if errors.As(err, &e) && e.Status == http.StatusForbidden {
		if token, err = c.currentToken(ctx, true); err != nil {
			return err
		}
		err = c.raw(ctx, method, path, token, body, out)
	}
	return err
}

// SignRequest is the body of <mount>/sign/<role>.
type SignRequest struct {
	CSR               string `json:"csr"`
	CommonName        string `json:"common_name"`
	URISANs           string `json:"uri_sans,omitempty"`
	ExcludeCNFromSANs bool   `json:"exclude_cn_from_sans"`
	TTL               string `json:"ttl"`
}

// Signed is a certificate OpenBao issued, with the chain it returned.
type Signed struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
}

// Sign signs a PEM CSR with mount/role.
func (c *Client) Sign(ctx context.Context, mount, role string, req SignRequest) (*Signed, error) {
	var resp struct {
		Data struct {
			Certificate string   `json:"certificate"`
			CAChain     []string `json:"ca_chain"`
			IssuingCA   string   `json:"issuing_ca"`
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodPost, mount+"/sign/"+role, req, &resp); err != nil {
		return nil, err
	}
	leaf, err := parsePEMCertificates(resp.Data.Certificate)
	if err != nil || len(leaf) != 1 {
		return nil, fmt.Errorf("openbao sign: answer has no single certificate")
	}
	chainPEM := resp.Data.CAChain
	if len(chainPEM) == 0 && resp.Data.IssuingCA != "" {
		chainPEM = []string{resp.Data.IssuingCA}
	}
	var chain []*x509.Certificate
	for _, p := range chainPEM {
		certs, err := parsePEMCertificates(p)
		if err != nil {
			return nil, fmt.Errorf("openbao sign: bad CA chain: %w", err)
		}
		chain = append(chain, certs...)
	}
	return &Signed{Certificate: leaf[0], Chain: chain}, nil
}

// Revoke revokes a certificate by serial (as returned by SerialText).
// It doesn't rebuild the CRL; call RotateCRL afterwards.
func (c *Client) Revoke(ctx context.Context, mount, serial string) error {
	colon, err := colonSerial(serial)
	if err != nil {
		return err
	}
	return c.call(ctx, http.MethodPost, mount+"/revoke", map[string]string{"serial_number": colon}, nil)
}

// RotateCRL rebuilds the mount's CRL, which auto_rebuild otherwise defers.
func (c *Client) RotateCRL(ctx context.Context, mount string) error {
	return c.call(ctx, http.MethodGet, mount+"/crl/rotate", nil, nil)
}

// EnabledUser returns the stored spelling of username if it is in the
// user-groups map (ignoring case) and not disabled; ErrUserNotEnabled if
// not; another error if the map can't be read or is malformed.
func (c *Client) EnabledUser(ctx context.Context, username string) (string, error) {
	var resp struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	path := c.cfg.KVMount + "/data/" + c.cfg.UserGroupsPath
	if err := c.call(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return "", err
	}
	return enabledUser(resp.Data.Data, username)
}

func enabledUser(groups map[string]any, username string) (string, error) {
	if len(groups) == 0 {
		return "", errors.New("user-groups map is empty")
	}
	seen := make(map[string]bool, len(groups))
	for name := range groups {
		if !usernamePattern.MatchString(name) {
			return "", errors.New("user-groups map has a username outside letters, digits and ._@-")
		}
		lower := strings.ToLower(name)
		if seen[lower] {
			return "", errors.New("user-groups map has usernames that differ only in case")
		}
		seen[lower] = true
	}
	for name, group := range groups {
		if !strings.EqualFold(name, username) {
			continue
		}
		if g, ok := group.(string); !ok || g == disabledGroup {
			return "", ErrUserNotEnabled
		}
		return name, nil
	}
	return "", ErrUserNotEnabled
}

func parsePEMCertificates(s string) ([]*x509.Certificate, error) {
	raw := []byte(s)
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate")
	}
	return certs, nil
}

// SerialText is the form serials are stored in: lowercase hex of the
// serial's minimal big-endian bytes, without separators.
func SerialText(n *big.Int) string {
	return hex.EncodeToString(n.Bytes())
}

// colonSerial turns SerialText's form into OpenBao's aa:bb:cc form.
func colonSerial(s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) == 0 {
		return "", fmt.Errorf("invalid serial %q", s)
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = hex.EncodeToString([]byte{v})
	}
	return strings.Join(parts, ":"), nil
}

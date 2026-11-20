// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package attest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	statusTimeout         = 30 * time.Second
	statusMaxBody         = 10 << 20
	statusRefreshInterval = 6 * time.Hour
	// statusRetryInterval is used after a failed fetch, so a failure at
	// startup doesn't keep attestation closed for six hours.
	statusRetryInterval = 5 * time.Minute
	statusMaxAge        = 7 * 24 * time.Hour
)

// ErrStatusUnavailable means the revocation list is configured but has
// not been loaded or is too old. Attestation fails closed.
var ErrStatusUnavailable = errors.New("attestation status list unavailable")

// StatusList is Google's public attestation revocation list, refreshed
// in the background.
type StatusList struct {
	url    string
	client *http.Client
	log    *slog.Logger
	now    func() time.Time

	mu      sync.RWMutex
	entries map[string]string // normalized serial (lowercase hex) -> status
	loaded  bool
	fetched time.Time
}

// NewStatusList returns the list for an https status URL, or nil when the
// URL is empty. The list is not fetched yet; Run does that.
func NewStatusList(rawURL string, log *slog.Logger) (*StatusList, error) {
	if rawURL == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("status URL must be an https URL")
	}
	if log == nil {
		log = slog.Default()
	}
	client := &http.Client{
		Timeout: statusTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return errors.New("status URL redirected to a non-https URL")
			}
			if len(via) >= 10 {
				return errors.New("too many status URL redirects")
			}
			return nil
		},
	}
	return &StatusList{url: rawURL, client: client, log: log, now: time.Now}, nil
}

// Run loads the list at once and then every six hours until ctx ends;
// after a failed fetch it retries every five minutes.
func (l *StatusList) Run(ctx context.Context) {
	if l == nil {
		return
	}
	for {
		wait := statusRefreshInterval
		if !l.refresh(ctx) {
			wait = statusRetryInterval
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

func (l *StatusList) refresh(ctx context.Context) bool {
	if err := l.Refresh(ctx); err != nil {
		if ctx.Err() == nil {
			l.log.Error("attestation_status_failed", "error", err.Error())
		}
		return false
	}
	l.mu.RLock()
	n := len(l.entries)
	l.mu.RUnlock()
	l.log.Info("attestation_status_loaded", "entries", n)
	return true
}

// Refresh fetches and parses the list. On failure the last good list is
// kept; Check fails closed once it is too old.
func (l *StatusList) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.url, nil)
	if err != nil {
		return err
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status URL returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, statusMaxBody+1))
	if err != nil {
		return err
	}
	if len(body) > statusMaxBody {
		return fmt.Errorf("status list is larger than %d bytes", statusMaxBody)
	}
	entries, err := parseStatusList(body)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.entries = entries
	l.loaded = true
	l.fetched = l.now()
	l.mu.Unlock()
	return nil
}

func parseStatusList(body []byte) (map[string]string, error) {
	var doc struct {
		Entries map[string]struct {
			Status string `json:"status"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("status list is not JSON: %w", err)
	}
	// Google's list is never empty; an empty one is a broken answer, and
	// accepting it would silently turn revocation checks off.
	if len(doc.Entries) == 0 {
		return nil, errors.New("status list has no entries")
	}
	entries := make(map[string]string, len(doc.Entries))
	for text, entry := range doc.Entries {
		n, ok := new(big.Int).SetString(text, 16)
		if !ok || n.Sign() < 0 {
			return nil, fmt.Errorf("status list has an invalid serial %q", text)
		}
		entries[n.Text(16)] = strings.ToUpper(entry.Status)
	}
	return entries, nil
}

// Check refuses revoked or suspended certificates and fails closed when
// the list is configured but missing or stale. A nil list means the
// revocation list isn't configured.
func (l *StatusList) Check(chain []*x509.Certificate, now time.Time) error {
	if l == nil || l.url == "" {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if !l.loaded || now.Sub(l.fetched) > statusMaxAge {
		return fmt.Errorf("%w: no successful fetch within %v", ErrStatusUnavailable, statusMaxAge)
	}
	for i, cert := range chain {
		if cert.SerialNumber == nil {
			continue
		}
		serial := cert.SerialNumber.Text(16)
		switch l.entries[serial] {
		case "REVOKED", "SUSPENDED":
			return fmt.Errorf("attestation certificate %d with serial %s is %s",
				i, serial, strings.ToLower(l.entries[serial]))
		}
	}
	return nil
}

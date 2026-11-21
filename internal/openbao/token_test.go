// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package openbao

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nosini/eap-enroll-server/internal/config"
)

// TestTokenRevocation checks that a token replaced after a 403 and the
// token left at Close are revoked, and that a 403 for a fresh token (a
// policy denial) doesn't log in again.
func TestTokenRevocation(t *testing.T) {
	var (
		mu      sync.Mutex
		logins  int
		revoked []string
		refused = map[string]bool{}
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		token := r.Header.Get("X-Vault-Token")
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			logins++
			fmt.Fprintf(w, `{"auth":{"client_token":"t%d","lease_duration":1200}}`, logins)
		case "/v1/auth/token/revoke-self":
			revoked = append(revoked, token)
			w.WriteHeader(http.StatusNoContent)
		case "/v1/kv/data/groups":
			if refused[token] {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"alice": "staff"}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c, err := New(config.OpenBao{
		Address:        srv.URL,
		CAFile:         write("ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))),
		RoleIDFile:     write("role-id", "role"),
		SecretIDFile:   write("secret-id", "secret"),
		AppRoleMount:   "approle",
		KVMount:        "kv",
		UserGroupsPath: "groups",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c.now = func() time.Time { return now }
	ctx := context.Background()
	check := func(step string, wantLogins int, wantRevoked ...string) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if logins != wantLogins || !slices.Equal(revoked, wantRevoked) {
			t.Errorf("%s: %d logins, revoked %v; want %d, %v", step, logins, revoked, wantLogins, wantRevoked)
		}
	}
	if _, err := c.EnabledUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	check("first request", 1)

	// t1 is a few minutes old when OpenBao refuses it: expired or
	// revoked, so log in again and revoke it.
	now = now.Add(2 * reloginAfter)
	mu.Lock()
	refused["t1"] = true
	mu.Unlock()
	if _, err := c.EnabledUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	check("after an old token was refused", 2, "t1")

	// A request that failed with a token another request has replaced
	// already uses the new one instead of logging in again.
	if token, err := c.currentToken(ctx, "t1"); err != nil || token != "t2" {
		t.Errorf("currentToken after replacement: %q, %v", token, err)
	}

	// t2 is fresh when OpenBao refuses it: the policy denies the
	// request, so the error comes back and t2 stays.
	mu.Lock()
	refused["t2"] = true
	mu.Unlock()
	if _, err := c.EnabledUser(ctx, "alice"); err == nil {
		t.Error("request refused by the policy succeeded")
	}
	check("after a fresh token was refused", 2, "t1")

	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	check("after Close", 2, "t1", "t2")
}

func TestNewRequiresCA(t *testing.T) {
	if _, err := New(config.OpenBao{Address: "https://openbao.example.org:8200"}); err == nil {
		t.Error("New accepted a configuration without ca_file")
	}
}

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

	"github.com/nosini/eap-enroll-server/internal/config"
)

// TestTokenRevocation checks that a token replaced after a 403 and the
// token left at Close are revoked.
func TestTokenRevocation(t *testing.T) {
	var (
		mu      sync.Mutex
		logins  int
		revoked []string
		refused = map[string]bool{"t1": true} // t1 "expired" on the server
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
	ctx := context.Background()
	if _, err := c.EnabledUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if logins != 2 || !slices.Equal(revoked, []string{"t1"}) {
		t.Errorf("after a refused token: %d logins, revoked %v; want 2, [t1]", logins, revoked)
	}
	mu.Unlock()

	// A request that failed with a token another request has replaced
	// already uses the new one instead of logging in again.
	if token, err := c.currentToken(ctx, "t1"); err != nil || token != "t2" {
		t.Errorf("currentToken after replacement: %q, %v", token, err)
	}

	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if logins != 2 || !slices.Equal(revoked, []string{"t1", "t2"}) {
		t.Errorf("after Close: %d logins, revoked %v; want 2, [t1 t2]", logins, revoked)
	}
}

func TestNewRequiresCA(t *testing.T) {
	if _, err := New(config.OpenBao{Address: "https://openbao.example.org:8200"}); err == nil {
		t.Error("New accepted a configuration without ca_file")
	}
}

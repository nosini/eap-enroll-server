// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package attest

import (
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewStatusList(t *testing.T) {
	if l, err := NewStatusList("", nil); err != nil || l != nil {
		t.Errorf("empty URL: %v %v", l, err)
	}
	if _, err := NewStatusList("http://enroll.example.org/status", nil); err == nil {
		t.Error("http status URL accepted")
	}
	if _, err := NewStatusList("https://enroll.example.org/status", nil); err != nil {
		t.Error(err)
	}
}

func TestStatusListRefresh(t *testing.T) {
	status := http.StatusOK
	body := `{"entries":{"00AB":{"status":"REVOKED"},"cd":{"status":"SUSPENDED"},"ef":{"status":"VALID"}}}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer srv.Close()

	l, err := NewStatusList(srv.URL, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	l.client = srv.Client()
	now := time.Now()
	l.now = func() time.Time { return now }
	if err := l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{
		{SerialNumber: big.NewInt(0xab)},
		{SerialNumber: big.NewInt(0xcd)},
	}
	if err := l.Check(chain, now); err == nil || !strings.Contains(err.Error(), "is revoked") {
		t.Errorf("check revoked leaf: %v", err)
	}
	if err := l.Check(chain[1:], now); err == nil || !strings.Contains(err.Error(), "is suspended") {
		t.Errorf("check suspended: %v", err)
	}
	if err := l.Check([]*x509.Certificate{{SerialNumber: big.NewInt(0xef)}}, now); err != nil {
		t.Errorf("VALID entry refused: %v", err)
	}

	// A failed refresh keeps the last good list.
	status = http.StatusInternalServerError
	if err := l.Refresh(context.Background()); err == nil {
		t.Error("500 accepted")
	}
	if err := l.Check(chain[1:], now); err == nil {
		t.Error("old list lost after a failed refresh")
	}
}

func TestParseStatusListRefusesEmpty(t *testing.T) {
	for _, body := range []string{`{}`, `{"entries":{}}`} {
		if _, err := parseStatusList([]byte(body)); err == nil {
			t.Errorf("%s accepted", body)
		}
	}
}

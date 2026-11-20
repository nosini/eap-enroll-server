// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "enroll.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCheckCode(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	hash := []byte("code-hash")
	if err := s.CheckCode(ctx, hash, now); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("unknown code: %v", err)
	}
	if err := s.CreateCode(ctx, hash, "alice", "Phone", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckCode(ctx, hash, now); err != nil {
		t.Errorf("usable code: %v", err)
	}
	if _, err := s.UseCode(ctx, hash, "00000000-0000-4000-8000-000000000001", now); err != nil {
		t.Fatalf("use code: %v", err)
	}
	if err := s.CheckCode(ctx, hash, now); !errors.Is(err, ErrCodeUsed) {
		t.Errorf("used code: %v", err)
	}

	// An expired code is reported as expired, and checking it doesn't
	// use it up.
	other := []byte("other-hash")
	if err := s.CreateCode(ctx, other, "alice", "Phone", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckCode(ctx, other, now.Add(time.Minute)); !errors.Is(err, ErrCodeExpired) {
		t.Errorf("expired code: %v", err)
	}
	if err := s.CheckCode(ctx, other, now); err != nil {
		t.Errorf("usable after an expiry check: %v", err)
	}
	if _, err := s.UseCode(ctx, other, "00000000-0000-4000-8000-000000000002", now); err != nil {
		t.Errorf("use after an expiry check: %v", err)
	}
}

func TestCertificateLimits(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	hash := []byte("code-hash")
	if err := s.CreateCode(ctx, hash, "alice", "Phone", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	dev, err := s.UseCode(ctx, hash, "00000000-0000-4000-8000-000000000003", now)
	if err != nil {
		t.Fatal(err)
	}
	add := func(kind, serial string, issued time.Time) error {
		return s.AddCertificate(ctx, Certificate{
			Serial: serial, Kind: kind, DeviceID: dev.ID,
			Issued: issued, NotAfter: issued.Add(48 * time.Hour),
		})
	}

	// The sixth valid Wi-Fi certificate is refused in the transaction.
	for i := 0; i < maxValidWifi; i++ {
		if err := add(KindWifi, fmt.Sprintf("wifi%d", i), now); err != nil {
			t.Fatalf("wifi %d: %v", i, err)
		}
	}
	if err := add(KindWifi, "wifi5", now); !errors.Is(err, ErrTooManyCertificates) {
		t.Errorf("sixth valid Wi-Fi certificate: %v", err)
	}
	if err := s.CheckCertificateLimit(ctx, dev.ID, KindWifi, now); !errors.Is(err, ErrTooManyCertificates) {
		t.Errorf("check at the valid cap: %v", err)
	}
	// A revoked certificate frees a slot.
	if err := s.MarkRevoked(ctx, KindWifi, "wifi0", now); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckCertificateLimit(ctx, dev.ID, KindWifi, now); err != nil {
		t.Errorf("check after revoking one: %v", err)
	}
	if err := add(KindWifi, "wifi5", now); err != nil {
		t.Errorf("add after revoking one: %v", err)
	}
	// Expired ones don't count as valid either.
	if err := s.CheckCertificateLimit(ctx, dev.ID, KindWifi, now.Add(3*24*time.Hour)); err != nil {
		t.Errorf("expired certificates count as valid: %v", err)
	}

	// Device credentials: five in 24 hours, revoked ones included, and
	// three valid at most.
	for i := 0; i < maxIssuedDevice; i++ {
		serial := fmt.Sprintf("device%d", i)
		if err := add(KindDevice, serial, now); err != nil {
			t.Fatalf("device %d: %v", i, err)
		}
		if err := s.MarkRevoked(ctx, KindDevice, serial, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CheckCertificateLimit(ctx, dev.ID, KindDevice, now); !errors.Is(err, ErrTooManyCertificates) {
		t.Errorf("check at the 24 hour cap: %v", err)
	}
	if err := s.CheckCertificateLimit(ctx, dev.ID, KindDevice, now.Add(issuanceWindow+time.Minute)); err != nil {
		t.Errorf("check after the window: %v", err)
	}
}

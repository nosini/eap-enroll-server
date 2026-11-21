// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"database/sql"
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
	// The transaction enforces it too, so concurrent requests that all
	// passed the check can't exceed it.
	if err := add(KindDevice, "device5", now); !errors.Is(err, ErrTooManyCertificates) {
		t.Errorf("add at the 24 hour cap: %v", err)
	}
	if err := add(KindDevice, "device5", now.Add(issuanceWindow+time.Minute)); err != nil {
		t.Errorf("add after the window: %v", err)
	}
	if err := s.CheckCertificateLimit(ctx, dev.ID, KindDevice, now.Add(issuanceWindow+time.Minute)); err != nil {
		t.Errorf("check after the window: %v", err)
	}
}

func TestPruneDevices(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	device := func(n int) Device {
		t.Helper()
		hash := []byte(fmt.Sprintf("code-%d", n))
		if err := s.CreateCode(ctx, hash, "alice", fmt.Sprintf("Phone %d", n), now, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		d, err := s.UseCode(ctx, hash, fmt.Sprintf("00000000-0000-4000-8000-%012d", n), now)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	add := func(d Device, kind, serial string, notAfter time.Time) {
		t.Helper()
		if err := s.AddCertificate(ctx, Certificate{
			Serial: serial, Kind: kind, DeviceID: d.ID, Issued: now.Add(-time.Hour), NotAfter: notAfter,
		}); err != nil {
			t.Fatal(err)
		}
	}
	disable := func(d Device) {
		t.Helper()
		if _, err := s.DisableDevice(ctx, d.ID, now); err != nil {
			t.Fatal(err)
		}
	}

	// Enabled: never deleted, even without valid certificates.
	enabled := device(1)
	add(enabled, KindDevice, "d1", now.Add(-time.Minute))
	// Disabled, all certificates revoked: deleted.
	revoked := device(2)
	add(revoked, KindDevice, "d2", now.Add(time.Hour))
	add(revoked, KindWifi, "w2", now.Add(time.Hour))
	disable(revoked)
	for _, c := range []struct{ kind, serial string }{{KindDevice, "d2"}, {KindWifi, "w2"}} {
		if err := s.MarkRevoked(ctx, c.kind, c.serial, now); err != nil {
			t.Fatal(err)
		}
	}
	// Disabled, the unrevoked certificate has expired: deleted.
	expired := device(3)
	add(expired, KindWifi, "w3", now.Add(-time.Minute))
	disable(expired)
	// Disabled without certificates: deleted.
	empty := device(4)
	disable(empty)
	// Disabled but a certificate is still valid and unrevoked (the
	// revocation failed): kept for a disable rerun.
	unfinished := device(5)
	add(unfinished, KindWifi, "w5", now.Add(time.Hour))
	disable(unfinished)

	pruned, pending, err := s.PruneDevices(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	ids := func(list []Device) []string {
		var out []string
		for _, d := range list {
			out = append(out, d.ID)
		}
		return out
	}
	if got, want := fmt.Sprint(ids(pruned)), fmt.Sprint([]string{revoked.ID, expired.ID, empty.ID}); got != want {
		t.Errorf("pruned %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(ids(pending)), fmt.Sprint([]string{unfinished.ID}); got != want {
		t.Errorf("pending %s, want %s", got, want)
	}
	for _, d := range []Device{revoked, expired, empty} {
		if _, err := s.Device(ctx, d.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("device %s still there: %v", d.ID, err)
		}
	}
	for _, c := range []struct{ kind, serial string }{{KindDevice, "d2"}, {KindWifi, "w2"}, {KindWifi, "w3"}} {
		if _, err := s.Certificate(ctx, c.kind, c.serial); !errors.Is(err, ErrNotFound) {
			t.Errorf("certificate %s %s still there: %v", c.kind, c.serial, err)
		}
	}
	for _, d := range []Device{enabled, unfinished} {
		if _, err := s.Device(ctx, d.ID); err != nil {
			t.Errorf("device %s deleted: %v", d.ID, err)
		}
	}
	if _, err := s.Certificate(ctx, KindWifi, "w5"); err != nil {
		t.Errorf("pending device's certificate deleted: %v", err)
	}

	// Once the revocation is recorded, the next prune deletes it.
	if err := s.MarkRevoked(ctx, KindWifi, "w5", now); err != nil {
		t.Fatal(err)
	}
	pruned, pending, err = s.PruneDevices(ctx, now)
	if err != nil || len(pruned) != 1 || pruned[0].ID != unfinished.ID || len(pending) != 0 {
		t.Errorf("second prune: %v %v %v", ids(pruned), ids(pending), err)
	}
}

func TestCredentialUse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	hash := []byte("code-hash")
	if err := s.CreateCode(ctx, hash, "alice", "Phone", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	dev, err := s.UseCode(ctx, hash, "00000000-0000-4000-8000-000000000005", now)
	if err != nil {
		t.Fatal(err)
	}
	add := func(serial string) {
		t.Helper()
		if err := s.AddCertificate(ctx, Certificate{
			Serial: serial, Kind: KindDevice, DeviceID: dev.ID, Issued: now, NotAfter: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	state := func(serial string) Certificate {
		t.Helper()
		c, err := s.Certificate(ctx, KindDevice, serial)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	add("a")
	if err := s.UseCredential(ctx, dev.ID, "a", now); err != nil {
		t.Fatalf("use a: %v", err)
	}
	if c := state("a"); c.Used == nil || c.Superseded != nil {
		t.Errorf("a after use: %+v", c)
	}
	if err := s.UseCredential(ctx, "00000000-0000-4000-8000-000000000006", "a", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("another device's credential: %v", err)
	}

	// Two renewals with a; b is replaced by c before it was used.
	add("b")
	add("c")
	if got, err := s.SupersedeUnused(ctx, dev.ID, "a", "c", now); err != nil || len(got) != 1 || got[0] != "b" {
		t.Fatalf("supersede unused: %v %v", got, err)
	}
	if c := state("b"); c.Superseded == nil {
		t.Error("b not superseded")
	}
	if c := state("a"); c.Superseded != nil {
		t.Error("the presented credential was superseded")
	}
	if err := s.UseCredential(ctx, dev.ID, "b", now); !errors.Is(err, ErrSuperseded) {
		t.Errorf("use of a replaced renewal: %v", err)
	}

	// Using c supersedes a; a is then refused.
	if err := s.UseCredential(ctx, dev.ID, "c", now); err != nil {
		t.Fatalf("use c: %v", err)
	}
	if err := s.UseCredential(ctx, dev.ID, "a", now); !errors.Is(err, ErrSuperseded) {
		t.Errorf("use of a superseded credential: %v", err)
	}
	// Used credentials are never replaced as unused.
	add("d")
	if got, err := s.SupersedeUnused(ctx, dev.ID, "a", "d", now); err != nil || len(got) != 0 {
		t.Errorf("supersede after c was used: %v %v", got, err)
	}

	list, err := s.SupersededCertificates(ctx, dev.ID, now)
	if err != nil || len(list) != 2 || list[0].Serial != "a" || list[1].Serial != "b" {
		t.Fatalf("superseded: %+v %v", list, err)
	}
	if err := s.MarkRevoked(ctx, KindDevice, "a", now); err != nil {
		t.Fatal(err)
	}
	if list, err := s.SupersededCertificates(ctx, dev.ID, now); err != nil || len(list) != 1 {
		t.Errorf("superseded after revoking one: %+v %v", list, err)
	}

	// Superseded credentials don't count as valid: c and d.
	var valid int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM certificates`).Scan(&valid); err != nil || valid != 4 {
		t.Fatalf("certificates: %d %v", valid, err)
	}
	add("e") // the third valid one
	if err := s.CheckCertificateLimit(ctx, dev.ID, KindDevice, now); !errors.Is(err, ErrTooManyCertificates) {
		t.Errorf("check at the cap: %v", err)
	}
}

func TestMigrateFromVersion1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enroll.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE codes (hash BLOB PRIMARY KEY, username TEXT NOT NULL, label TEXT NOT NULL,
			created INTEGER NOT NULL, expires INTEGER NOT NULL, used INTEGER) STRICT`,
		`CREATE TABLE devices (id TEXT PRIMARY KEY, username TEXT NOT NULL, label TEXT NOT NULL,
			created INTEGER NOT NULL, disabled INTEGER) STRICT`,
		`CREATE TABLE certificates (serial TEXT NOT NULL,
			kind TEXT NOT NULL CHECK (kind IN ('device', 'wifi')),
			device_id TEXT NOT NULL REFERENCES devices(id), issued INTEGER NOT NULL,
			not_after INTEGER NOT NULL, revoked INTEGER, PRIMARY KEY (kind, serial)) STRICT`,
		`CREATE INDEX certificates_device ON certificates(device_id)`,
		`INSERT INTO devices VALUES ('d', 'alice', 'Phone', 1, NULL)`,
		`INSERT INTO certificates VALUES ('old', 'device', 'd', 1, 9999999999, 5)`,
		`INSERT INTO certificates VALUES ('new', 'device', 'd', 2, 9999999999, NULL)`,
		`INSERT INTO certificates VALUES ('w', 'wifi', 'd', 2, 9999999999, 7)`,
		`PRAGMA user_version = 1`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	old, err := s.Certificate(ctx, KindDevice, "old")
	if err != nil || old.Superseded == nil || old.Superseded.Unix() != 5 {
		t.Errorf("revoked device credential after migration: %+v %v", old, err)
	}
	if c, err := s.Certificate(ctx, KindDevice, "new"); err != nil || c.Superseded != nil || c.Used != nil {
		t.Errorf("current device credential after migration: %+v %v", c, err)
	}
	if c, err := s.Certificate(ctx, KindWifi, "w"); err != nil || c.Superseded != nil {
		t.Errorf("Wi-Fi certificate after migration: %+v %v", c, err)
	}
	if err := s.UseCredential(ctx, "d", "old", time.Now()); !errors.Is(err, ErrSuperseded) {
		t.Errorf("revoked credential after migration: %v", err)
	}
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != schemaVersion {
		t.Errorf("version %d %v", version, err)
	}
}

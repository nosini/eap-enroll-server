// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package store keeps devices, one-time code hashes and issued
// certificates in SQLite. The server and the admin commands open the same
// file concurrently.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"
)

// Errors the callers distinguish.
var (
	ErrNotFound       = errors.New("not found")
	ErrCodeInvalid    = errors.New("unknown code")
	ErrCodeUsed       = errors.New("code already used")
	ErrCodeExpired    = errors.New("code expired")
	ErrDeviceDisabled = errors.New("device is disabled")
)

// Certificate kinds.
const (
	KindDevice = "device"
	KindWifi   = "wifi"
)

// schemaVersion is stored in PRAGMA user_version.
const schemaVersion = 1

var schema = []string{
	`CREATE TABLE codes (
		hash BLOB PRIMARY KEY,
		username TEXT NOT NULL,
		label TEXT NOT NULL,
		created INTEGER NOT NULL,
		expires INTEGER NOT NULL,
		used INTEGER
	) STRICT`,
	`CREATE TABLE devices (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		label TEXT NOT NULL,
		created INTEGER NOT NULL,
		disabled INTEGER
	) STRICT`,
	`CREATE TABLE certificates (
		serial TEXT NOT NULL,
		kind TEXT NOT NULL CHECK (kind IN ('device', 'wifi')),
		device_id TEXT NOT NULL REFERENCES devices(id),
		issued INTEGER NOT NULL,
		not_after INTEGER NOT NULL,
		revoked INTEGER,
		PRIMARY KEY (kind, serial)
	) STRICT`,
	`CREATE INDEX certificates_device ON certificates(device_id)`,
}

// Device is a registered phone.
type Device struct {
	ID       string
	Username string
	Label    string
	Created  time.Time
	Disabled *time.Time
}

// Certificate is an issued certificate. Serial is lowercase hex without
// separators (openbao.SerialText).
type Certificate struct {
	Serial   string
	Kind     string
	DeviceID string
	Issued   time.Time
	NotAfter time.Time
	Revoked  *time.Time
}

// Store is an open database.
type Store struct {
	db *sql.DB
}

// Open opens or creates the database and brings the schema up to date.
func Open(path string) (*Store, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("database path %q: empty or contains ? or #", path)
	}
	q := url.Values{}
	q.Set("_txlock", "immediate")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "foreign_keys(1)")
	db, err := sql.Open("sqlite", path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database %s: %w", path, err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	switch {
	case version == schemaVersion:
		return nil
	case version > schemaVersion:
		return fmt.Errorf("schema version %d is newer than this program (%d)", version, schemaVersion)
	case version != 0:
		return fmt.Errorf("no migration from schema version %d", version)
	}
	for _, stmt := range schema {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

func unix(t time.Time) int64 { return t.Unix() }

func fromUnix(v int64) time.Time { return time.Unix(v, 0).UTC() }

func fromNullUnix(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromUnix(v.Int64)
	return &t
}

// CreateCode stores a code hash for username and label.
func (s *Store) CreateCode(ctx context.Context, hash []byte, username, label string, created, expires time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO codes (hash, username, label, created, expires) VALUES (?, ?, ?, ?, ?)`,
		hash, username, label, unix(created), unix(expires))
	return err
}

// UseCode consumes a code and creates a device with deviceID for the
// code's username and label, in one transaction.
func (s *Store) UseCode(ctx context.Context, hash []byte, deviceID string, now time.Time) (Device, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback()
	var (
		username, label string
		expires         int64
		used            sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `SELECT username, label, expires, used FROM codes WHERE hash = ?`, hash).
		Scan(&username, &label, &expires, &used)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Device{}, ErrCodeInvalid
	case err != nil:
		return Device{}, err
	case used.Valid:
		return Device{}, ErrCodeUsed
	case unix(now) >= expires:
		return Device{}, ErrCodeExpired
	}
	if _, err := tx.ExecContext(ctx, `UPDATE codes SET used = ? WHERE hash = ?`, unix(now), hash); err != nil {
		return Device{}, err
	}
	d := Device{ID: deviceID, Username: username, Label: label, Created: fromUnix(unix(now))}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO devices (id, username, label, created) VALUES (?, ?, ?, ?)`,
		d.ID, d.Username, d.Label, unix(now)); err != nil {
		return Device{}, err
	}
	return d, tx.Commit()
}

// DeleteDevice removes a device that has no certificates (enrollment
// failed after the code was consumed).
func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM devices WHERE id = ? AND NOT EXISTS (SELECT 1 FROM certificates WHERE device_id = ?)`, id, id)
	return err
}

// Device returns a device by ID.
func (s *Store) Device(ctx context.Context, id string) (Device, error) {
	var (
		d        Device
		created  int64
		disabled sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, label, created, disabled FROM devices WHERE id = ?`, id).
		Scan(&d.ID, &d.Username, &d.Label, &created, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
	d.Created, d.Disabled = fromUnix(created), fromNullUnix(disabled)
	return d, nil
}

// AddCertificate records an issued certificate. It fails with
// ErrDeviceDisabled if the device was disabled meanwhile; the caller must
// then revoke the certificate. Because SQLite serialises writers, either
// this insert happens before the device is disabled (and disabling sees
// and revokes the certificate) or it fails.
func (s *Store) AddCertificate(ctx context.Context, c Certificate) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var disabled sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT disabled FROM devices WHERE id = ?`, c.DeviceID).Scan(&disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if disabled.Valid {
		return ErrDeviceDisabled
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO certificates (serial, kind, device_id, issued, not_after) VALUES (?, ?, ?, ?, ?)`,
		c.Serial, c.Kind, c.DeviceID, unix(c.Issued), unix(c.NotAfter)); err != nil {
		return err
	}
	return tx.Commit()
}

// Certificate returns a certificate by kind and serial.
func (s *Store) Certificate(ctx context.Context, kind, serial string) (Certificate, error) {
	var (
		c                Certificate
		issued, notAfter int64
		revoked          sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT serial, kind, device_id, issued, not_after, revoked FROM certificates WHERE kind = ? AND serial = ?`,
		kind, serial).Scan(&c.Serial, &c.Kind, &c.DeviceID, &issued, &notAfter, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, ErrNotFound
	}
	if err != nil {
		return Certificate{}, err
	}
	c.Issued, c.NotAfter, c.Revoked = fromUnix(issued), fromUnix(notAfter), fromNullUnix(revoked)
	return c, nil
}

// DisableDevice marks a device disabled (keeping an earlier time if it
// already was) and returns it.
func (s *Store) DisableDevice(ctx context.Context, id string, now time.Time) (Device, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE devices SET disabled = coalesce(disabled, ?) WHERE id = ?`, unix(now), id)
	if err != nil {
		return Device{}, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return Device{}, err
	} else if n == 0 {
		return Device{}, ErrNotFound
	}
	return s.Device(ctx, id)
}

// UnrevokedCertificates lists a device's certificates that are neither
// revoked nor expired at now.
func (s *Store) UnrevokedCertificates(ctx context.Context, deviceID string, now time.Time) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT serial, kind, device_id, issued, not_after FROM certificates
		 WHERE device_id = ? AND revoked IS NULL AND not_after > ? ORDER BY issued`,
		deviceID, unix(now))
	if err != nil {
		return nil, err
	}
	return scanCertificates(rows)
}

// OlderCertificates lists a device's unrevoked, unexpired certificates of
// kind that were recorded before the certificate with serial.
func (s *Store) OlderCertificates(ctx context.Context, deviceID, kind, serial string, now time.Time) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT serial, kind, device_id, issued, not_after FROM certificates
		 WHERE device_id = ? AND kind = ? AND revoked IS NULL AND not_after > ?
		   AND rowid < (SELECT rowid FROM certificates WHERE kind = ? AND serial = ?)
		 ORDER BY rowid`,
		deviceID, kind, unix(now), kind, serial)
	if err != nil {
		return nil, err
	}
	return scanCertificates(rows)
}

// scanCertificates reads rows of serial, kind, device_id, issued,
// not_after.
func scanCertificates(rows *sql.Rows) ([]Certificate, error) {
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		var (
			c                Certificate
			issued, notAfter int64
		)
		if err := rows.Scan(&c.Serial, &c.Kind, &c.DeviceID, &issued, &notAfter); err != nil {
			return nil, err
		}
		c.Issued, c.NotAfter = fromUnix(issued), fromUnix(notAfter)
		out = append(out, c)
	}
	return out, rows.Err()
}

// MarkRevoked records that a certificate was revoked.
func (s *Store) MarkRevoked(ctx context.Context, kind, serial string, now time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE certificates SET revoked = coalesce(revoked, ?) WHERE kind = ? AND serial = ?`,
		unix(now), kind, serial)
	return err
}

// DeviceSummary is a row of the device list.
type DeviceSummary struct {
	Device
	WifiNotAfter   *time.Time
	DeviceNotAfter *time.Time
}

// Devices lists all devices with the expiry of their newest unrevoked
// certificate of each kind.
func (s *Store) Devices(ctx context.Context) ([]DeviceSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, d.username, d.label, d.created, d.disabled,
		  (SELECT max(not_after) FROM certificates WHERE device_id = d.id AND kind = 'wifi' AND revoked IS NULL),
		  (SELECT max(not_after) FROM certificates WHERE device_id = d.id AND kind = 'device' AND revoked IS NULL)
		FROM devices d ORDER BY d.username, d.created`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceSummary
	for rows.Next() {
		var (
			d                          DeviceSummary
			created                    int64
			disabled, wifi, deviceCert sql.NullInt64
		)
		if err := rows.Scan(&d.ID, &d.Username, &d.Label, &created, &disabled, &wifi, &deviceCert); err != nil {
			return nil, err
		}
		d.Created, d.Disabled = fromUnix(created), fromNullUnix(disabled)
		d.WifiNotAfter, d.DeviceNotAfter = fromNullUnix(wifi), fromNullUnix(deviceCert)
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteExpiredCodes removes codes (used or not) whose validity ended.
func (s *Store) DeleteExpiredCodes(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM codes WHERE expires <= ?`, unix(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

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
	ErrNotFound            = errors.New("not found")
	ErrCodeInvalid         = errors.New("unknown code")
	ErrCodeUsed            = errors.New("code already used")
	ErrCodeExpired         = errors.New("code expired")
	ErrDeviceDisabled      = errors.New("device is disabled")
	ErrTooManyCertificates = errors.New("too many certificates for this device")
	ErrSuperseded          = errors.New("device credential was superseded")
)

// Certificate kinds.
const (
	KindDevice = "device"
	KindWifi   = "wifi"
)

// Per-device limits on the certificates of each kind: at most this many
// are valid (unrevoked, unexpired) at once, and at most this many are
// issued within issuanceWindow, counting revoked ones.
const (
	maxValidWifi    = 5
	maxValidDevice  = 3
	maxIssuedWifi   = 10
	maxIssuedDevice = 5
	issuanceWindow  = 24 * time.Hour
)

// limits returns the per-device caps for a certificate kind.
func limits(kind string) (valid, issued int) {
	if kind == KindDevice {
		return maxValidDevice, maxIssuedDevice
	}
	return maxValidWifi, maxIssuedWifi
}

// schemaVersion is stored in PRAGMA user_version.
const schemaVersion = 2

// schema creates the current version in an empty database.
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
		used INTEGER,
		superseded INTEGER,
		PRIMARY KEY (kind, serial)
	) STRICT`,
	`CREATE INDEX certificates_device ON certificates(device_id)`,
}

// migrations[v] brings a database from version v+1 to v+2.
var migrations = [][]string{
	// 1 -> 2: device credentials record their first use and when a newer
	// one replaced them. Revoked ones were all replaced (or their device
	// is disabled).
	{
		`ALTER TABLE certificates ADD COLUMN used INTEGER`,
		`ALTER TABLE certificates ADD COLUMN superseded INTEGER`,
		`UPDATE certificates SET superseded = revoked WHERE kind = 'device' AND revoked IS NOT NULL`,
	},
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
// separators (openbao.SerialText). Used and Superseded are only set for
// device credentials: when the credential first authenticated, and when
// a newer one took its place, after which presenting it is reuse.
type Certificate struct {
	Serial     string
	Kind       string
	DeviceID   string
	Issued     time.Time
	NotAfter   time.Time
	Revoked    *time.Time
	Used       *time.Time
	Superseded *time.Time
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
	var stmts []string
	switch {
	case version == schemaVersion:
		return nil
	case version > schemaVersion:
		return fmt.Errorf("schema version %d is newer than this program (%d)", version, schemaVersion)
	case version == 0:
		stmts = schema
	default:
		for _, m := range migrations[version-1:] {
			stmts = append(stmts, m...)
		}
	}
	for _, stmt := range stmts {
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

// queryer is a database or transaction, which is all readCode needs.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// readCode reads a code and reports whether it can be used at now: nil,
// ErrCodeInvalid, ErrCodeUsed or ErrCodeExpired. UseCode and CheckCode
// share it so both answer the same.
func readCode(ctx context.Context, q queryer, hash []byte, now time.Time) (username, label string, err error) {
	var (
		expires int64
		used    sql.NullInt64
	)
	err = q.QueryRowContext(ctx, `SELECT username, label, expires, used FROM codes WHERE hash = ?`, hash).
		Scan(&username, &label, &expires, &used)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", "", ErrCodeInvalid
	case err != nil:
		return "", "", err
	case used.Valid:
		return "", "", ErrCodeUsed
	case unix(now) >= expires:
		return "", "", ErrCodeExpired
	}
	return username, label, nil
}

// CheckCode reports whether a code can be used, without changing
// anything: nil, ErrCodeInvalid, ErrCodeUsed or ErrCodeExpired.
func (s *Store) CheckCode(ctx context.Context, hash []byte, now time.Time) error {
	_, _, err := readCode(ctx, s.db, hash, now)
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
	username, label, err := readCode(ctx, tx, hash, now)
	if err != nil {
		return Device{}, err
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
// ErrDeviceDisabled if the device was disabled meanwhile and with
// ErrTooManyCertificates if the device is at one of the caps
// CheckCertificateLimit checks; the caller must then revoke the
// certificate. Because SQLite serialises writers, either this insert
// happens before the device is disabled (and disabling sees and revokes
// the certificate) or it fails, and concurrent requests can't exceed the
// caps.
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
	if err := checkLimits(ctx, tx, c.DeviceID, c.Kind, c.Issued); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO certificates (serial, kind, device_id, issued, not_after) VALUES (?, ?, ?, ?, ?)`,
		c.Serial, c.Kind, c.DeviceID, unix(c.Issued), unix(c.NotAfter)); err != nil {
		return err
	}
	return tx.Commit()
}

// CheckCertificateLimit reports whether the device may get another
// certificate of kind at now: ErrTooManyCertificates if it already has
// the maximum number of valid ones (unrevoked, unexpired and not
// superseded) or was issued the maximum number within issuanceWindow.
func (s *Store) CheckCertificateLimit(ctx context.Context, deviceID, kind string, now time.Time) error {
	return checkLimits(ctx, s.db, deviceID, kind, now)
}

// checkLimits is CheckCertificateLimit on a database or transaction.
func checkLimits(ctx context.Context, q queryer, deviceID, kind string, now time.Time) error {
	var valid, issued int
	err := q.QueryRowContext(ctx, `
		SELECT
		  coalesce(sum(CASE WHEN revoked IS NULL AND superseded IS NULL AND not_after > ? THEN 1 ELSE 0 END), 0),
		  coalesce(sum(CASE WHEN issued > ? THEN 1 ELSE 0 END), 0)
		FROM certificates WHERE device_id = ? AND kind = ?`,
		unix(now), unix(now.Add(-issuanceWindow)), deviceID, kind).Scan(&valid, &issued)
	if err != nil {
		return err
	}
	maxValid, maxIssued := limits(kind)
	if valid >= maxValid || issued >= maxIssued {
		return ErrTooManyCertificates
	}
	return nil
}

// Certificate returns a certificate by kind and serial.
func (s *Store) Certificate(ctx context.Context, kind, serial string) (Certificate, error) {
	return readCertificate(ctx, s.db, kind, serial)
}

func readCertificate(ctx context.Context, q queryer, kind, serial string) (Certificate, error) {
	var (
		c                         Certificate
		issued, notAfter          int64
		revoked, used, superseded sql.NullInt64
	)
	err := q.QueryRowContext(ctx,
		`SELECT serial, kind, device_id, issued, not_after, revoked, used, superseded
		 FROM certificates WHERE kind = ? AND serial = ?`,
		kind, serial).Scan(&c.Serial, &c.Kind, &c.DeviceID, &issued, &notAfter, &revoked, &used, &superseded)
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, ErrNotFound
	}
	if err != nil {
		return Certificate{}, err
	}
	c.Issued, c.NotAfter, c.Revoked = fromUnix(issued), fromUnix(notAfter), fromNullUnix(revoked)
	c.Used, c.Superseded = fromNullUnix(used), fromNullUnix(superseded)
	return c, nil
}

// UseCredential records that a device credential authenticated at now:
// it is marked used, and the device's older credentials are marked
// superseded, so presenting one of them later is reuse. In the same
// transaction it fails with ErrSuperseded if the credential itself was
// superseded or revoked meanwhile, and with ErrNotFound if it isn't one
// of the device's credentials.
func (s *Store) UseCredential(ctx context.Context, deviceID, serial string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	c, err := readCertificate(ctx, tx, KindDevice, serial)
	if err != nil {
		return err
	}
	if c.DeviceID != deviceID {
		return ErrNotFound
	}
	if c.Superseded != nil || c.Revoked != nil {
		return ErrSuperseded
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE certificates SET used = coalesce(used, ?) WHERE kind = 'device' AND serial = ?`,
		unix(now), serial); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE certificates SET superseded = ?
		 WHERE device_id = ? AND kind = 'device' AND superseded IS NULL
		   AND rowid < (SELECT rowid FROM certificates WHERE kind = 'device' AND serial = ?)`,
		unix(now), deviceID, serial); err != nil {
		return err
	}
	return tx.Commit()
}

// SupersedeUnused marks the device credentials that were issued after
// presented and before issued and never used as superseded: renewals with
// presented whose answers the phone didn't get, or that someone else
// holds. It returns their serials.
func (s *Store) SupersedeUnused(ctx context.Context, deviceID, presented, issued string, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`UPDATE certificates SET superseded = ?
		 WHERE device_id = ? AND kind = 'device' AND used IS NULL AND superseded IS NULL AND revoked IS NULL
		   AND rowid > (SELECT rowid FROM certificates WHERE kind = 'device' AND serial = ?)
		   AND rowid < (SELECT rowid FROM certificates WHERE kind = 'device' AND serial = ?)
		 RETURNING serial`,
		unix(now), deviceID, presented, issued)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var serials []string
	for rows.Next() {
		var serial string
		if err := rows.Scan(&serial); err != nil {
			return nil, err
		}
		serials = append(serials, serial)
	}
	return serials, rows.Err()
}

// SupersededCertificates lists a device's superseded credentials that are
// not yet revoked and not expired at now.
func (s *Store) SupersededCertificates(ctx context.Context, deviceID string, now time.Time) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT serial, kind, device_id, issued, not_after FROM certificates
		 WHERE device_id = ? AND kind = 'device' AND superseded IS NOT NULL
		   AND revoked IS NULL AND not_after > ? ORDER BY rowid`,
		deviceID, unix(now))
	if err != nil {
		return nil, err
	}
	return scanCertificates(rows)
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
// (and, for device credentials, not superseded) certificate of each kind.
func (s *Store) Devices(ctx context.Context) ([]DeviceSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, d.username, d.label, d.created, d.disabled,
		  (SELECT max(not_after) FROM certificates WHERE device_id = d.id AND kind = 'wifi' AND revoked IS NULL),
		  (SELECT max(not_after) FROM certificates
		   WHERE device_id = d.id AND kind = 'device' AND revoked IS NULL AND superseded IS NULL)
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

// PruneDevices deletes disabled devices whose certificates are all
// revoked or expired at now, together with their certificate records.
// Disabled devices that still have a valid unrevoked certificate (their
// disable didn't finish) are kept and returned as pending, so that
// rerunning disable can revoke the rest. Enabled devices are never
// touched.
func (s *Store) PruneDevices(ctx context.Context, now time.Time) (pruned, pending []Device, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
		SELECT d.id, d.username, d.label, d.created, d.disabled,
		  EXISTS (SELECT 1 FROM certificates c
		          WHERE c.device_id = d.id AND c.revoked IS NULL AND c.not_after > ?)
		FROM devices d WHERE d.disabled IS NOT NULL ORDER BY d.username, d.created`, unix(now))
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var (
			d        Device
			created  int64
			disabled sql.NullInt64
			valid    bool
		)
		if err := rows.Scan(&d.ID, &d.Username, &d.Label, &created, &disabled, &valid); err != nil {
			rows.Close()
			return nil, nil, err
		}
		d.Created, d.Disabled = fromUnix(created), fromNullUnix(disabled)
		if valid {
			pending = append(pending, d)
		} else {
			pruned = append(pruned, d)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for _, d := range pruned {
		if _, err := tx.ExecContext(ctx, `DELETE FROM certificates WHERE device_id = ?`, d.ID); err != nil {
			return nil, nil, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, d.ID); err != nil {
			return nil, nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return pruned, pending, nil
}

// DeleteExpiredCodes removes codes (used or not) whose validity ended.
func (s *Store) DeleteExpiredCodes(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM codes WHERE expires <= ?`, unix(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

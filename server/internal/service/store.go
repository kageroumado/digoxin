package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/kageroumado/digoxin/server/identity"
	_ "modernc.org/sqlite"
)

// schema is the database at schemaVersion. It is applied on every start
// after the migrations; each statement is idempotent.
const schema = `
CREATE TABLE IF NOT EXISTS installs (
	id            TEXT PRIMARY KEY,
	app           TEXT NOT NULL,
	public_key    BLOB NOT NULL,
	trust         TEXT NOT NULL,
	attest_env    TEXT,
	-- The attested key's policy (identity.KeyPolicy as JSON), for attested installs.
	attest_policy TEXT,
	-- created, updated and last_seen are days, YYYY-MM-DD.
	created       TEXT NOT NULL,
	updated       TEXT NOT NULL,
	-- The last day this install sent a heartbeat or registered; retention
	-- forgets installs silent for longer than it keeps heartbeats.
	last_seen     TEXT NOT NULL,
	last_seq      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS installs_app ON installs(app, trust);

-- One row per install per day of use: day is the client's local calendar
-- day, and no time of day is kept.
CREATE TABLE IF NOT EXISTS heartbeats (
	install      TEXT NOT NULL REFERENCES installs(id) ON DELETE CASCADE,
	app          TEXT NOT NULL,
	day          TEXT NOT NULL,
	app_version  TEXT NOT NULL,
	app_build    TEXT NOT NULL,
	os           TEXT NOT NULL,
	arch         TEXT NOT NULL,
	chip_family  TEXT NOT NULL,
	memory_gb    INTEGER NOT NULL,
	language     TEXT NOT NULL,
	active_days7 INTEGER NOT NULL,
	properties   TEXT NOT NULL,
	PRIMARY KEY (install, day)
);
CREATE INDEX IF NOT EXISTS heartbeats_app_day ON heartbeats(app, day);

-- Daily active counts kept after the raw heartbeats are dropped.
CREATE TABLE IF NOT EXISTS daily_actives (
	app      TEXT NOT NULL,
	day      TEXT NOT NULL,
	trust    TEXT NOT NULL,
	installs INTEGER NOT NULL,
	PRIMARY KEY (app, day, trust)
);

CREATE TABLE IF NOT EXISTS crash_reports (
	id       TEXT PRIMARY KEY,
	install  TEXT NOT NULL REFERENCES installs(id) ON DELETE CASCADE,
	app      TEXT NOT NULL,
	-- The UTC day it arrived, YYYY-MM-DD.
	received TEXT NOT NULL,
	context  TEXT NOT NULL,
	-- The files as stored, [{"name","size"}], under <crash dir>/<app>/<id>/.
	files    TEXT NOT NULL,
	bytes    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS crash_reports_app ON crash_reports(app, received);
CREATE INDEX IF NOT EXISTS crash_reports_install ON crash_reports(install, received);
`

// errReplay is a sequence number the install has already used.
var errReplay = errors.New("sequence number already used")

// Store is the database plus the lock that serializes writers: SQLite takes
// one writer at a time, and waiting here is cheaper than a busy retry.
type Store struct {
	db    *sql.DB
	write sync.Mutex
}

// OpenStore opens or creates the database at path.
func OpenStore(path string) (*Store, error) {
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if err := migrate(context.Background(), db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

type installRecord struct {
	ID        string
	App       string
	PublicKey []byte
	Trust     string
	LastSeq   int64
}

// install loads an install of app, or nil when app has none by that id.
func (s *Store) install(ctx context.Context, app, id string) (*installRecord, error) {
	var rec installRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT id, app, public_key, trust, last_seq FROM installs WHERE id = ? AND app = ?`, id, app,
	).Scan(&rec.ID, &rec.App, &rec.PublicKey, &rec.Trust, &rec.LastSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &rec, err
}

// saveInstall registers a key, or refreshes the evidence of one already
// known while keeping its sequence number and any trust an operator set.
func (s *Store) saveInstall(ctx context.Context, app, id string, key []byte, v identity.Verdict, now time.Time) error {
	policy := ""
	if v.Policy != nil {
		encoded, err := json.Marshal(v.Policy)
		if err != nil {
			return err
		}
		policy = string(encoded)
	}
	s.write.Lock()
	defer s.write.Unlock()
	// Days, never times: when someone first used an app is not kept.
	stamp := now.UTC().Format(dayLayout)
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO installs (id, app, public_key, trust, attest_env, attest_policy, created, updated, last_seen, last_seq)
		VALUES (?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, 0)
		ON CONFLICT(id) DO UPDATE SET
			trust = CASE WHEN installs.trust IN ('verified', 'blocked') THEN installs.trust ELSE excluded.trust END,
			attest_env = excluded.attest_env, attest_policy = excluded.attest_policy,
			updated = excluded.updated, last_seen = excluded.last_seen
		WHERE installs.app = excluded.app`,
		id, app, key, v.Trust, v.Env, policy, stamp, stamp, stamp)
	if err != nil {
		return err
	}
	// The conflict's WHERE leaves another app's row alone and changes nothing.
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errOtherApp
	}
	return nil
}

// errOtherApp is a key another app registered first.
var errOtherApp = errors.New("key registered for another app")

// advance moves an install's sequence number to seq inside tx, refusing
// one already used.
func advance(ctx context.Context, tx *sql.Tx, install string, seq int64) error {
	result, err := tx.ExecContext(ctx, `UPDATE installs SET last_seq = ? WHERE id = ? AND last_seq < ?`, seq, install, seq)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errReplay
	}
	return nil
}

// deleteInstall forgets an install, its heartbeats and its crash reports,
// and answers the crash report ids whose files the caller removes.
func (s *Store) deleteInstall(ctx context.Context, install string, seq int64) ([]string, error) {
	s.write.Lock()
	defer s.write.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := advance(ctx, tx, install, seq); err != nil {
		return nil, err
	}
	crashes, err := crashIDs(ctx, tx, `SELECT id FROM crash_reports WHERE install = ?`, install)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM installs WHERE id = ?`, install); err != nil {
		return nil, err
	}
	return crashes, tx.Commit()
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func crashIDs(ctx context.Context, q queryer, query string, args ...any) ([]string, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Backup writes a consistent copy of the live database to target with
// VACUUM INTO, which reads through a transaction while the service keeps
// writing. The file is made first, empty and 0640, so the copy is never
// readable by others, not even while it is written.
func (s *Store) Backup(ctx context.Context, target string) error {
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	file.Close()
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, target); err != nil {
		os.Remove(target)
		return fmt.Errorf("VACUUM INTO %s: %w", target, err)
	}
	return nil
}

package service

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// firstCutSchema is the schema of the first release (68b8c77), which
// databases made before schema versions carry; a9772a5 dropped
// heartbeats.received from it.
const firstCutSchema = `
CREATE TABLE IF NOT EXISTS installs (
	id            TEXT PRIMARY KEY,
	app           TEXT NOT NULL,
	public_key    BLOB NOT NULL,
	trust         TEXT NOT NULL,
	attest_env    TEXT,
	-- The attested key's policy (identity.KeyPolicy as JSON), for attested installs.
	attest_policy TEXT,
	created       TEXT NOT NULL,
	updated       TEXT NOT NULL,
	-- The last day this install sent a heartbeat or registered; retention
	-- forgets installs silent for longer than it keeps heartbeats.
	last_seen     TEXT NOT NULL,
	last_seq      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS installs_app ON installs(app, trust);

-- One row per install per day of use: day is the client's local calendar day.
CREATE TABLE IF NOT EXISTS heartbeats (
	install      TEXT NOT NULL REFERENCES installs(id) ON DELETE CASCADE,
	app          TEXT NOT NULL,
	day          TEXT NOT NULL,
	received     TEXT NOT NULL,
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
	received TEXT NOT NULL,
	context  TEXT NOT NULL,
	-- The files as stored, [{"name","size"}], under <crash dir>/<app>/<id>/.
	files    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS crash_reports_app ON crash_reports(app, received);
CREATE INDEX IF NOT EXISTS crash_reports_install ON crash_reports(install, received);
`

func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func columns(t *testing.T, db *sql.DB, table string) string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		_ = rows.Scan(&name)
		names = append(names, name)
	}
	return strings.Join(names, ",")
}

// TestFirstCutDatabasesMigrate: a database the first release made, with
// rows in every table, opens at the current schema with its data intact.
func TestFirstCutDatabasesMigrate(t *testing.T) {
	for name, dropReceived := range map[string]bool{"68b8c77": false, "a9772a5": true} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "old.db")
			old := openRaw(t, path)
			statements := []string{
				firstCutSchema,
				`INSERT INTO installs VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaa', 'refrax', x'00', 'attested', 'production', '{}',
					'2026-10-04T23:16:46Z', '2026-10-04T23:16:46Z', '2026-10-05', 7)`,
				`INSERT INTO heartbeats VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaa', 'refrax', '2026-10-05', '2026-10-04T23:16:46Z',
					'0.34', '41', '27.0', 'arm64', 'M3', 36, 'fr', 3, '{"tabs":7}')`,
				`INSERT INTO daily_actives VALUES ('refrax', '2025-09-01', 'attested', 4)`,
				`INSERT INTO crash_reports VALUES ('0123456789abcdef0123456789abcdef', 'aaaaaaaaaaaaaaaaaaaaaaaaaa', 'refrax',
					'2026-10-04T23:17:26Z', '{"installLocation":"applications"}',
					'[{"name":"a.ips","size":2299},{"name":"b.log","size":100}]')`,
			}
			if dropReceived {
				statements[2] = strings.Replace(statements[2], "'2026-10-04T23:16:46Z',\n", "", 1)
				statements = append([]string{statements[0], `ALTER TABLE heartbeats DROP COLUMN received`}, statements[1:]...)
			}
			for _, statement := range statements {
				if _, err := old.Exec(statement); err != nil {
					t.Fatalf("%v\n%s", err, statement)
				}
			}
			old.Close()

			store, err := OpenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			var version int
			_ = store.db.QueryRow(`PRAGMA user_version`).Scan(&version)
			if version != schemaVersion {
				t.Fatalf("user_version %d", version)
			}
			if got := columns(t, store.db, "heartbeats"); strings.Contains(got, "received") {
				t.Fatalf("heartbeats columns %s", got)
			}
			if got := columns(t, store.db, "crash_reports"); !strings.HasSuffix(got, ",bytes") {
				t.Fatalf("crash_reports columns %s", got)
			}
			var created, updated, lastSeen, trust string
			var seq int
			_ = store.db.QueryRow(`SELECT created, updated, last_seen, trust, last_seq FROM installs`).Scan(&created, &updated, &lastSeen, &trust, &seq)
			if created != "2026-10-04" || updated != "2026-10-04" || lastSeen != "2026-10-05" || trust != "attested" || seq != 7 {
				t.Fatalf("install %s %s %s %s %d", created, updated, lastSeen, trust, seq)
			}
			var day, properties string
			_ = store.db.QueryRow(`SELECT day, properties FROM heartbeats`).Scan(&day, &properties)
			var received string
			var size int64
			_ = store.db.QueryRow(`SELECT received, bytes FROM crash_reports`).Scan(&received, &size)
			var actives int
			_ = store.db.QueryRow(`SELECT installs FROM daily_actives`).Scan(&actives)
			if day != "2026-10-05" || properties != `{"tabs":7}` || received != "2026-10-04" || size != 2399 || actives != 4 {
				t.Fatalf("rows: %s %s %s %d %d", day, properties, received, size, actives)
			}
			used, err := store.crashBytes(context.Background(), "2026-10-04")
			if err != nil || used != 2399 {
				t.Fatalf("crash bytes %d %v", used, err)
			}
			store.Close()
			// Opening again is a no-op.
			again, err := OpenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			again.Close()
		})
	}
}

func TestFreshDatabasesStartAtTheCurrentVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	_ = store.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	store.Close()
	if version != schemaVersion || schemaVersion < 1 {
		t.Fatalf("user_version %d, schema %d", version, schemaVersion)
	}
}

func TestANewerDatabaseIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newer.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion+1))
	store.Close()
	if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "newer build") {
		t.Fatalf("a newer database opened: %v", err)
	}
}

// TestABrokenDatabaseIsAnErrorNotAPolicy: when the store cannot answer,
// the client hears 500, never a capacity refusal it would wait out.
func TestABrokenDatabaseIsAnErrorNotAPolicy(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	h.postHeartbeats(c, validHeartbeat(h.today()))
	if _, err := h.svc.Store.db.Exec(`ALTER TABLE crash_reports DROP COLUMN bytes`); err != nil {
		t.Fatal(err)
	}
	if got := h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).Code; got != http.StatusInternalServerError {
		t.Fatalf("a crash report against a broken table: %d", got)
	}
	if _, err := h.svc.Store.db.Exec(`ALTER TABLE heartbeats RENAME TO gone`); err != nil {
		t.Fatal(err)
	}
	if got := h.adminGet("/admin/refrax/stats").Code; got != http.StatusInternalServerError {
		t.Fatalf("stats without heartbeats: %d", got)
	}
}

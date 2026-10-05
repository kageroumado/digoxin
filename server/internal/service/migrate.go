package service

import (
	"context"
	"database/sql"
	"fmt"
)

// migrations bring a database from one schema version to the next:
// migrations[v] takes version v to v+1, and len(migrations) is the version
// schema describes. A fresh database is made from schema directly.
// Append to the list; never edit or reorder a migration that has shipped.
var migrations = []func(ctx context.Context, tx *sql.Tx) error{
	migrateFirstCut,
}

// schemaVersion is the version schema describes.
var schemaVersion = len(migrations)

// migrate brings the database to schemaVersion in one transaction, and
// refuses one a newer build has written.
func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > schemaVersion {
		return fmt.Errorf("the database is at schema version %d and this build knows %d; run a newer build", version, schemaVersion)
	}
	fresh := false
	if version == 0 {
		var tables int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'installs'`).Scan(&tables); err != nil {
			return err
		}
		fresh = tables == 0
	}
	if !fresh {
		for v := version; v < schemaVersion; v++ {
			if err := migrations[v](ctx, tx); err != nil {
				return fmt.Errorf("migrating to schema version %d: %w", v+1, err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	// PRAGMA takes no parameters; the value is this build's own constant.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// migrateFirstCut brings a database made before schema versions existed
// (user_version 0, from the first releases) to version 1:
//   - heartbeats loses received, the time each one arrived;
//   - installs.created and installs.updated become days;
//   - crash_reports.received becomes a day, and crash_reports gains bytes,
//     filled from the sizes in its files list.
//
// Each step checks the shape first, so a database made by any of those
// releases migrates.
func migrateFirstCut(ctx context.Context, tx *sql.Tx) error {
	dropped, err := hasColumn(ctx, tx, "heartbeats", "received")
	if err != nil {
		return err
	}
	if dropped {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE heartbeats DROP COLUMN received`); err != nil {
			return err
		}
	}
	hasBytes, err := hasColumn(ctx, tx, "crash_reports", "bytes")
	if err != nil {
		return err
	}
	if !hasBytes {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE crash_reports ADD COLUMN bytes INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE crash_reports SET bytes = (
				SELECT COALESCE(SUM(json_extract(value, '$.size')), 0) FROM json_each(crash_reports.files))`); err != nil {
			return err
		}
	}
	for _, statement := range []string{
		`UPDATE installs SET created = substr(created, 1, 10), updated = substr(updated, 1, 10)
			WHERE length(created) > 10 OR length(updated) > 10`,
		`UPDATE crash_reports SET received = substr(received, 1, 10) WHERE length(received) > 10`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func hasColumn(ctx context.Context, tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

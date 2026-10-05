package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	// HeartbeatRetention is how long raw heartbeats stay; older days are
	// kept only as counts in daily_actives.
	HeartbeatRetention = 400 * 24 * time.Hour
	// CrashRetention is how long crash reports and their files stay.
	CrashRetention = 180 * 24 * time.Hour
)

// retentionPass rolls heartbeats past HeartbeatRetention into daily
// counts and drops them, forgets installs silent for as long, and removes
// crash reports past CrashRetention with their files.
func (s *Service) retentionPass(ctx context.Context) error {
	now := s.Now().UTC()
	heartbeatCutoff := now.Add(-HeartbeatRetention).Format(dayLayout)
	crashCutoff := now.Add(-CrashRetention).Format(dayLayout)

	st := s.Store
	st.write.Lock()
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		st.write.Unlock()
		return err
	}
	defer tx.Rollback()
	steps := []struct {
		query string
		args  []any
	}{
		{`INSERT OR IGNORE INTO daily_actives (app, day, trust, installs)
			SELECT h.app, h.day, i.trust, COUNT(*) FROM heartbeats h JOIN installs i ON i.id = h.install
			WHERE h.day < ? GROUP BY h.app, h.day, i.trust`, []any{heartbeatCutoff}},
		{`DELETE FROM heartbeats WHERE day < ?`, []any{heartbeatCutoff}},
	}
	for _, step := range steps {
		if _, err := tx.ExecContext(ctx, step.query, step.args...); err != nil {
			st.write.Unlock()
			return err
		}
	}
	type expired struct{ app, id string }
	var gone []expired
	rows, err := tx.QueryContext(ctx, `
		SELECT app, id FROM crash_reports WHERE received < ?
		UNION ALL
		SELECT c.app, c.id FROM crash_reports c JOIN installs i ON i.id = c.install WHERE i.last_seen < ?`,
		crashCutoff, heartbeatCutoff)
	if err != nil {
		st.write.Unlock()
		return err
	}
	for rows.Next() {
		var e expired
		if err := rows.Scan(&e.app, &e.id); err != nil {
			rows.Close()
			st.write.Unlock()
			return err
		}
		gone = append(gone, e)
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, `DELETE FROM crash_reports WHERE received < ?`, crashCutoff); err != nil {
		st.write.Unlock()
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM installs WHERE last_seen < ?`, heartbeatCutoff)
	if err != nil {
		st.write.Unlock()
		return err
	}
	if err := tx.Commit(); err != nil {
		st.write.Unlock()
		return err
	}
	st.write.Unlock()
	for _, e := range gone {
		s.removeCrashFiles(e.app, []string{e.id})
	}
	if forgotten, _ := result.RowsAffected(); forgotten > 0 || len(gone) > 0 {
		log.Printf("digoxin: retention forgot %d silent installs and %d crash reports", forgotten, len(gone))
	}
	return s.removeOrphans(ctx, now)
}

// orphanAge is how old a crash folder without a row must be before
// retention removes it: an upload in flight has a folder and no row yet.
const orphanAge = time.Hour

// removeOrphans removes crash folders no report names (left by a crash
// between the database and the disk) and abandoned uploads.
func (s *Service) removeOrphans(ctx context.Context, now time.Time) error {
	apps, err := os.ReadDir(s.CrashDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, app := range apps {
		if !app.IsDir() {
			continue
		}
		folder := filepath.Join(s.CrashDir, app.Name())
		entries, err := os.ReadDir(folder)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil || now.Sub(info.ModTime()) < orphanAge {
				continue
			}
			if app.Name() != incomingDir {
				var known int
				if err := s.Store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM crash_reports WHERE id = ? AND app = ?`,
					entry.Name(), app.Name()).Scan(&known); err != nil {
					return fmt.Errorf("looking up crash folder %s: %w", entry.Name(), err)
				}
				if known > 0 {
					continue
				}
			}
			if err := os.RemoveAll(filepath.Join(folder, entry.Name())); err != nil {
				log.Printf("digoxin: retention: removing %s: %v", entry.Name(), err)
			}
		}
	}
	return nil
}

package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
)

// Events are the counters of a web page. The page sends
//
//	POST /v1/{app}/events  {"name": "complete", "label": "raads-r"}
//
// and the service adds one to (app, UTC day of arrival, name, label). The
// name must be in the app's events allowlist; the label is a slug, usually
// a test's id, or empty. The row holds the count and nothing else: no
// address, no identifier, no time of day. The per-address write limit of
// withApp applies, and a day takes at most maxLabelsPerDay distinct labels
// per event, so junk labels cannot grow the table.

const (
	maxEventBytes   = 1 << 10
	maxLabelsPerDay = 64
	eventsDays      = 30
	maxEventsDays   = 400
)

var errTooManyLabels = errors.New("too many labels for one day")

type event struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

// EventCount is one counter row.
type EventCount struct {
	Day   string `json:"day"`
	Name  string `json:"name"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// withEventsApp resolves {app} to an app with an events allowlist and applies
// the per-address write limit.
func (s *Service) withEventsApp(handler func(http.ResponseWriter, *http.Request, *App)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app := s.Apps[r.PathValue("app")]
		if app == nil || len(app.Config.Events) == 0 {
			writeError(w, http.StatusNotFound, "unknown app")
			return
		}
		if !s.Writes.Admit(s.Clients.Key(r), s.Now()) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		handler(w, r, app)
	}
}

func (s *Service) handleEvent(w http.ResponseWriter, r *http.Request, app *App) {
	body, ok := readBody(w, r, maxEventBytes)
	if !ok {
		return
	}
	var e event
	if err := json.Unmarshal(body, &e); err != nil {
		writeError(w, http.StatusBadRequest, "not an event")
		return
	}
	if !slices.Contains(app.Config.Events, e.Name) {
		writeError(w, http.StatusBadRequest, "unknown event")
		return
	}
	if e.Label != "" && !reSlug.MatchString(e.Label) {
		writeError(w, http.StatusBadRequest, "label is a slug of at most 32 characters")
		return
	}
	day := s.Now().UTC().Format(dayLayout)
	err := s.Store.countEvent(r.Context(), app.Config.Slug, day, e.Name, e.Label)
	if errors.Is(err, errTooManyLabels) {
		writeError(w, http.StatusBadRequest, "too many labels today")
		return
	}
	if err != nil {
		internal(w, "counting an event", err)
		return
	}
	noContent(w)
}

// countEvent adds one to the counter, opening the row for a label the day
// has not seen while fewer than maxLabelsPerDay exist for the event.
func (s *Store) countEvent(ctx context.Context, app, day, name, label string) error {
	s.write.Lock()
	defer s.write.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var known int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM events WHERE app = ? AND day = ? AND name = ? AND label = ?`,
		app, day, name, label).Scan(&known); err != nil {
		return err
	}
	if known == 0 {
		var labels int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM events WHERE app = ? AND day = ? AND name = ?`,
			app, day, name).Scan(&labels); err != nil {
			return err
		}
		if labels >= maxLabelsPerDay {
			return errTooManyLabels
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO events (app, day, name, label, count) VALUES (?, ?, ?, ?, 1)
		ON CONFLICT(app, day, name, label) DO UPDATE SET count = count + 1`,
		app, day, name, label); err != nil {
		return err
	}
	return tx.Commit()
}

// events lists the counters of app from day from to day to, inclusive.
func (s *Store) events(ctx context.Context, app, from, to string) ([]EventCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT day, name, label, count FROM events
		WHERE app = ? AND day BETWEEN ? AND ?
		ORDER BY day, name, label`, app, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventCount{}
	for rows.Next() {
		var e EventCount
		if err := rows.Scan(&e.Day, &e.Name, &e.Label, &e.Count); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// adminEvents answers GET /admin/{app}/events?days=30: the counters of the
// last days, today included.
func (s *Service) adminEvents(w http.ResponseWriter, r *http.Request, app string) {
	days := eventsDays
	if q := r.URL.Query().Get("days"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > maxEventsDays {
			writeError(w, http.StatusBadRequest, "days is 1 to 400")
			return
		}
		days = n
	}
	today := s.Now().UTC()
	from := today.AddDate(0, 0, -(days - 1)).Format(dayLayout)
	to := today.Format(dayLayout)
	events, err := s.Store.events(r.Context(), app, from, to)
	if err != nil {
		internal(w, "listing events", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": app, "from": from, "to": to, "events": events})
}

package service

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// activeCacheTTL is how long one app's answer to GET /v1/{app}/active is
// served from memory, and the max-age its answer carries.
const activeCacheTTL = 10 * time.Minute

// activeCount is the public figure an app shows beside its consent toggle:
// how many installs counted themselves in on the latest complete day.
type activeCount struct {
	App    string `json:"app"`
	Day    string `json:"day"`
	Active int    `json:"active"`
}

// activeCache holds each app's activeCount for activeCacheTTL, so the
// endpoint costs one query per app per ten minutes however often it is asked.
type activeCache struct {
	mu      sync.Mutex
	entries map[string]activeEntry
}

type activeEntry struct {
	answer  activeCount
	expires time.Time
}

// handleActive answers the public, unauthenticated count of installs with
// a heartbeat yesterday, at the counted trusts. Yesterday in the server's
// clock is the newest day that is complete everywhere: heartbeat days are
// the install's local date, which runs up to leadingZone ahead of UTC.
func (s *Service) handleActive(w http.ResponseWriter, r *http.Request, app *App) {
	now := s.Now().UTC()
	day := now.AddDate(0, 0, -1).Format(dayLayout)
	slug := app.Config.Slug

	s.actives.mu.Lock()
	entry, hit := s.actives.entries[slug]
	s.actives.mu.Unlock()
	if !hit || entry.answer.Day != day || !now.Before(entry.expires) {
		active, err := s.Store.activeOn(r, slug, day, countedTrusts)
		if err != nil {
			internal(w, "counting actives", err)
			return
		}
		entry = activeEntry{answer: activeCount{App: slug, Day: day, Active: active}, expires: now.Add(activeCacheTTL)}
		s.actives.mu.Lock()
		if s.actives.entries == nil {
			s.actives.entries = map[string]activeEntry{}
		}
		s.actives.entries[slug] = entry
		s.actives.mu.Unlock()
	}

	securityHeaders(w)
	// The figure is public and changes once a day, so caches may keep it;
	// every other answer of the API is private and carries no-store.
	w.Header().Set("Cache-Control", "public, max-age=600")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(entry.answer)
}

// activeOn counts the distinct installs of app with a heartbeat on day
// whose trust is one of trusts: the dau figure of /admin/{app}/stats,
// summed over those trusts.
func (s *Store) activeOn(r *http.Request, app, day string, trusts []string) (int, error) {
	placeholders, args := inList(trusts)
	args = append([]any{app, day}, args...)
	var n int
	err := s.db.QueryRowContext(r.Context(), `
		SELECT COUNT(DISTINCT h.install)
		FROM heartbeats h JOIN installs i ON i.id = h.install
		WHERE h.app = ? AND h.day = ? AND i.trust IN (`+placeholders+`)`, args...).Scan(&n)
	return n, err
}

// inList is the placeholders and arguments of an SQL IN over values.
func inList(values []string) (string, []any) {
	args := make([]any, 0, len(values))
	for _, v := range values {
		args = append(args, v)
	}
	return strings.TrimSuffix(strings.Repeat("?,", len(values)), ","), args
}

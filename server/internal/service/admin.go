package service

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kageroumado/digoxin/server/identity"
)

// The admin API answers JSON on a loopback listener with no
// authentication; `kagerou <app> …` reaches it over ssh.
//
//	GET /admin/apps
//	GET /admin/{app}/stats?day=YYYY-MM-DD&trust=attested,device (day defaults to the newest day heartbeats carry)
//	GET /admin/{app}/history?days=90
//	GET /admin/{app}/installs/{id}
//	GET /admin/{app}/crashes?limit=50
//	GET /admin/{app}/crashes/{id}
//	GET /admin/{app}/crashes/{id}/files/{name}

const (
	weekDays  = 7
	monthDays = 30
)

// AdminRoutes is the loopback admin API. It answers only requests named
// for the loopback host and sent by no web page, so a page whose name
// rebinds to 127.0.0.1 cannot read it through a browser.
func (s *Service) AdminRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/apps", s.adminApps)
	mux.HandleFunc("GET /admin/{app}/stats", s.adminApp(s.adminStats))
	mux.HandleFunc("GET /admin/{app}/history", s.adminApp(s.adminHistory))
	mux.HandleFunc("GET /admin/{app}/installs/{id}", s.adminApp(s.adminInstall))
	mux.HandleFunc("GET /admin/{app}/crashes", s.adminApp(s.adminCrashes))
	mux.HandleFunc("GET /admin/{app}/crashes/{id}", s.adminApp(s.adminCrash))
	mux.HandleFunc("GET /admin/{app}/crashes/{id}/files/{name}", s.adminApp(s.adminCrashFile))
	return loopbackHost(mux)
}

func loopbackHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) || r.Header.Get("Origin") != "" {
			writeError(w, http.StatusForbidden, "the admin API answers loopback requests only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LoopbackOnly refuses an admin address that another machine could reach:
// the admin listener has no authentication.
func LoopbackOnly(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("admin address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("admin address %q is not loopback; the admin listener has no authentication", addr)
}

func (s *Service) adminApp(handler func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("app")
		if s.Apps[slug] == nil {
			writeError(w, http.StatusNotFound, "unknown app")
			return
		}
		handler(w, r, slug)
	}
}

type appSummary struct {
	App          string         `json:"app"`
	Installs     map[string]int `json:"installs"`
	Heartbeats   int            `json:"heartbeats"`
	CrashReports int            `json:"crash_reports"`
}

func (s *Service) adminApps(w http.ResponseWriter, r *http.Request) {
	out := []appSummary{}
	for slug := range s.Apps {
		summary := appSummary{App: slug, Installs: map[string]int{}}
		rows, err := s.Store.db.QueryContext(r.Context(), `SELECT trust, COUNT(*) FROM installs WHERE app = ? GROUP BY trust`, slug)
		if err != nil {
			internal(w, "counting installs", err)
			return
		}
		for rows.Next() {
			var trust string
			var n int
			if err := rows.Scan(&trust, &n); err != nil {
				rows.Close()
				internal(w, "counting installs", err)
				return
			}
			summary.Installs[trust] = n
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			internal(w, "counting installs", err)
			return
		}
		if err := s.Store.db.QueryRowContext(r.Context(),
			`SELECT (SELECT COUNT(*) FROM heartbeats WHERE app = ?), (SELECT COUNT(*) FROM crash_reports WHERE app = ?)`,
			slug, slug).Scan(&summary.Heartbeats, &summary.CrashReports); err != nil {
			internal(w, "counting", err)
			return
		}
		out = append(out, summary)
	}
	slices.SortFunc(out, func(a, b appSummary) int { return strings.Compare(a.App, b.App) })
	writeJSON(w, http.StatusOK, out)
}

// Stats is one app's figures as of a day.
type Stats struct {
	App string `json:"app"`
	Day string `json:"day"`
	// Actives counts distinct installs with a heartbeat on the day (dau),
	// in the 7 days ending on it (wau) and the 30 (mau), per trust tier.
	Actives map[string]map[string]int `json:"actives"`
	// Sample is how many installs the spreads below describe: those with a
	// heartbeat in the 30 days, of the trust tiers asked for, each by its
	// latest heartbeat.
	Sample      int                                 `json:"sample"`
	Trusts      []string                            `json:"trusts"`
	Versions    map[string]int                      `json:"versions"`
	OS          map[string]int                      `json:"os"`
	Arch        map[string]int                      `json:"arch"`
	ChipFamily  map[string]int                      `json:"chip_family"`
	MemoryGB    map[string]int                      `json:"memory_gb"`
	Language    map[string]int                      `json:"language"`
	ActiveDays7 map[string]int                      `json:"active_days7"`
	Properties  map[string]map[string]PropertyShare `json:"properties"`
}

// PropertyShare is how many installs in the sample reported a value, and
// what fraction of the sample that is.
type PropertyShare struct {
	Installs int     `json:"installs"`
	Share    float64 `json:"share"`
}

var countedTrusts = []string{identity.TrustAttested, identity.TrustVerified, identity.TrustDevice, identity.TrustUnverified}

func (s *Service) adminStats(w http.ResponseWriter, r *http.Request, app string) {
	day := r.URL.Query().Get("day")
	if day == "" {
		newest, err := s.Store.newestDay(r, app, s.Now())
		if err != nil {
			internal(w, "finding the newest day", err)
			return
		}
		day = newest
	}
	asOf, err := time.Parse(dayLayout, day)
	if err != nil {
		writeError(w, http.StatusBadRequest, "day is YYYY-MM-DD")
		return
	}
	trusts := countedTrusts
	if list := r.URL.Query().Get("trust"); list != "" {
		trusts = strings.Split(list, ",")
	}
	stats, err := s.Store.stats(r, app, asOf, trusts)
	if err != nil {
		internal(w, "stats", err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Store) stats(r *http.Request, app string, asOf time.Time, trusts []string) (*Stats, error) {
	ctx := r.Context()
	day := asOf.Format(dayLayout)
	weekStart := asOf.AddDate(0, 0, -(weekDays - 1)).Format(dayLayout)
	monthStart := asOf.AddDate(0, 0, -(monthDays - 1)).Format(dayLayout)
	out := &Stats{
		App: app, Day: day, Trusts: trusts,
		Actives:  map[string]map[string]int{"dau": {}, "wau": {}, "mau": {}},
		Versions: map[string]int{}, OS: map[string]int{}, Arch: map[string]int{}, ChipFamily: map[string]int{},
		MemoryGB: map[string]int{}, Language: map[string]int{}, ActiveDays7: map[string]int{},
		Properties: map[string]map[string]PropertyShare{},
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT i.trust,
			COUNT(DISTINCT CASE WHEN h.day = ? THEN h.install END),
			COUNT(DISTINCT CASE WHEN h.day >= ? THEN h.install END),
			COUNT(DISTINCT h.install)
		FROM heartbeats h JOIN installs i ON i.id = h.install
		WHERE h.app = ? AND h.day BETWEEN ? AND ?
		GROUP BY i.trust`, day, weekStart, app, monthStart, day)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var trust string
		var dau, wau, mau int
		if err := rows.Scan(&trust, &dau, &wau, &mau); err != nil {
			rows.Close()
			return nil, err
		}
		out.Actives["dau"][trust], out.Actives["wau"][trust], out.Actives["mau"][trust] = dau, wau, mau
	}
	rows.Close()

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(trusts)), ",")
	args := []any{app, monthStart, day}
	for _, t := range trusts {
		args = append(args, t)
	}
	rows, err = s.db.QueryContext(ctx, `
		WITH latest AS (
			SELECT h.*, ROW_NUMBER() OVER (PARTITION BY h.install ORDER BY h.day DESC) AS rank
			FROM heartbeats h JOIN installs i ON i.id = h.install
			WHERE h.app = ? AND h.day BETWEEN ? AND ? AND i.trust IN (`+placeholders+`)
		)
		SELECT day, app_version, os, arch, chip_family, memory_gb, language, active_days7, properties
		FROM latest WHERE rank = 1`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	propertyCounts := map[string]map[string]int{}
	for rows.Next() {
		var h heartbeat
		var properties string
		if err := rows.Scan(&h.Day, &h.AppVersion, &h.OS, &h.Arch, &h.ChipFamily, &h.MemoryClassGB, &h.Language, &h.ActiveDays7, &properties); err != nil {
			return nil, err
		}
		out.Sample++
		out.Versions[h.AppVersion]++
		out.OS[h.OS]++
		out.Arch[h.Arch]++
		out.ChipFamily[h.ChipFamily]++
		out.MemoryGB[strconv.FormatInt(h.MemoryClassGB, 10)]++
		out.Language[h.Language]++
		if h.Day >= weekStart {
			out.ActiveDays7[strconv.FormatInt(h.ActiveDays7, 10)]++
		}
		var values map[string]any
		_ = json.Unmarshal([]byte(properties), &values)
		for key, value := range values {
			if propertyCounts[key] == nil {
				propertyCounts[key] = map[string]int{}
			}
			propertyCounts[key][fmt.Sprint(value)]++
		}
	}
	for key, counts := range propertyCounts {
		shares := map[string]PropertyShare{}
		for value, n := range counts {
			shares[value] = PropertyShare{Installs: n, Share: float64(n) / float64(out.Sample)}
		}
		out.Properties[key] = shares
	}
	return out, rows.Err()
}

// leadingZone is the furthest-ahead UTC offset (Kiritimati, UTC+14): no
// client's local day is later than the UTC date of now plus this.
const leadingZone = 14 * time.Hour

// newestDay is the latest local day any heartbeat of app carries, which is
// today somewhere on Earth: heartbeats count the client's own calendar day,
// so the UTC date lags it for every client east of Greenwich.
func (s *Store) newestDay(r *http.Request, app string, now time.Time) (string, error) {
	limit := now.UTC().Add(leadingZone).Format(dayLayout)
	var day sql.NullString
	if err := s.db.QueryRowContext(r.Context(), `SELECT MAX(day) FROM heartbeats WHERE app = ? AND day <= ?`, app, limit).Scan(&day); err != nil {
		return "", err
	}
	if day.Valid {
		return day.String, nil
	}
	return now.UTC().Format(dayLayout), nil
}

type historyRow struct {
	Day      string `json:"day"`
	Trust    string `json:"trust"`
	Installs int    `json:"installs"`
}

// adminHistory is daily actives per trust tier, from the raw heartbeats
// and, past their retention, the rolled-up counts.
func (s *Service) adminHistory(w http.ResponseWriter, r *http.Request, app string) {
	days, err := strconv.Atoi(r.URL.Query().Get("days"))
	if err != nil || days <= 0 {
		days = 90
	}
	since := s.Now().UTC().AddDate(0, 0, -days).Format(dayLayout)
	rows, err := s.Store.db.QueryContext(r.Context(), `
		SELECT day, trust, installs FROM daily_actives WHERE app = ? AND day >= ?
		UNION ALL
		SELECT h.day, i.trust, COUNT(*) FROM heartbeats h JOIN installs i ON i.id = h.install
		WHERE h.app = ? AND h.day >= ? GROUP BY h.day, i.trust
		ORDER BY 1, 2`, app, since, app, since)
	if err != nil {
		internal(w, "history", err)
		return
	}
	defer rows.Close()
	out := []historyRow{}
	for rows.Next() {
		var row historyRow
		if err := rows.Scan(&row.Day, &row.Trust, &row.Installs); err != nil {
			internal(w, "history", err)
			return
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, out)
}

type installDetail struct {
	ID         string          `json:"id"`
	Trust      string          `json:"trust"`
	AttestEnv  string          `json:"attest_env,omitempty"`
	Policy     json.RawMessage `json:"attest_policy,omitempty"`
	Created    string          `json:"created"`
	LastSeen   string          `json:"last_seen"`
	Heartbeats int             `json:"heartbeats"`
	Crashes    int             `json:"crash_reports"`
}

func (s *Service) adminInstall(w http.ResponseWriter, r *http.Request, app string) {
	var d installDetail
	var env, policy sql.NullString
	err := s.Store.db.QueryRowContext(r.Context(), `
		SELECT id, trust, attest_env, attest_policy, created, last_seen,
			(SELECT COUNT(*) FROM heartbeats WHERE install = installs.id),
			(SELECT COUNT(*) FROM crash_reports WHERE install = installs.id)
		FROM installs WHERE id = ? AND app = ?`, r.PathValue("id"), app,
	).Scan(&d.ID, &d.Trust, &env, &policy, &d.Created, &d.LastSeen, &d.Heartbeats, &d.Crashes)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "no such install")
		return
	}
	if err != nil {
		internal(w, "install", err)
		return
	}
	d.AttestEnv = env.String
	if policy.Valid {
		d.Policy = json.RawMessage(policy.String)
	}
	writeJSON(w, http.StatusOK, d)
}

// CrashReport is a stored crash report as the admin API lists it.
type CrashReport struct {
	ID       string          `json:"id"`
	Install  string          `json:"install"`
	Received string          `json:"received"`
	Context  json.RawMessage `json:"context"`
	Files    json.RawMessage `json:"files"`
}

func (s *Service) adminCrashes(w http.ResponseWriter, r *http.Request, app string) {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.Store.db.QueryContext(r.Context(),
		`SELECT id, install, received, context, files FROM crash_reports WHERE app = ? ORDER BY received DESC, rowid DESC LIMIT ?`, app, limit)
	if err != nil {
		internal(w, "crashes", err)
		return
	}
	defer rows.Close()
	out := []CrashReport{}
	for rows.Next() {
		var c CrashReport
		var context, files string
		if err := rows.Scan(&c.ID, &c.Install, &c.Received, &context, &files); err != nil {
			internal(w, "crashes", err)
			return
		}
		c.Context, c.Files = json.RawMessage(context), json.RawMessage(files)
		out = append(out, c)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) crashReport(r *http.Request, app string) (*CrashReport, error) {
	var c CrashReport
	var context, files string
	err := s.Store.db.QueryRowContext(r.Context(),
		`SELECT id, install, received, context, files FROM crash_reports WHERE id = ? AND app = ?`, r.PathValue("id"), app,
	).Scan(&c.ID, &c.Install, &c.Received, &context, &files)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	c.Context, c.Files = json.RawMessage(context), json.RawMessage(files)
	return &c, err
}

func (s *Service) adminCrash(w http.ResponseWriter, r *http.Request, app string) {
	c, err := s.crashReport(r, app)
	switch {
	case err != nil:
		internal(w, "crash", err)
	case c == nil:
		writeError(w, http.StatusNotFound, "no such crash report")
	default:
		writeJSON(w, http.StatusOK, c)
	}
}

func (s *Service) adminCrashFile(w http.ResponseWriter, r *http.Request, app string) {
	c, err := s.crashReport(r, app)
	if err != nil {
		internal(w, "crash", err)
		return
	}
	name := r.PathValue("name")
	listed := false
	if c != nil {
		var files []crashFile
		_ = json.Unmarshal(c.Files, &files)
		for _, f := range files {
			listed = listed || f.Name == name
		}
	}
	if !listed || !reReportID.MatchString(c.ID) || !reFileName.MatchString(name) {
		writeError(w, http.StatusNotFound, "no such file")
		return
	}
	data, err := os.ReadFile(filepath.Join(s.CrashDir, app, c.ID, name))
	if err != nil {
		internal(w, "reading crash file", err)
		return
	}
	securityHeaders(w)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	_, _ = w.Write(data)
}

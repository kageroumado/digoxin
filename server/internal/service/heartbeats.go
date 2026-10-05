package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	dayLayout = "2006-01-02"
	// maxHeartbeatsPerBatch covers a week offline plus today.
	maxHeartbeatsPerBatch = 8
	// heartbeatMaxAgeDays is how old a queued heartbeat's day may be; the
	// client drops items it has held for a week.
	heartbeatMaxAgeDays = 8
	maxStringValue      = 64
)

var (
	reAppBuild    = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,32}$`)
	reOS          = regexp.MustCompile(`^[0-9]{2}\.[0-9]{1,2}$`)
	reChipFamily  = regexp.MustCompile(`^(M[1-9][0-9]?|Intel|unknown)$`)
	reLanguage    = regexp.MustCompile(`^[a-z]{2}$`)
	arches        = map[string]bool{"arm64": true, "x86_64": true}
	memoryClasses = map[int64]bool{8: true, 16: true, 24: true, 32: true, 36: true, 48: true, 64: true, 96: true, 128: true}
)

// BasicInfo is what every heartbeat and crash report says about the app
// and the Mac, each field bounded.
type BasicInfo struct {
	AppVersion    string `json:"appVersion"`
	AppBuild      string `json:"appBuild"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	ChipFamily    string `json:"chipFamily"`
	MemoryClassGB int64  `json:"memoryClassGB"`
	Language      string `json:"language"`
}

// validate answers what is wrong with the info, empty when nothing is.
func (b *BasicInfo) validate() string {
	switch {
	case !reAppVersion.MatchString(b.AppVersion):
		return "appVersion"
	case !reAppBuild.MatchString(b.AppBuild):
		return "appBuild"
	case !reOS.MatchString(b.OS):
		return "os"
	case !arches[b.Arch]:
		return "arch"
	case !reChipFamily.MatchString(b.ChipFamily):
		return "chipFamily"
	case !memoryClasses[b.MemoryClassGB]:
		return "memoryClassGB"
	case !reLanguage.MatchString(b.Language):
		return "language"
	}
	return ""
}

type heartbeat struct {
	BasicInfo
	Day         string                     `json:"day"`
	ActiveDays7 int64                      `json:"activeDays7"`
	Properties  map[string]json.RawMessage `json:"properties"`
}

type rejection struct {
	I   int    `json:"i"`
	Why string `json:"why"`
}

// validate checks a heartbeat against now and answers its kept properties.
func (h *heartbeat) validate(now time.Time, allowlist map[string]string) (map[string]any, string) {
	if why := h.BasicInfo.validate(); why != "" {
		return nil, why
	}
	day, err := time.Parse(dayLayout, h.Day)
	latest, _ := time.Parse(dayLayout, now.UTC().Add(leadingZone).Format(dayLayout))
	if err != nil || day.After(latest) || day.Before(latest.AddDate(0, 0, -heartbeatMaxAgeDays-1)) {
		return nil, "day"
	}
	if h.ActiveDays7 < 1 || h.ActiveDays7 > 7 {
		return nil, "activeDays7"
	}
	return filterValues(h.Properties, allowlist), ""
}

// filterValues keeps the allowlisted keys whose value has the listed type.
func filterValues(values map[string]json.RawMessage, allowlist map[string]string) map[string]any {
	kept := map[string]any{}
	for key, raw := range values {
		kind, listed := allowlist[key]
		if !listed {
			continue
		}
		if value, ok := typedValue(raw, kind); ok {
			kept[key] = value
		}
	}
	return kept
}

func typedValue(raw json.RawMessage, kind string) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, false
	}
	switch kind {
	case "bool":
		b, ok := value.(bool)
		return b, ok
	case "int":
		n, ok := value.(json.Number)
		if !ok {
			return nil, false
		}
		i, err := n.Int64()
		return i, err == nil && i > -1e12 && i < 1e12
	case "number":
		n, ok := value.(json.Number)
		if !ok {
			return nil, false
		}
		f, err := n.Float64()
		return f, err == nil && !math.IsInf(f, 0) && !math.IsNaN(f)
	case "string":
		s, ok := value.(string)
		return s, ok && cleanString(s)
	}
	return nil, false
}

// cleanString is a short string with nothing invisible in it: these reach
// the operator's terminal.
func cleanString(s string) bool {
	if len([]rune(s)) > maxStringValue {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func (s *Service) handleHeartbeats(w http.ResponseWriter, r *http.Request, app *App) {
	env, install, ok := s.authenticate(w, r, app, sentTolerance)
	if !ok {
		return
	}
	if len(env.Heartbeats) == 0 || len(env.Heartbeats) > maxHeartbeatsPerBatch {
		writeError(w, http.StatusBadRequest, "send 1 to 8 heartbeats")
		return
	}
	now := s.Now()
	rejected := []rejection{}
	var kept []storedHeartbeat
	for i, raw := range env.Heartbeats {
		var h heartbeat
		if err := json.Unmarshal(raw, &h); err != nil {
			rejected = append(rejected, rejection{I: i, Why: "not a heartbeat"})
			continue
		}
		properties, why := h.validate(now, app.Config.Properties)
		if why != "" {
			rejected = append(rejected, rejection{I: i, Why: why})
			continue
		}
		encoded, _ := json.Marshal(properties)
		kept = append(kept, storedHeartbeat{heartbeat: h, properties: string(encoded)})
	}
	accepted, err := s.Store.saveHeartbeats(r.Context(), app.Config.Slug, install.ID, env.Seq, kept)
	if errors.Is(err, errReplay) {
		writeError(w, http.StatusConflict, "seq already used")
		return
	}
	if err != nil {
		internal(w, "storing heartbeats", err)
		return
	}
	if len(rejected) > 0 {
		log.Printf("digoxin: %s: an install sent %d heartbeats, rejected %v", app.Config.Slug, len(env.Heartbeats), rejected)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": accepted, "rejected": rejected})
}

type storedHeartbeat struct {
	heartbeat
	properties string
}

// saveHeartbeats stores the batch under seq; a day already counted keeps
// its first heartbeat. It answers how many days were new.
func (s *Store) saveHeartbeats(ctx context.Context, app, install string, seq int64, items []storedHeartbeat) (int, error) {
	s.write.Lock()
	defer s.write.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := advance(ctx, tx, install, seq); err != nil {
		return 0, err
	}
	stored := 0
	latest := ""
	for _, h := range items {
		result, err := tx.ExecContext(ctx, `
			INSERT INTO heartbeats (install, app, day, app_version, app_build, os, arch,
				chip_family, memory_gb, language, active_days7, properties)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(install, day) DO NOTHING`,
			install, app, h.Day, h.AppVersion, h.AppBuild, h.OS, h.Arch,
			h.ChipFamily, h.MemoryClassGB, h.Language, h.ActiveDays7, h.properties)
		if err != nil {
			return 0, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		stored += int(n)
		if strings.Compare(h.Day, latest) > 0 {
			latest = h.Day
		}
	}
	if latest != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE installs SET last_seen = MAX(last_seen, ?) WHERE id = ?`, latest, install); err != nil {
			return 0, err
		}
	}
	return stored, tx.Commit()
}

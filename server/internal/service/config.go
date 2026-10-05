package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"

	"github.com/kageroumado/digoxin/server/identity"
)

// Config is the apps file: every app the service counts, by slug.
//
//	{"apps": {"refrax": {"app_attest_id": "TEAMID.bundle.id", "team_id": "TEAMID",
//	  "device_check": {"key_path": "/etc/digoxin/AuthKey_X.p8", "key_id": "X", "registered_bit": "bit1"},
//	  "properties": {"chromiumInstalled": "bool"},
//	  "crash_context": {"engines": "string"},
//	  "crash_reports": {"max_files": 4, "max_bytes": 2097152, "per_install_per_day": 5}}}}
type Config struct {
	// ClientIPHeader names the header a trusted proxy writes the client's
	// address into (CF-Connecting-IP, X-Forwarded-For). Empty: the peer
	// address is the client's.
	ClientIPHeader string `json:"client_ip_header"`
	// TrustedProxies are the CIDRs whose ClientIPHeader is believed.
	TrustedProxies []string              `json:"trusted_proxies"`
	CrashStorage   CrashStorage          `json:"crash_storage"`
	Apps           map[string]*AppConfig `json:"apps"`
}

// CrashStorage bounds what crash reports of every app may take of the disk.
type CrashStorage struct {
	// DailyBytes is how many bytes of crash files all apps together may
	// store per UTC day.
	DailyBytes int64 `json:"daily_bytes"`
	// MinFreeBytes is the free space below which no report is taken.
	MinFreeBytes int64 `json:"min_free_bytes"`
	// ConcurrentUploads is how many reports may arrive at once.
	ConcurrentUploads int `json:"concurrent_uploads"`
}

// AppConfig is one app's identity with Apple and what it may send.
type AppConfig struct {
	Slug string `json:"-"`
	// AppAttestID is "<team id>.<bundle id>", the App ID attestations name.
	AppAttestID string `json:"app_attest_id"`
	TeamID      string `json:"team_id"`
	// RequireProductionAttest turns development-environment attestations
	// away, so debug builds register as unverified.
	RequireProductionAttest bool               `json:"require_production_attest"`
	DeviceCheck             *DeviceCheckConfig `json:"device_check"`
	// Properties is the heartbeat's allowlist: key → type ("bool", "int",
	// "number" or "string"). A key not listed, or of another type, is dropped.
	Properties map[string]string `json:"properties"`
	// CrashContext is the same allowlist for a crash report's app-provided
	// context fields.
	CrashContext map[string]string `json:"crash_context"`
	CrashReports CrashLimits       `json:"crash_reports"`
}

// DeviceCheckConfig names the team's DeviceCheck key by path; the key
// itself never enters the config or the repository.
type DeviceCheckConfig struct {
	KeyPath string `json:"key_path"`
	KeyID   string `json:"key_id"`
	// RegisteredBit is the device bit ("bit0" or "bit1") that marks this
	// app's registrations, so a reinstall reads as reregistered. The two
	// bits are shared by every app of the team, so at most two apps can have
	// one; sevostats uses bit0 for Sevoflurane. Empty: the token proves the
	// device and reinstalls are not told apart.
	RegisteredBit string `json:"registered_bit"`
	// Sandbox asks Apple's development DeviceCheck endpoint.
	Sandbox bool `json:"sandbox"`
	// URL overrides the endpoint, for tests.
	URL string `json:"url"`
}

// CrashLimits bounds one app's crash reports.
type CrashLimits struct {
	MaxFiles         int   `json:"max_files"`
	MaxBytes         int64 `json:"max_bytes"`
	PerInstallPerDay int   `json:"per_install_per_day"`
	// MinTrust is the lowest trust tier whose reports are taken: unverified
	// (the default), reregistered, device, attested or verified.
	MinTrust string `json:"min_trust"`
}

const (
	defaultCrashFiles     = 4
	defaultCrashBytes     = 2 << 20
	defaultCrashesPerDay  = 5
	defaultDailyBytes     = 512 << 20
	defaultMinFreeBytes   = 2 << 30
	defaultUploads        = 4
	maxCrashBytesAccepted = 16 << 20
)

var (
	reSlug        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	reAppAttestID = regexp.MustCompile(`^[A-Z0-9]{10}\.[A-Za-z0-9.-]{1,155}$`)
	rePropertyKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,47}$`)
	propertyTypes = map[string]bool{"bool": true, "int": true, "number": true, "string": true}
	// reservedContext are the crash context fields the service itself
	// defines; an app's allowlist cannot redefine them.
	reservedContext = map[string]bool{
		"appVersion": true, "appBuild": true, "os": true, "arch": true, "chipFamily": true,
		"memoryClassGB": true, "language": true, "installLocation": true, "previousVersion": true,
		"consecutiveLaunchCrashes": true, "secondsSinceLaunch": true,
	}
)

// LoadConfig reads and checks the apps file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(raw)
}

// ParseConfig checks an apps file's contents and fills in defaults.
func ParseConfig(raw []byte) (*Config, error) {
	var c Config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// A misspelled field would silently fall back to a default.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("apps file: %w", err)
	}
	if len(c.Apps) == 0 {
		return nil, fmt.Errorf("apps file names no apps")
	}
	for slug, app := range c.Apps {
		if app == nil {
			return nil, fmt.Errorf("app %q is empty", slug)
		}
		app.Slug = slug
		if err := app.check(); err != nil {
			return nil, fmt.Errorf("app %q: %w", slug, err)
		}
	}
	if err := c.checkBits(); err != nil {
		return nil, err
	}
	if _, err := identity.ParseClientAddress(c.ClientIPHeader, c.TrustedProxies); err != nil {
		return nil, err
	}
	storage := &c.CrashStorage
	if storage.DailyBytes <= 0 {
		storage.DailyBytes = defaultDailyBytes
	}
	if storage.MinFreeBytes <= 0 {
		storage.MinFreeBytes = defaultMinFreeBytes
	}
	if storage.ConcurrentUploads <= 0 {
		storage.ConcurrentUploads = defaultUploads
	}
	return &c, nil
}

// Slugs lists the configured apps in order.
func (c *Config) Slugs() []string {
	slugs := make([]string, 0, len(c.Apps))
	for slug := range c.Apps {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	return slugs
}

// checkBits refuses two apps of one team marking registrations with the
// same device bit: the second would see every Mac the first registered as
// a reinstall.
func (c *Config) checkBits() error {
	owners := map[string]string{}
	for _, slug := range c.Slugs() {
		app := c.Apps[slug]
		if app.DeviceCheck == nil || app.DeviceCheck.RegisteredBit == "" {
			continue
		}
		key := app.TeamID + " " + app.DeviceCheck.RegisteredBit
		if other, taken := owners[key]; taken {
			return fmt.Errorf("apps %q and %q both mark registrations with %s of team %s", other, slug, app.DeviceCheck.RegisteredBit, app.TeamID)
		}
		owners[key] = slug
	}
	return nil
}

func (a *AppConfig) check() error {
	if !reSlug.MatchString(a.Slug) {
		return fmt.Errorf("slug must match %s", reSlug)
	}
	if !reAppAttestID.MatchString(a.AppAttestID) {
		return fmt.Errorf("app_attest_id %q is not TEAMID.bundle.id", a.AppAttestID)
	}
	if a.TeamID == "" {
		a.TeamID = a.AppAttestID[:10]
	}
	for name, allowlist := range map[string]map[string]string{"properties": a.Properties, "crash_context": a.CrashContext} {
		for key, kind := range allowlist {
			if !rePropertyKey.MatchString(key) {
				return fmt.Errorf("%s key %q", name, key)
			}
			if !propertyTypes[kind] {
				return fmt.Errorf("%s.%s has type %q; use bool, int, number or string", name, key, kind)
			}
			if name == "crash_context" && reservedContext[key] {
				return fmt.Errorf("crash_context.%s is a field the service defines", key)
			}
		}
	}
	if dc := a.DeviceCheck; dc != nil && dc.RegisteredBit != "" {
		if dc.RegisteredBit != "bit0" && dc.RegisteredBit != "bit1" {
			return fmt.Errorf("device_check.registered_bit is %q; use bit0, bit1 or leave it out", dc.RegisteredBit)
		}
		if dc.KeyPath == "" || dc.KeyID == "" {
			return fmt.Errorf("device_check.registered_bit needs key_path and key_id")
		}
	}
	if dc := a.DeviceCheck; dc != nil && dc.KeyPath != "" {
		// Group-readable is how a service user in the key's group reads it;
		// readable by everyone is a leaked key.
		info, err := os.Stat(dc.KeyPath)
		if err != nil {
			return fmt.Errorf("device_check.key_path: %w", err)
		}
		if info.Mode().Perm()&0o004 != 0 {
			return fmt.Errorf("device_check.key_path %s is readable by everyone; chmod o-r it", dc.KeyPath)
		}
	}
	limits := &a.CrashReports
	if limits.MaxFiles <= 0 {
		limits.MaxFiles = defaultCrashFiles
	}
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = defaultCrashBytes
	}
	if limits.MaxBytes > maxCrashBytesAccepted {
		return fmt.Errorf("crash_reports.max_bytes is over %d", maxCrashBytesAccepted)
	}
	if limits.PerInstallPerDay <= 0 {
		limits.PerInstallPerDay = defaultCrashesPerDay
	}
	if _, known := trustRank[limits.MinTrust]; limits.MinTrust != "" && !known {
		return fmt.Errorf("crash_reports.min_trust %q is not a trust tier", limits.MinTrust)
	}
	return nil
}

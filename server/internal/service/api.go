// Package service is the Digoxin HTTP service: registration of install
// keys against Apple's evidence, signed heartbeats and crash reports, the
// signed delete, retention, and the loopback admin API.
package service

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/kageroumado/digoxin/server/identity"
)

const (
	maxBodyBytes = 64 << 10
	// installsPerDay is how many new installs one address may register per
	// app per day; registering an install the server knows is not counted.
	installsPerDay = 5
	installsWindow = 24 * time.Hour
	// reregistrationsPerDay is how often one install may register again a
	// day: each registration can cost a call to Apple.
	reregistrationsPerDay = 3
	writesPerMinute       = 60
	sentTolerance         = 48 * time.Hour
	// deleteSentTolerance is how old a signed delete may be: the client
	// signs it when the person turns telemetry off and destroys its key at
	// once, so a Mac that was offline sends it days later.
	deleteSentTolerance = 30 * 24 * time.Hour
	InstallHeader       = "Digoxin-Install"
	SignatureHeader     = "Digoxin-Signature"
	envelopeVersion     = 1
)

var reAppVersion = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]{0,31}$`)

// App is one configured app with its trust judge.
type App struct {
	Config *AppConfig
	Judge  *identity.Judge
}

// Service serves every configured app from one database.
type Service struct {
	Store      *Store
	Apps       map[string]*App
	Challenges *identity.Challenges
	// Clients names the address a request comes from, for rate limits.
	Clients         identity.ClientAddress
	Writes          *identity.Limiter
	Registrations   *identity.Limiter
	Reregistrations *identity.Limiter
	// CrashDir holds crash report files as <app>/<report id>/<name>.
	CrashDir string
	Storage  CrashStorage
	Now      func() time.Time
	// uploads holds a slot per crash report being received.
	uploads chan struct{}
}

// New builds the service for config, loading each app's DeviceCheck key.
func New(store *Store, config *Config, crashDir string) (*Service, error) {
	clients, err := identity.ParseClientAddress(config.ClientIPHeader, config.TrustedProxies)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(crashDir, 0o750); err != nil {
		return nil, err
	}
	s := &Service{
		Store: store, Apps: map[string]*App{}, Challenges: identity.NewChallenges(), Clients: clients,
		Writes:          identity.NewLimiter(writesPerMinute, time.Minute),
		Registrations:   identity.NewLimiter(installsPerDay, installsWindow),
		Reregistrations: identity.NewLimiter(reregistrationsPerDay, installsWindow),
		CrashDir:        crashDir, Storage: config.CrashStorage, Now: time.Now,
		uploads: make(chan struct{}, config.CrashStorage.ConcurrentUploads),
	}
	for slug, cfg := range config.Apps {
		judge := &identity.Judge{
			AppID: cfg.AppAttestID, RequireProductionAttest: cfg.RequireProductionAttest,
			Now: func() time.Time { return s.Now() }, Logf: prefixed(slug),
		}
		if dc := cfg.DeviceCheck; dc != nil {
			base := identity.DeviceCheckProduction
			if dc.Sandbox {
				base = identity.DeviceCheckSandbox
			}
			if dc.URL != "" {
				base = dc.URL
			}
			loaded, err := identity.LoadDeviceCheck(base, dc.KeyPath, dc.KeyID, cfg.TeamID)
			if err != nil {
				return nil, fmt.Errorf("app %s DeviceCheck key: %w", slug, err)
			}
			judge.DeviceCheck = loaded
			judge.RegisteredBit = map[string]int{"bit0": identity.Bit0, "bit1": identity.Bit1}[dc.RegisteredBit]
			if dc.RegisteredBit == "" {
				judge.RegisteredBit = identity.NoBit
			}
		}
		if judge.DeviceCheck == nil {
			log.Printf("digoxin: %s: DeviceCheck is off; registrations without App Attest stay unverified", slug)
		}
		s.Apps[slug] = &App{Config: cfg, Judge: judge}
	}
	s.Challenges.Now = func() time.Time { return s.Now() }
	return s, nil
}

func prefixed(slug string) func(string, ...any) {
	return func(format string, args ...any) { log.Printf("digoxin: "+slug+": "+format, args...) }
}

// Routes is the public API.
func (s *Service) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/{app}/challenge", s.withApp(s.handleChallenge))
	mux.HandleFunc("POST /v1/{app}/installs", s.withApp(s.handleRegister))
	mux.HandleFunc("DELETE /v1/{app}/installs/{id}", s.withApp(s.handleDelete))
	mux.HandleFunc("POST /v1/{app}/heartbeats", s.withApp(s.handleHeartbeats))
	mux.HandleFunc("POST /v1/{app}/crash-reports", s.withApp(s.handleCrashReport))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// withApp resolves {app} and applies the per-address write limit, both
// answered by the wrapper itself.
func (s *Service) withApp(handler func(http.ResponseWriter, *http.Request, *App)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app := s.Apps[r.PathValue("app")]
		if app == nil {
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

// securityHeaders are the API's: its answers are JSON or a bare status, so
// nothing may load, frame or embed them.
func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Cache-Control", "no-store")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	securityHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func noContent(w http.ResponseWriter) {
	securityHeaders(w)
	w.WriteHeader(http.StatusNoContent)
}

func internal(w http.ResponseWriter, what string, err error) {
	log.Printf("digoxin: %s: %v", what, err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// readBody reads at most limit bytes, answering 413 or 400 itself.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body over %d bytes", limit))
		} else {
			writeError(w, http.StatusBadRequest, "body not received")
		}
		return nil, false
	}
	return body, true
}

func (s *Service) handleChallenge(w http.ResponseWriter, r *http.Request, _ *App) {
	writeJSON(w, http.StatusOK, map[string]string{"challenge": base64.StdEncoding.EncodeToString(s.Challenges.Issue())})
}

type registration struct {
	Version     string `json:"version"`
	Challenge   string `json:"challenge"`
	PublicKey   string `json:"public_key"`
	DeviceCheck string `json:"device_check"`
	AppAttest   *struct {
		KeyID       string `json:"key_id"`
		Attestation string `json:"attestation"`
	} `json:"app_attest"`
}

func (s *Service) handleRegister(w http.ResponseWriter, r *http.Request, app *App) {
	body, ok := readBody(w, r, maxBodyBytes)
	if !ok {
		return
	}
	var reg registration
	if err := json.Unmarshal(body, &reg); err != nil {
		writeError(w, http.StatusBadRequest, "registration is not JSON")
		return
	}
	keyDER, err := base64.StdEncoding.DecodeString(reg.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "public_key is not base64")
		return
	}
	key, err := identity.ParseP256(keyDER)
	if err != nil {
		writeError(w, http.StatusBadRequest, "public_key is not a P-256 SubjectPublicKeyInfo")
		return
	}
	id := identity.InstallID(keyDER)
	if r.Header.Get(InstallHeader) != id || !identity.VerifyBody(key, body, r.Header.Get(SignatureHeader)) {
		writeError(w, http.StatusUnauthorized, errSignature)
		return
	}
	// Spent only by a request its key signed, so nobody can burn another's.
	challenge, err := base64.StdEncoding.DecodeString(reg.Challenge)
	if err != nil || !s.Challenges.Consume(challenge) {
		writeError(w, http.StatusBadRequest, "challenge unknown, used or expired")
		return
	}
	if !reAppVersion.MatchString(reg.Version) {
		writeError(w, http.StatusBadRequest, "version")
		return
	}
	var owner string
	err = s.Store.db.QueryRowContext(r.Context(), `SELECT app FROM installs WHERE id = ?`, id).Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		internal(w, "loading install", err)
		return
	}
	if err == nil && owner != app.Config.Slug {
		writeError(w, http.StatusConflict, errOtherAppMessage)
		return
	}
	existing, err := s.Store.install(r.Context(), app.Config.Slug, id)
	if err != nil {
		internal(w, "loading install", err)
		return
	}
	existingTrust := ""
	if existing != nil {
		existingTrust = existing.Trust
		if existing.Trust == identity.TrustBlocked {
			writeError(w, http.StatusForbidden, "install is blocked")
			return
		}
	}
	// A new install takes one of its address's daily slots before anything
	// asks Apple, so concurrent registrations cannot all fit in one slot; a
	// registration that fails gives it back. An install registering again
	// has its own daily allowance.
	now := s.Now()
	slot := app.Config.Slug + " " + s.Clients.Key(r)
	refund := func() {}
	if existing == nil {
		if !s.Registrations.Admit(slot, now) {
			w.Header().Set("Retry-After", "3600")
			writeError(w, http.StatusTooManyRequests, "too many new installs from this address today")
			return
		}
		refund = func() { s.Registrations.Refund(slot, now) }
	} else if !s.Reregistrations.Admit(app.Config.Slug+" "+id, now) {
		w.Header().Set("Retry-After", "3600")
		writeError(w, http.StatusTooManyRequests, "this install registered too often today")
		return
	}
	evidence := identity.Evidence{DeviceCheck: reg.DeviceCheck}
	if a := reg.AppAttest; a != nil {
		evidence.AppAttestKeyID, evidence.AppAttestAttestation = a.KeyID, a.Attestation
	}
	v, err := app.Judge.Judge(r.Context(), evidence, keyDER, challenge, existingTrust)
	if err != nil {
		refund()
		log.Printf("digoxin: %s: DeviceCheck unavailable: %v", app.Config.Slug, err)
		w.Header().Set("Retry-After", "300")
		writeError(w, http.StatusServiceUnavailable, "device check unavailable, try later")
		return
	}
	err = s.Store.saveInstall(r.Context(), app.Config.Slug, id, keyDER, v, now)
	if errors.Is(err, errOtherApp) {
		refund()
		writeError(w, http.StatusConflict, errOtherAppMessage)
		return
	}
	if err != nil {
		refund()
		internal(w, "saving install", err)
		return
	}
	// The log names no install: its lines carry times, which the database
	// does not keep.
	log.Printf("digoxin: %s: registered an install (%s)", app.Config.Slug, v.Trust)
	writeJSON(w, http.StatusCreated, map[string]string{"install": id, "trust": v.Trust})
}

// errSignature answers every request whose install or signature does not
// check, alike, so the answer does not say which installs exist.
const errSignature = "signature does not verify"

const errOtherAppMessage = "this key is registered for another app"

// envelope is the signed wrapper of every request after registration.
type envelope struct {
	V          int               `json:"v"`
	Seq        int64             `json:"seq"`
	Sent       string            `json:"sent"`
	Install    string            `json:"install"`
	Heartbeats []json.RawMessage `json:"heartbeats"`
	Context    json.RawMessage   `json:"context"`
}

// lookupInstall finds the install the request's header names, and its
// key, before any of the body is read; it answers itself on failure.
func (s *Service) lookupInstall(w http.ResponseWriter, r *http.Request, app *App) (*installRecord, *ecdsa.PublicKey, bool) {
	id := r.Header.Get(InstallHeader)
	if !identity.ValidInstallID(id) {
		writeError(w, http.StatusUnauthorized, errSignature)
		return nil, nil, false
	}
	install, err := s.Store.install(r.Context(), app.Config.Slug, id)
	if err != nil {
		internal(w, "loading install", err)
		return nil, nil, false
	}
	if install == nil {
		writeError(w, http.StatusUnauthorized, errSignature)
		return nil, nil, false
	}
	key, err := identity.ParseP256(install.PublicKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errSignature)
		return nil, nil, false
	}
	return install, key, true
}

// checkEnvelope parses a signed envelope and checks its common fields,
// answering itself on failure. maxAge is how far in the past sent may be.
func (s *Service) checkEnvelope(w http.ResponseWriter, raw []byte, install *installRecord, maxAge time.Duration) (*envelope, bool) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		writeError(w, http.StatusBadRequest, "envelope is not JSON")
		return nil, false
	}
	if env.Install != install.ID {
		writeError(w, http.StatusUnauthorized, "envelope names another install")
		return nil, false
	}
	if env.V != envelopeVersion {
		writeError(w, http.StatusBadRequest, "v must be 1")
		return nil, false
	}
	sent, err := time.Parse(time.RFC3339, env.Sent)
	if age := s.Now().Sub(sent); err != nil || age > maxAge || age < -sentTolerance {
		writeError(w, http.StatusBadRequest, "sent is out of range")
		return nil, false
	}
	if env.Seq <= install.LastSeq {
		writeError(w, http.StatusConflict, "seq already used")
		return nil, false
	}
	if install.Trust == identity.TrustBlocked {
		writeError(w, http.StatusForbidden, "install is blocked")
		return nil, false
	}
	return &env, true
}

// authenticate reads a JSON body, checks its signature and envelope.
func (s *Service) authenticate(w http.ResponseWriter, r *http.Request, app *App, maxAge time.Duration) (*envelope, *installRecord, bool) {
	install, key, ok := s.lookupInstall(w, r, app)
	if !ok {
		return nil, nil, false
	}
	body, ok := readBody(w, r, maxBodyBytes)
	if !ok {
		return nil, nil, false
	}
	if !identity.VerifyBody(key, body, r.Header.Get(SignatureHeader)) {
		writeError(w, http.StatusUnauthorized, errSignature)
		return nil, nil, false
	}
	env, ok := s.checkEnvelope(w, body, install, maxAge)
	return env, install, ok
}

func (s *Service) handleDelete(w http.ResponseWriter, r *http.Request, app *App) {
	// An unknown install answers as an unsigned request does, so the answer
	// does not say which installs exist.
	if r.Header.Get(InstallHeader) != r.PathValue("id") {
		writeError(w, http.StatusUnauthorized, errSignature)
		return
	}
	env, install, ok := s.authenticate(w, r, app, deleteSentTolerance)
	if !ok {
		return
	}
	if len(env.Heartbeats) != 0 || len(env.Context) != 0 {
		writeError(w, http.StatusBadRequest, "a delete carries nothing else")
		return
	}
	crashes, err := s.Store.deleteInstall(r.Context(), install.ID, env.Seq)
	if errors.Is(err, errReplay) {
		writeError(w, http.StatusConflict, "seq already used")
		return
	}
	if err != nil {
		internal(w, "deleting install", err)
		return
	}
	s.removeCrashFiles(app.Config.Slug, crashes)
	log.Printf("digoxin: %s: deleted an install, its heartbeats and %d crash reports", app.Config.Slug, len(crashes))
	noContent(w)
}

// removeCrashFiles deletes the stored files of the given reports.
func (s *Service) removeCrashFiles(app string, ids []string) {
	for _, id := range ids {
		if !reReportID.MatchString(id) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.CrashDir, app, id)); err != nil {
			log.Printf("digoxin: %s: removing crash report %s: %v", app, id, err)
		}
	}
}

// Retain runs the retention pass now and then every interval until ctx ends.
func (s *Service) Retain(ctx context.Context, interval time.Duration) {
	for {
		if err := s.retentionPass(ctx); err != nil {
			log.Printf("digoxin: retention: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

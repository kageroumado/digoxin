package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/kageroumado/digoxin/server/identity"
)

const (
	// multipartOverhead is what a crash report may carry beyond its files:
	// the envelope and the part headers.
	multipartOverhead = 64 << 10
	maxLaunchCrashes  = 1000
	maxSinceLaunch    = 1e9
	// incomingDir holds uploads until their signature checks, under the
	// crash directory so moving one into place is a rename.
	incomingDir = ".incoming"
)

var (
	reReportID = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	locations  = map[string]bool{"applications": true, "translocated": true, "other": true}
)

// crashContext is a crash report's context: the basic info, how the app
// was installed and launched, and the app's own allowlisted fields.
type crashContext struct {
	BasicInfo
	InstallLocation          string                     `json:"installLocation"`
	PreviousVersion          string                     `json:"previousVersion,omitempty"`
	ConsecutiveLaunchCrashes *int64                     `json:"consecutiveLaunchCrashes,omitempty"`
	SecondsSinceLaunch       *float64                   `json:"secondsSinceLaunch,omitempty"`
	Fields                   map[string]json.RawMessage `json:"fields,omitempty"`
}

// storedContext is crashContext as kept: the app's fields filtered.
type storedContext struct {
	BasicInfo
	InstallLocation          string         `json:"installLocation"`
	PreviousVersion          string         `json:"previousVersion,omitempty"`
	ConsecutiveLaunchCrashes *int64         `json:"consecutiveLaunchCrashes,omitempty"`
	SecondsSinceLaunch       *float64       `json:"secondsSinceLaunch,omitempty"`
	Fields                   map[string]any `json:"fields"`
}

func (c *crashContext) validate(allowlist map[string]string) (*storedContext, string) {
	if why := c.BasicInfo.validate(); why != "" {
		return nil, why
	}
	if !locations[c.InstallLocation] {
		return nil, "installLocation"
	}
	if c.PreviousVersion != "" && !reAppVersion.MatchString(c.PreviousVersion) {
		return nil, "previousVersion"
	}
	if n := c.ConsecutiveLaunchCrashes; n != nil && (*n < 0 || *n > maxLaunchCrashes) {
		return nil, "consecutiveLaunchCrashes"
	}
	if f := c.SecondsSinceLaunch; f != nil && (*f < 0 || *f > maxSinceLaunch) {
		return nil, "secondsSinceLaunch"
	}
	return &storedContext{
		BasicInfo: c.BasicInfo, InstallLocation: c.InstallLocation, PreviousVersion: c.PreviousVersion,
		ConsecutiveLaunchCrashes: c.ConsecutiveLaunchCrashes, SecondsSinceLaunch: c.SecondsSinceLaunch,
		Fields: filterValues(c.Fields, allowlist),
	}, ""
}

type crashFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// trustRank orders trust tiers for crash_reports.min_trust.
var trustRank = map[string]int{
	identity.TrustUnverified: 0, identity.TrustReregistered: 1, identity.TrustDevice: 2,
	identity.TrustAttested: 3, identity.TrustVerified: 4,
}

// handleCrashReport takes a signed multipart body: an "envelope" part (the
// signed envelope with the context) and one "file" part per file. The
// signature covers the whole body as sent.
//
// Everything that can be refused without the body is refused first: an
// unknown install, a trust below the app's minimum, an install past its
// daily reports, a full disk or day's budget, too many uploads at once.
// The body is then streamed into a temporary folder within the app's
// limits, hashed on the way, and moved into place only once the signature,
// the envelope and the context check.
func (s *Service) handleCrashReport(w http.ResponseWriter, r *http.Request, app *App) {
	limits := app.Config.CrashReports
	install, key, ok := s.lookupInstall(w, r, app)
	if !ok {
		return
	}
	why, status, err := s.crashRoom(r.Context(), app, install)
	if err != nil {
		internal(w, "checking room for a crash report", err)
		return
	}
	if why != "" {
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "86400")
		}
		writeError(w, status, why)
		return
	}
	select {
	case s.uploads <- struct{}{}:
		defer func() { <-s.uploads }()
	default:
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, "too many crash reports arriving at once")
		return
	}

	staging, err := s.stagingDir()
	if err != nil {
		internal(w, "staging a crash report", err)
		return
	}
	defer os.RemoveAll(staging)
	body := http.MaxBytesReader(w, r.Body, limits.MaxBytes+multipartOverhead)
	defer body.Close()
	digest := sha256.New()
	source := &recordingReader{r: io.TeeReader(body, digest)}
	envelopeRaw, files, why := readCrashParts(r.Header.Get("Content-Type"), source, staging, limits)
	if why == "" {
		if _, err := io.Copy(io.Discard, source); err != nil {
			why = "body not received"
		}
	}
	var tooLarge *http.MaxBytesError
	if errors.As(source.err, &tooLarge) || why == "files over the size limit" || why == "too many files" {
		writeError(w, http.StatusRequestEntityTooLarge, why)
		return
	}
	if !identity.VerifyDigest(key, digest.Sum(nil), r.Header.Get(SignatureHeader)) {
		writeError(w, http.StatusUnauthorized, errSignature)
		return
	}
	if why != "" {
		writeError(w, http.StatusBadRequest, why)
		return
	}
	env, ok := s.checkEnvelope(w, envelopeRaw, install, sentTolerance)
	if !ok {
		return
	}
	if len(env.Context) == 0 {
		writeError(w, http.StatusBadRequest, "context missing")
		return
	}
	var context crashContext
	if err := json.Unmarshal(env.Context, &context); err != nil {
		writeError(w, http.StatusBadRequest, "context is not an object")
		return
	}
	stored, why := context.validate(app.Config.CrashContext)
	if why != "" {
		writeError(w, http.StatusBadRequest, why)
		return
	}
	id, err := s.saveCrashReport(r.Context(), app, install.ID, env.Seq, stored, files, staging)
	switch {
	case errors.Is(err, errReplay):
		writeError(w, http.StatusConflict, "seq already used")
	case errors.Is(err, errDailyCrashLimit):
		w.Header().Set("Retry-After", "86400")
		writeError(w, http.StatusTooManyRequests, "daily crash report limit reached")
	case errors.Is(err, errCrashBudget):
		w.Header().Set("Retry-After", "3600")
		writeError(w, http.StatusInsufficientStorage, "crash report storage is full for today")
	case err != nil:
		internal(w, "storing crash report", err)
	default:
		// The log names no report: its id maps to an install, and log lines carry times.
		log.Printf("digoxin: %s: a crash report, %d files", app.Config.Slug, len(files))
		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	}
}

// crashRoom answers why a report from install cannot be taken now, with
// the status to answer, or "" when it can. A failure to find out is an
// error, never a policy answer: a broken database is not a full disk.
func (s *Service) crashRoom(ctx context.Context, app *App, install *installRecord) (string, int, error) {
	limits := app.Config.CrashReports
	if trustRank[install.Trust] < trustRank[limits.MinTrust] || install.Trust == identity.TrustBlocked {
		return "this install's trust is below what crash reports need", http.StatusForbidden, nil
	}
	today := s.Now().UTC().Format(dayLayout)
	var sent int
	if err := s.Store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM crash_reports WHERE install = ? AND received = ?`,
		install.ID, today).Scan(&sent); err != nil {
		return "", 0, fmt.Errorf("counting today's reports: %w", err)
	}
	if sent >= limits.PerInstallPerDay {
		return "daily crash report limit reached", http.StatusTooManyRequests, nil
	}
	free, err := freeBytes(s.CrashDir)
	if err != nil {
		// Unknown free space refuses, as low free space does.
		log.Printf("digoxin: %s: free space of the crash directory is unreadable, refusing reports: %v", app.Config.Slug, err)
		return "the server is low on disk", http.StatusInsufficientStorage, nil
	}
	if free < s.Storage.MinFreeBytes {
		return "the server is low on disk", http.StatusInsufficientStorage, nil
	}
	used, err := s.Store.crashBytes(ctx, today)
	if err != nil {
		return "", 0, fmt.Errorf("summing today's report bytes: %w", err)
	}
	if used >= s.Storage.DailyBytes {
		return "crash report storage is full for today", http.StatusInsufficientStorage, nil
	}
	return "", 0, nil
}

func freeBytes(dir string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

func (s *Store) crashBytes(ctx context.Context, day string) (int64, error) {
	var used int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(bytes), 0) FROM crash_reports WHERE received = ?`, day).Scan(&used)
	return used, err
}

// stagingDir makes a fresh folder for one upload.
func (s *Service) stagingDir() (string, error) {
	parent := filepath.Join(s.CrashDir, incomingDir)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return "", err
	}
	return os.MkdirTemp(parent, "upload-")
}

// readCrashParts streams the multipart body: the envelope into memory, each
// file into dir, within the limits. It answers why it cannot when it cannot.
func readCrashParts(contentType string, body io.Reader, dir string, limits CrashLimits) ([]byte, []crashFile, string) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return nil, nil, "body is not multipart/form-data"
	}
	reader := multipart.NewReader(body, params["boundary"])
	var envelopeRaw []byte
	var files []crashFile
	var total int64
	// Names compare case-insensitively: on the case-insensitive file
	// systems these reports come from, A.ips and a.ips are one file.
	seen := map[string]bool{}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, "multipart body is malformed"
		}
		switch part.FormName() {
		case "envelope":
			if envelopeRaw != nil {
				return nil, nil, "more than one envelope"
			}
			envelopeRaw, err = io.ReadAll(io.LimitReader(part, maxBodyBytes+1))
			if err != nil || len(envelopeRaw) > maxBodyBytes {
				return nil, nil, "envelope is malformed or too large"
			}
		case "file":
			name := part.FileName()
			folded := strings.ToLower(name)
			if !reFileName.MatchString(name) || seen[folded] {
				return nil, nil, "file name"
			}
			seen[folded] = true
			if len(files) == limits.MaxFiles {
				return nil, nil, "too many files"
			}
			size, why := writePart(part, filepath.Join(dir, name), limits.MaxBytes-total)
			if why != "" {
				return nil, nil, why
			}
			total += size
			files = append(files, crashFile{Name: name, Size: size})
		default:
			return nil, nil, "unknown part " + part.FormName()
		}
	}
	if envelopeRaw == nil {
		return nil, nil, "envelope missing"
	}
	if len(files) == 0 {
		return nil, nil, "no files"
	}
	return envelopeRaw, files, ""
}

// writePart copies a part into path, refusing one longer than room.
func writePart(part io.Reader, path string, room int64) (int64, string) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return 0, "file name"
	}
	defer file.Close()
	size, err := io.Copy(file, io.LimitReader(part, room+1))
	switch {
	case err != nil:
		return 0, "multipart body is malformed"
	case size > room:
		return 0, "files over the size limit"
	}
	return size, ""
}

var (
	errDailyCrashLimit = errors.New("daily crash report limit")
	errCrashBudget     = errors.New("daily crash report budget")
)

// saveCrashReport stores the row under seq, then moves the staged files
// into place; a row whose files cannot follow is removed again.
func (s *Service) saveCrashReport(ctx context.Context, app *App, install string, seq int64, c *storedContext, files []crashFile, staging string) (string, error) {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	id := hex.EncodeToString(raw)
	if err := s.Store.saveCrashRow(ctx, app, install, seq, id, c, files, s.Now(), s.Storage.DailyBytes); err != nil {
		return "", err
	}
	dir := filepath.Join(s.CrashDir, app.Config.Slug)
	err := os.MkdirAll(dir, 0o750)
	if err == nil {
		err = os.Rename(staging, filepath.Join(dir, id))
	}
	if err != nil {
		if _, undo := s.Store.db.ExecContext(ctx, `DELETE FROM crash_reports WHERE id = ?`, id); undo != nil {
			log.Printf("digoxin: %s: a crash report's files could not be moved and its row stays: %v", app.Config.Slug, undo)
		}
		return "", err
	}
	return id, nil
}

// recordingReader keeps the first error its reader answered, which the
// multipart reader otherwise reports only as a malformed body.
type recordingReader struct {
	r   io.Reader
	err error
}

func (r *recordingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil && err != io.EOF && r.err == nil {
		r.err = err
	}
	return n, err
}

func (s *Store) saveCrashRow(ctx context.Context, app *App, install string, seq int64, id string, c *storedContext, files []crashFile, now time.Time, dailyBytes int64) error {
	contextJSON, err := json.Marshal(c)
	if err != nil {
		return err
	}
	filesJSON, err := json.Marshal(files)
	if err != nil {
		return err
	}
	var size int64
	for _, f := range files {
		size += f.Size
	}
	s.write.Lock()
	defer s.write.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := advance(ctx, tx, install, seq); err != nil {
		return err
	}
	day := now.UTC().Format(dayLayout)
	var sent int
	var used int64
	if err := tx.QueryRowContext(ctx, `
		SELECT (SELECT COUNT(*) FROM crash_reports WHERE install = ? AND received = ?),
			(SELECT COALESCE(SUM(bytes), 0) FROM crash_reports WHERE received = ?)`,
		install, day, day).Scan(&sent, &used); err != nil {
		return err
	}
	var refusal error
	switch {
	case sent >= app.Config.CrashReports.PerInstallPerDay:
		refusal = errDailyCrashLimit
	case used+size > dailyBytes:
		refusal = errCrashBudget
	}
	if refusal != nil {
		// The sequence number is spent all the same, so the refusal commits.
		if err := tx.Commit(); err != nil {
			return err
		}
		return refusal
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO crash_reports (id, install, app, received, context, files, bytes) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, install, app.Config.Slug, day, string(contextJSON), string(filesJSON), size); err != nil {
		return fmt.Errorf("inserting crash report: %w", err)
	}
	return tx.Commit()
}

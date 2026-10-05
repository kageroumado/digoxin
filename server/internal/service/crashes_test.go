package service

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// countingReader is a request body that counts what the server read of it.
type countingReader struct {
	r *bytes.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func (c *countingReader) Close() error { return nil }

// postCounting posts a signed crash report whose body counts its reads.
func (h *harness) postCounting(c *testClient, files map[string]string) (*httptest.ResponseRecorder, *countingReader) {
	body, contentType := h.crashBody(c, testCrashContext(), files)
	reader := &countingReader{r: bytes.NewReader(body)}
	request := httptest.NewRequest("POST", "/v1/refrax/crash-reports", reader)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set(InstallHeader, c.id)
	request.Header.Set(SignatureHeader, c.sign(h.t, body))
	recorder := httptest.NewRecorder()
	h.mux.ServeHTTP(recorder, request)
	return recorder, reader
}

func crashConfig(storage string, limits string) string {
	return `{` + storage + `"apps": {"refrax": {"app_attest_id": "52K336H235.website.refrax.browser",
		"crash_context": {"engines": "string"}, "crash_reports": {` + limits + `}}}}`
}

// TestNothingIsReadForAReportThatCannotBeTaken: an unknown install, one
// past its daily reports, or a full disk cost the server no body bytes.
func TestNothingIsReadForAReportThatCannotBeTaken(t *testing.T) {
	h := newHarnessWith(t, crashConfig("", `"per_install_per_day": 1`))
	stranger := newTestClient(t)
	response, read := h.postCounting(stranger, map[string]string{"a.ips": strings.Repeat("x", 60000)})
	if response.Code != http.StatusUnauthorized || read.n != 0 {
		t.Fatalf("unknown install: %d after %d bytes", response.Code, read.n)
	}
	c := newTestClient(t)
	h.register(c)
	h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).id(t)
	response, read = h.postCounting(c, map[string]string{"a.ips": "2"})
	if response.Code != http.StatusTooManyRequests || read.n != 0 {
		t.Fatalf("past the daily reports: %d after %d bytes", response.Code, read.n)
	}

	full := newHarnessWith(t, crashConfig(`"crash_storage": {"min_free_bytes": 4611686018427387904},`, ""))
	c = newTestClient(t)
	full.register(c)
	response, read = full.postCounting(c, map[string]string{"a.ips": "1"})
	if response.Code != http.StatusInsufficientStorage || read.n != 0 {
		t.Fatalf("a full disk: %d after %d bytes", response.Code, read.n)
	}
}

func TestTheDailyBudgetCoversEveryApp(t *testing.T) {
	h := newHarnessWith(t, crashConfig(`"crash_storage": {"daily_bytes": 1500},`, `"per_install_per_day": 10`))
	a, b := newTestClient(t), newTestClient(t)
	h.register(a)
	h.register(b)
	h.postCrash(a, testCrashContext(), map[string]string{"a.ips": strings.Repeat("x", 1000)}).id(t)
	if got := h.postCrash(b, testCrashContext(), map[string]string{"a.ips": strings.Repeat("x", 1000)}).Code; got != http.StatusInsufficientStorage {
		t.Fatalf("a report past the day's budget: %d", got)
	}
	h.now = h.now.Add(24 * time.Hour)
	h.postCrash(b, testCrashContext(), map[string]string{"a.ips": strings.Repeat("x", 1000)}).id(t)
}

func TestCrashReportsCanRequireTrust(t *testing.T) {
	h := newHarnessWith(t, crashConfig("", `"min_trust": "device"`))
	c := newTestClient(t)
	h.register(c)
	if got := h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).Code; got != http.StatusForbidden {
		t.Fatalf("an unverified install where device is required: %d", got)
	}
	_, _ = h.svc.Store.db.Exec(`UPDATE installs SET trust = 'attested' WHERE id = ?`, c.id)
	h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).id(t)
}

func TestUploadsAtOnceAreBounded(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	h.svc.uploads = make(chan struct{}, 1)
	h.svc.uploads <- struct{}{}
	if got := h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).Code; got != http.StatusServiceUnavailable {
		t.Fatalf("an upload past the bound: %d", got)
	}
	<-h.svc.uploads
	h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).id(t)
	if entries, _ := os.ReadDir(filepath.Join(h.svc.CrashDir, incomingDir)); len(entries) != 0 {
		t.Fatalf("%d staged uploads left behind", len(entries))
	}
}

// TestFileNamesDifferOnlyInCase: A.ips and a.ips are one file on the Macs
// these reports come from; the second would overwrite the first.
func TestFileNamesDifferOnlyInCase(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	envelope, _ := writer.CreateFormField("envelope")
	_, _ = envelope.Write(h.envelope(c, map[string]any{"context": testCrashContext()}))
	for _, name := range []string{"A.ips", "a.ips"} {
		part, _ := writer.CreateFormFile("file", name)
		_, _ = part.Write([]byte(name))
	}
	_ = writer.Close()
	response := h.do("POST", "/v1/refrax/crash-reports", body.Bytes(), map[string]string{
		InstallHeader: c.id, SignatureHeader: c.sign(t, body.Bytes()), "Content-Type": writer.FormDataContentType(),
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("names differing in case: %d %s", response.Code, response.Body)
	}
}

// TestCrashReportsKeepTheDayOnly: no stored value says at what hour a
// report arrived.
func TestCrashReportsKeepTheDayOnly(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	id := h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).id(t)
	var received string
	_ = h.svc.Store.db.QueryRow(`SELECT received FROM crash_reports WHERE id = ?`, id).Scan(&received)
	if received != h.today() {
		t.Fatalf("received %q", received)
	}
	var list []CrashReport
	h.adminJSON("/admin/refrax/crashes", &list)
	if len(list) != 1 || list[0].Received != h.today() {
		t.Fatalf("list %+v", list)
	}
}

func TestRetentionRemovesOrphanedFolders(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	id := h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).id(t)
	orphan := filepath.Join(h.svc.CrashDir, "refrax", strings.Repeat("ab", 16))
	staged := filepath.Join(h.svc.CrashDir, incomingDir, "upload-1")
	for _, dir := range []string{orphan, staged} {
		_ = os.MkdirAll(dir, 0o750)
		old := time.Now().Add(-2 * orphanAge)
		_ = os.Chtimes(dir, old, old)
	}
	fresh := filepath.Join(h.svc.CrashDir, incomingDir, "upload-2")
	_ = os.MkdirAll(fresh, 0o750)
	if err := h.svc.removeOrphans(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]bool{orphan: false, staged: false, fresh: true, filepath.Join(h.svc.CrashDir, "refrax", id): true} {
		if _, err := os.Stat(dir); (err == nil) != want {
			t.Errorf("%s exists: %v, want %v", dir, err == nil, want)
		}
	}
}

func TestCrashLimitsAreChecked(t *testing.T) {
	for name, limits := range map[string]string{
		"min_trust": `"min_trust": "trusted"`,
	} {
		if _, err := ParseConfig([]byte(crashConfig("", limits))); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	config, _ := ParseConfig([]byte(crashConfig("", "")))
	if s := config.CrashStorage; s.DailyBytes != defaultDailyBytes || s.MinFreeBytes != defaultMinFreeBytes || s.ConcurrentUploads != defaultUploads {
		_ = json.NewEncoder(os.Stderr).Encode(s)
		t.Fatal("crash storage defaults")
	}
}

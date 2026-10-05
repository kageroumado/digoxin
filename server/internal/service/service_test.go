package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kageroumado/digoxin/server/identity"
	"github.com/kageroumado/digoxin/server/identity/identitytest"
)

// ---- Harness ----

const testConfig = `{"apps": {
	"refrax": {
		"app_attest_id": "52K336H235.website.refrax.browser",
		"properties": {"chromiumInstalled": "bool", "tabs": "int", "engine": "string"},
		"crash_context": {"engines": "string"},
		"crash_reports": {"max_files": 2, "max_bytes": 4096, "per_install_per_day": 2}
	},
	"sevoflurane": {"app_attest_id": "52K336H235.glass.kagerou.sevoflurane"}
}}`

type testClient struct {
	key *ecdsa.PrivateKey
	der []byte
	id  string
	seq int64
}

func newTestClient(t *testing.T) *testClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{key: key, der: der, id: identity.InstallID(der)}
}

func (c *testClient) sign(t *testing.T, body []byte) string {
	t.Helper()
	digest := sha256.Sum256(body)
	signature, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

type harness struct {
	t     *testing.T
	svc   *Service
	mux   http.Handler
	admin http.Handler
	now   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, testConfig)
}

func newHarnessWith(t *testing.T, configJSON string) *harness {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	config, err := ParseConfig([]byte(configJSON))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(store, config, filepath.Join(dir, "crashes"))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, svc: svc, now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	svc.Now = func() time.Time { return h.now }
	svc.Writes = identity.NewLimiter(10000, time.Minute)
	h.mux, h.admin = svc.Routes(), svc.AdminRoutes()
	return h
}

func (h *harness) do(method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	recorder := httptest.NewRecorder()
	h.mux.ServeHTTP(recorder, request)
	return recorder
}

func (h *harness) adminGet(path string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", path, nil)
	request.Host = "127.0.0.1:9131"
	h.admin.ServeHTTP(recorder, request)
	return recorder
}

func (h *harness) adminJSON(path string, into any) {
	h.t.Helper()
	response := h.adminGet(path)
	if response.Code != http.StatusOK {
		h.t.Fatalf("%s: %d %s", path, response.Code, response.Body)
	}
	if err := json.Unmarshal(response.Body.Bytes(), into); err != nil {
		h.t.Fatalf("%s: %v", path, err)
	}
}

func (h *harness) challenge(app string) string {
	h.t.Helper()
	response := h.do("GET", "/v1/"+app+"/challenge", nil, nil)
	if response.Code != http.StatusOK {
		h.t.Fatalf("challenge: %d", response.Code)
	}
	var answer struct{ Challenge string }
	_ = json.Unmarshal(response.Body.Bytes(), &answer)
	return answer.Challenge
}

func (h *harness) registerIn(app string, c *testClient, extra map[string]any) *httptest.ResponseRecorder {
	h.t.Helper()
	fields := map[string]any{
		"version": "0.34", "challenge": h.challenge(app), "public_key": base64.StdEncoding.EncodeToString(c.der),
	}
	for k, v := range extra {
		fields[k] = v
	}
	body, _ := json.Marshal(fields)
	return h.do("POST", "/v1/"+app+"/installs", body, map[string]string{InstallHeader: c.id, SignatureHeader: c.sign(h.t, body)})
}

func (h *harness) register(c *testClient) {
	h.t.Helper()
	if response := h.registerIn("refrax", c, nil); response.Code != http.StatusCreated {
		h.t.Fatalf("register: %d %s", response.Code, response.Body)
	}
}

func (h *harness) envelope(c *testClient, fields map[string]any) []byte {
	c.seq++
	all := map[string]any{"v": 1, "seq": c.seq, "sent": h.now.Format(time.RFC3339), "install": c.id}
	for k, v := range fields {
		all[k] = v
	}
	body, _ := json.Marshal(all)
	return body
}

func (h *harness) signed(method, path string, c *testClient, body []byte) *httptest.ResponseRecorder {
	return h.do(method, path, body, map[string]string{InstallHeader: c.id, SignatureHeader: c.sign(h.t, body)})
}

func (h *harness) postHeartbeats(c *testClient, beats ...map[string]any) *httptest.ResponseRecorder {
	return h.signed("POST", "/v1/refrax/heartbeats", c, h.envelope(c, map[string]any{"heartbeats": beats}))
}

func (h *harness) deleteInstall(c *testClient) *httptest.ResponseRecorder {
	return h.signed("DELETE", "/v1/refrax/installs/"+c.id, c, h.envelope(c, nil))
}

func basicInfo() map[string]any {
	return map[string]any{
		"appVersion": "0.34", "appBuild": "41", "os": "27.0", "arch": "arm64",
		"chipFamily": "M3", "memoryClassGB": 36, "language": "fr",
	}
}

func validHeartbeat(day string) map[string]any {
	beat := basicInfo()
	beat["day"] = day
	beat["activeDays7"] = 3
	beat["properties"] = map[string]any{"chromiumInstalled": true, "tabs": 12}
	return beat
}

func (h *harness) today() string { return h.now.Format(dayLayout) }

func (h *harness) count(query string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.svc.Store.db.QueryRow(query, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

type batchAnswer struct {
	Accepted int
	Rejected []rejection
}

func answerOf(t *testing.T, response *httptest.ResponseRecorder) batchAnswer {
	t.Helper()
	if response.Code != http.StatusAccepted {
		t.Fatalf("heartbeats: %d %s", response.Code, response.Body)
	}
	var answer batchAnswer
	_ = json.Unmarshal(response.Body.Bytes(), &answer)
	return answer
}

// ---- Registration and heartbeats ----

func TestRegisterThenHeartbeat(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	response := h.registerIn("refrax", c, nil)
	var reg struct{ Install, Trust string }
	_ = json.Unmarshal(response.Body.Bytes(), &reg)
	if response.Code != http.StatusCreated || reg.Install != c.id || reg.Trust != identity.TrustUnverified {
		t.Fatalf("registered %d %+v", response.Code, reg)
	}

	bad := validHeartbeat(h.today())
	bad["chipFamily"] = "M3 Pro"
	answer := answerOf(t, h.postHeartbeats(c, validHeartbeat(h.today()), bad))
	if answer.Accepted != 1 || len(answer.Rejected) != 1 || answer.Rejected[0].I != 1 || answer.Rejected[0].Why != "chipFamily" {
		t.Fatalf("answer %+v", answer)
	}
	// A second heartbeat on the same day counts nothing new.
	if answer := answerOf(t, h.postHeartbeats(c, validHeartbeat(h.today()))); answer.Accepted != 0 {
		t.Fatalf("a day counted twice: %+v", answer)
	}
	yesterday := h.now.AddDate(0, 0, -1).Format(dayLayout)
	if answer := answerOf(t, h.postHeartbeats(c, validHeartbeat(yesterday))); answer.Accepted != 1 {
		t.Fatalf("yesterday: %+v", answer)
	}
	if n := h.count(`SELECT COUNT(*) FROM heartbeats WHERE install = ?`, c.id); n != 2 {
		t.Fatalf("%d heartbeats stored", n)
	}
}

func TestHeartbeatValidation(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	cases := map[string]func(map[string]any){
		"day":           func(b map[string]any) { b["day"] = h.now.AddDate(0, 0, -9).Format(dayLayout) },
		"activeDays7":   func(b map[string]any) { b["activeDays7"] = 8 },
		"memoryClassGB": func(b map[string]any) { b["memoryClassGB"] = 18 },
		"os":            func(b map[string]any) { b["os"] = "27.0.1" },
		"language":      func(b map[string]any) { b["language"] = "fr-FR" },
		"arch":          func(b map[string]any) { b["arch"] = "ppc" },
		"appVersion":    func(b map[string]any) { b["appVersion"] = "v1 beta" },
	}
	for why, spoil := range cases {
		beat := validHeartbeat(h.today())
		spoil(beat)
		answer := answerOf(t, h.postHeartbeats(c, beat))
		if answer.Accepted != 0 || len(answer.Rejected) != 1 || answer.Rejected[0].Why != why {
			t.Errorf("%s: %+v", why, answer)
		}
	}
	if got := h.postHeartbeats(c).Code; got != http.StatusBadRequest {
		t.Fatalf("an empty batch: %d", got)
	}
}

func TestPropertiesAreFilteredByTheAllowlist(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	beat := validHeartbeat(h.today())
	beat["properties"] = map[string]any{
		"chromiumInstalled": "yes",          // wrong type
		"tabs":              7,              // kept
		"engine":            "WebKit\u200b", // invisible character
		"homeFolder":        "/Users/kiri",  // not allowlisted
	}
	answerOf(t, h.postHeartbeats(c, beat))
	var properties string
	_ = h.svc.Store.db.QueryRow(`SELECT properties FROM heartbeats`).Scan(&properties)
	if properties != `{"tabs":7}` {
		t.Fatalf("stored properties %s", properties)
	}
}

func TestReplayedSequenceIsRefused(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	body := h.envelope(c, map[string]any{"heartbeats": []any{validHeartbeat(h.today())}})
	headers := map[string]string{InstallHeader: c.id, SignatureHeader: c.sign(t, body)}
	if got := h.do("POST", "/v1/refrax/heartbeats", body, headers).Code; got != http.StatusAccepted {
		t.Fatalf("first send: %d", got)
	}
	if got := h.do("POST", "/v1/refrax/heartbeats", body, headers).Code; got != http.StatusConflict {
		t.Fatalf("replay: %d, want 409", got)
	}
	c.seq = 0 // a lower sequence number, freshly signed
	if got := h.postHeartbeats(c, validHeartbeat(h.today())).Code; got != http.StatusConflict {
		t.Fatalf("stale seq: %d, want 409", got)
	}
}

func TestUnauthenticatedWritesAnswer401(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	if got := h.postHeartbeats(c, validHeartbeat(h.today())).Code; got != http.StatusUnauthorized {
		t.Fatalf("unknown install: %d", got)
	}
	h.register(c)

	body := h.envelope(c, map[string]any{"heartbeats": []any{validHeartbeat(h.today())}})
	other := newTestClient(t)
	if got := h.do("POST", "/v1/refrax/heartbeats", body, map[string]string{InstallHeader: c.id, SignatureHeader: other.sign(t, body)}).Code; got != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", got)
	}
	body = h.envelope(c, map[string]any{"install": other.id, "heartbeats": []any{validHeartbeat(h.today())}})
	if got := h.signed("POST", "/v1/refrax/heartbeats", c, body).Code; got != http.StatusUnauthorized {
		t.Fatalf("envelope names another install: %d", got)
	}
	if got := h.do("POST", "/v1/refrax/heartbeats", body, map[string]string{SignatureHeader: c.sign(t, body)}).Code; got != http.StatusUnauthorized {
		t.Fatalf("missing header: %d", got)
	}
	// An install is its app's: another app's route does not know it.
	body = h.envelope(c, map[string]any{"heartbeats": []any{validHeartbeat(h.today())}})
	if got := h.signed("POST", "/v1/sevoflurane/heartbeats", c, body).Code; got != http.StatusUnauthorized {
		t.Fatalf("another app's route: %d", got)
	}
	if got := h.registerIn("sevoflurane", c, nil).Code; got != http.StatusConflict {
		t.Fatalf("the same key in another app: %d", got)
	}
	if got := h.do("GET", "/v1/nonesuch/challenge", nil, nil).Code; got != http.StatusNotFound {
		t.Fatalf("unknown app: %d", got)
	}
}

func TestRegistrationChecks(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	fields := map[string]any{"version": "0.34", "challenge": h.challenge("refrax"), "public_key": base64.StdEncoding.EncodeToString(c.der)}
	body, _ := json.Marshal(fields)
	other := newTestClient(t)
	if got := h.do("POST", "/v1/refrax/installs", body, map[string]string{InstallHeader: other.id, SignatureHeader: c.sign(t, body)}).Code; got != http.StatusUnauthorized {
		t.Fatalf("id of another key: %d", got)
	}
	if got := h.do("POST", "/v1/refrax/installs", body, map[string]string{InstallHeader: c.id, SignatureHeader: other.sign(t, body)}).Code; got != http.StatusUnauthorized {
		t.Fatalf("signed by another key: %d", got)
	}
	// Neither refused attempt spent the challenge: only a request the key
	// signed can, so nobody can burn another client's.
	if got := h.do("POST", "/v1/refrax/installs", body, map[string]string{InstallHeader: c.id, SignatureHeader: c.sign(t, body)}).Code; got != http.StatusCreated {
		t.Fatalf("the challenge after refused attempts: %d", got)
	}
	if got := h.do("POST", "/v1/refrax/installs", body, map[string]string{InstallHeader: c.id, SignatureHeader: c.sign(t, body)}).Code; got != http.StatusBadRequest {
		t.Fatalf("reused challenge: %d", got)
	}
}

func TestSentOutsideTheWindowIsRefused(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	stale := h.now.Add(-49 * time.Hour).Format(time.RFC3339)
	body := h.envelope(c, map[string]any{"heartbeats": []any{validHeartbeat(h.today())}, "sent": stale})
	if got := h.signed("POST", "/v1/refrax/heartbeats", c, body).Code; got != http.StatusBadRequest {
		t.Fatalf("stale sent: %d", got)
	}
	// A delete signed when telemetry was turned off arrives days later.
	body = h.envelope(c, map[string]any{"sent": h.now.Add(-10 * 24 * time.Hour).Format(time.RFC3339)})
	if got := h.signed("DELETE", "/v1/refrax/installs/"+c.id, c, body).Code; got != http.StatusNoContent {
		t.Fatalf("a delete sent ten days ago: %d", got)
	}
}

func TestReregisteringKeepsTheSequence(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	h.postHeartbeats(c, validHeartbeat(h.today()))
	h.register(c)
	c.seq = 0
	if got := h.postHeartbeats(c, validHeartbeat(h.today())).Code; got != http.StatusConflict {
		t.Fatalf("seq restarted after re-registration: %d", got)
	}
}

func TestNewInstallsPerAddressAreCapped(t *testing.T) {
	h := newHarness(t)
	var first *testClient
	for i := 0; i < installsPerDay; i++ {
		c := newTestClient(t)
		if first == nil {
			first = c
		}
		h.register(c)
	}
	response := h.registerIn("refrax", newTestClient(t), nil)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("install %d: %d", installsPerDay+1, response.Code)
	}
	if got := h.registerIn("sevoflurane", newTestClient(t), nil).Code; got != http.StatusCreated {
		t.Fatalf("another app's first install from the address: %d", got)
	}
	if got := h.registerIn("refrax", first, nil).Code; got != http.StatusCreated {
		t.Fatalf("registering a known install again: %d", got)
	}
	h.now = h.now.Add(installsWindow + time.Minute)
	if got := h.registerIn("refrax", newTestClient(t), nil).Code; got != http.StatusCreated {
		t.Fatalf("a day later: %d", got)
	}
}

func TestDeviceCheckThroughRegistration(t *testing.T) {
	apple, keyPath := identitytest.NewFakeApple(t)
	config := fmt.Sprintf(`{"apps": {"refrax": {"app_attest_id": "52K336H235.website.refrax.browser",
		"device_check": {"key_path": %q, "key_id": "KEYID12345", "url": %q, "registered_bit": "bit1"}}}}`, keyPath, apple.URL)
	h := newHarnessWith(t, config)
	nonce := 0
	trust := func(c *testClient) string {
		nonce++
		response := h.registerIn("refrax", c, map[string]any{"device_check": identitytest.Token("this Mac", nonce)})
		var answer struct{ Trust string }
		_ = json.Unmarshal(response.Body.Bytes(), &answer)
		return answer.Trust
	}
	first := newTestClient(t)
	if got := trust(first); got != identity.TrustDevice {
		t.Fatalf("first: %s", got)
	}
	if got := trust(first); got != identity.TrustDevice {
		t.Fatalf("first again: %s", got)
	}
	if got := trust(newTestClient(t)); got != identity.TrustReregistered {
		t.Fatalf("reinstall: %s", got)
	}
}

// ---- Delete ----

func TestDeleteForgetsTheInstall(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	h.postHeartbeats(c, validHeartbeat(h.today()))
	id := h.postCrash(c, testCrashContext(), map[string]string{"Refrax.ips": "{}\n{}"}).id(t)
	dir := filepath.Join(h.svc.CrashDir, "refrax", id)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("crash files: %v", err)
	}

	if response := h.deleteInstall(c); response.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", response.Code, response.Body)
	}
	if n := h.count(`SELECT (SELECT COUNT(*) FROM installs) + (SELECT COUNT(*) FROM heartbeats) + (SELECT COUNT(*) FROM crash_reports)`); n != 0 {
		t.Fatalf("%d rows left", n)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("crash files left: %v", err)
	}
	if got := h.postHeartbeats(c, validHeartbeat(h.today())).Code; got != http.StatusUnauthorized {
		t.Fatalf("a deleted install still writes: %d", got)
	}
	// An unknown install answers as an unsigned request does: the answer
	// does not say whether it ever existed.
	if got := h.deleteInstall(c).Code; got != http.StatusUnauthorized {
		t.Fatalf("deleting an unknown install: %d, want 401", got)
	}
}

func TestDeleteCarriesNothingElse(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	body := h.envelope(c, map[string]any{"heartbeats": []any{validHeartbeat(h.today())}})
	if got := h.signed("DELETE", "/v1/refrax/installs/"+c.id, c, body).Code; got != http.StatusBadRequest {
		t.Fatalf("a delete with heartbeats: %d", got)
	}
	other := newTestClient(t)
	h.register(other)
	body = h.envelope(other, nil)
	if got := h.signed("DELETE", "/v1/refrax/installs/"+c.id, other, body).Code; got != http.StatusUnauthorized {
		t.Fatalf("deleting another install: %d", got)
	}
}

// ---- Crash reports ----

func testCrashContext() map[string]any {
	context := basicInfo()
	context["installLocation"] = "applications"
	context["previousVersion"] = "0.33"
	context["consecutiveLaunchCrashes"] = 0
	context["secondsSinceLaunch"] = 81.5
	context["fields"] = map[string]any{"engines": "webkit-621, chromium-142", "secret": "dropped"}
	return context
}

type crashResponse struct{ *httptest.ResponseRecorder }

func (r crashResponse) id(t *testing.T) string {
	t.Helper()
	if r.Code != http.StatusCreated {
		t.Fatalf("crash report: %d %s", r.Code, r.Body)
	}
	var answer struct{ ID string }
	_ = json.Unmarshal(r.Body.Bytes(), &answer)
	return answer.ID
}

func (h *harness) crashBody(c *testClient, context map[string]any, files map[string]string) ([]byte, string) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", `form-data; name="envelope"`)
	header.Set("Content-Type", "application/json")
	part, _ := writer.CreatePart(header)
	_, _ = part.Write(h.envelope(c, map[string]any{"context": context}))
	for name, content := range files {
		part, _ := writer.CreateFormFile("file", name)
		_, _ = part.Write([]byte(content))
	}
	_ = writer.Close()
	return body.Bytes(), writer.FormDataContentType()
}

func (h *harness) postCrash(c *testClient, context map[string]any, files map[string]string) crashResponse {
	body, contentType := h.crashBody(c, context, files)
	return crashResponse{h.do("POST", "/v1/refrax/crash-reports", body, map[string]string{
		InstallHeader: c.id, SignatureHeader: c.sign(h.t, body), "Content-Type": contentType,
	})}
}

func TestCrashReportIsStoredAndFetched(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	ips := "{\"app_name\":\"Refrax\"}\n{\"crashReporterKey\":\"00000000-0000-0000-0000-000000000000\"}"
	id := h.postCrash(c, testCrashContext(), map[string]string{"Refrax-2026-10-05-001046.ips": ips}).id(t)

	var list []CrashReport
	h.adminJSON("/admin/refrax/crashes", &list)
	if len(list) != 1 || list[0].ID != id || list[0].Install != c.id {
		t.Fatalf("list %+v", list)
	}
	var context storedContext
	_ = json.Unmarshal(list[0].Context, &context)
	if context.InstallLocation != "applications" || context.Fields["engines"] != "webkit-621, chromium-142" || context.Fields["secret"] != nil {
		t.Fatalf("context %+v", context)
	}
	file := h.adminGet("/admin/refrax/crashes/" + id + "/files/Refrax-2026-10-05-001046.ips")
	if file.Code != http.StatusOK || file.Body.String() != ips {
		t.Fatalf("file: %d %q", file.Code, file.Body)
	}
	for _, missing := range []string{"/admin/refrax/crashes/" + id + "/files/other.ips", "/admin/refrax/crashes/" + strings.Repeat("0", 32), "/admin/sevoflurane/crashes/" + id} {
		if got := h.adminGet(missing).Code; got != http.StatusNotFound {
			t.Errorf("%s: %d", missing, got)
		}
	}
}

func TestCrashReportLimits(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	cases := map[string]struct {
		files  map[string]string
		status int
	}{
		"too many files":  {map[string]string{"a.ips": "1", "b.ips": "2", "c.ips": "3"}, http.StatusRequestEntityTooLarge},
		"over the bytes":  {map[string]string{"a.ips": strings.Repeat("x", 4097)}, http.StatusRequestEntityTooLarge},
		"a dash-led name": {map[string]string{"-rf.ips": "1"}, http.StatusBadRequest},
		"no files":        {map[string]string{}, http.StatusBadRequest},
	}
	for name, tc := range cases {
		if got := h.postCrash(c, testCrashContext(), tc.files).Code; got != tc.status {
			t.Errorf("%s: %d, want %d", name, got, tc.status)
		}
	}
	bad := testCrashContext()
	bad["installLocation"] = "/Applications/Refrax.app"
	if got := h.postCrash(c, bad, map[string]string{"a.ips": "1"}).Code; got != http.StatusBadRequest {
		t.Errorf("a path as install location: %d", got)
	}
	// A body changed after signing does not verify.
	body, contentType := h.crashBody(c, testCrashContext(), map[string]string{"a.ips": "1"})
	signature := c.sign(t, body)
	body = bytes.Replace(body, []byte("\r\n1\r\n"), []byte("\r\n2\r\n"), 1)
	if got := h.do("POST", "/v1/refrax/crash-reports", body, map[string]string{InstallHeader: c.id, SignatureHeader: signature, "Content-Type": contentType}).Code; got != http.StatusUnauthorized {
		t.Fatalf("an altered body: %d", got)
	}
	h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).id(t)
	h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).id(t)
	if got := h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).Code; got != http.StatusTooManyRequests {
		t.Fatalf("third report in a day: %d", got)
	}
	if entries, _ := os.ReadDir(filepath.Join(h.svc.CrashDir, "refrax")); len(entries) != 2 {
		t.Fatalf("%d report directories, want the 2 accepted", len(entries))
	}
}

// ---- Admin ----

func TestStatsCountActivesPerTrustAndShares(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	day := func(back int) string { return h.now.AddDate(0, 0, -back).Format(dayLayout) }
	a, b, d, r := newTestClient(t), newTestClient(t), newTestClient(t), newTestClient(t)
	for _, c := range []*testClient{a, b, d, r} {
		h.register(c)
	}
	_ = h.svc.Store.saveInstall(ctx, "refrax", a.id, a.der, identity.Verdict{Trust: identity.TrustAttested}, h.now)
	_ = h.svc.Store.saveInstall(ctx, "refrax", r.id, r.der, identity.Verdict{Trust: identity.TrustReregistered}, h.now)

	old := validHeartbeat(day(1))
	old["appVersion"] = "0.33"
	answerOf(t, h.postHeartbeats(a, validHeartbeat(day(0)), old))
	beat := validHeartbeat(day(3))
	beat["properties"] = map[string]any{"chromiumInstalled": false}
	beat["activeDays7"] = 1
	answerOf(t, h.postHeartbeats(b, beat))
	// d was last seen 8 days ago: monthly, not weekly. The batch limit on
	// age is 8 days, so this is the oldest heartbeat it can send.
	answerOf(t, h.postHeartbeats(d, validHeartbeat(day(8))))
	answerOf(t, h.postHeartbeats(r, validHeartbeat(day(0))))

	var stats Stats
	h.adminJSON("/admin/refrax/stats?day="+day(0), &stats)
	actives := stats.Actives
	if actives["dau"]["attested"] != 1 || actives["dau"]["reregistered"] != 1 || actives["dau"]["unverified"] != 0 ||
		actives["wau"]["unverified"] != 1 || actives["mau"]["unverified"] != 2 || actives["mau"]["attested"] != 1 {
		t.Fatalf("actives %v", actives)
	}
	// The default sample leaves reregistered installs out.
	if stats.Sample != 3 || stats.Versions["0.34"] != 3 || stats.Versions["0.33"] != 0 {
		t.Fatalf("sample %d versions %v", stats.Sample, stats.Versions)
	}
	installed := stats.Properties["chromiumInstalled"]
	if installed["true"].Installs != 2 || installed["false"].Installs != 1 || installed["false"].Share < 0.33 || installed["false"].Share > 0.34 {
		t.Fatalf("properties %v", stats.Properties)
	}
	if stats.ActiveDays7["3"] != 1 || stats.ActiveDays7["1"] != 1 || len(stats.ActiveDays7) != 2 {
		t.Fatalf("activeDays7 %v", stats.ActiveDays7)
	}
	// Without a day, the newest local day any heartbeat carries: a client
	// in UTC+14 is already a day ahead of the server.
	stats = Stats{}
	h.adminJSON("/admin/refrax/stats", &stats)
	if stats.Day != day(0) || stats.Actives["dau"]["attested"] != 1 {
		t.Fatalf("default day %s %v", stats.Day, stats.Actives)
	}
	ahead := newTestClient(t)
	h.register(ahead)
	answerOf(t, h.postHeartbeats(ahead, validHeartbeat(day(-1))))
	h.adminJSON("/admin/refrax/stats", &stats)
	if stats.Day != day(-1) {
		t.Fatalf("default day %s with a client a day ahead", stats.Day)
	}
	h.adminJSON("/admin/refrax/stats?day="+day(0)+"&trust=attested", &stats)
	if stats.Sample != 1 {
		t.Fatalf("attested sample %d", stats.Sample)
	}

	var apps []appSummary
	h.adminJSON("/admin/apps", &apps)
	if len(apps) != 2 || apps[0].App != "refrax" || apps[0].Heartbeats != 6 || apps[0].Installs["unverified"] != 3 {
		t.Fatalf("apps %+v", apps)
	}
	var history []historyRow
	h.adminJSON("/admin/refrax/history?days=30", &history)
	if len(history) == 0 {
		t.Fatal("no history")
	}
}

func TestAttestedInstallShowsItsKeyPolicy(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	ctx := context.Background()
	policy := &identity.KeyPolicy{OS: "27.0", Platform: "macosx", SignNeedsSecureBoot: true, ACL: map[string]string{"osgn": "rsec([6]=1)"}}
	v := identity.Verdict{Trust: identity.TrustAttested, Env: identity.AttestEnvProduction, Policy: policy}
	if err := h.svc.Store.saveInstall(ctx, "refrax", c.id, c.der, v, h.now); err != nil {
		t.Fatal(err)
	}
	var detail installDetail
	h.adminJSON("/admin/refrax/installs/"+c.id, &detail)
	if detail.Trust != "attested" || detail.AttestEnv != "production" || !strings.Contains(string(detail.Policy), "rsec([6]=1)") {
		t.Fatalf("detail %+v %s", detail, detail.Policy)
	}
	// Registering again without App Attest clears what it no longer proves.
	_ = h.svc.Store.saveInstall(ctx, "refrax", c.id, c.der, identity.Verdict{Trust: identity.TrustDevice}, h.now)
	detail = installDetail{}
	h.adminJSON("/admin/refrax/installs/"+c.id, &detail)
	if detail.Trust != "device" || detail.Policy != nil || detail.AttestEnv != "" {
		t.Fatalf("stale policy %+v", detail)
	}
	// An operator's verdict survives re-registration.
	_, _ = h.svc.Store.db.Exec(`UPDATE installs SET trust = 'blocked' WHERE id = ?`, c.id)
	if got := h.registerIn("refrax", c, nil).Code; got != http.StatusForbidden {
		t.Fatalf("a blocked install registered: %d", got)
	}
}

func TestAdminAddressMustBeLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:9131", "[::1]:9131", "localhost:9131", "127.0.0.2:1"} {
		if err := LoopbackOnly(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:9131", ":9131", "10.0.0.1:9131", "[::]:9131", "example.com:9131", "9131"} {
		if err := LoopbackOnly(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestAPIAnswersCarryTheirOwnPolicy(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/v1/refrax/challenge", "/healthz", "/v1/nonesuch/challenge"} {
		headers := h.do("GET", path, nil, nil).Header()
		if headers.Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" ||
			headers.Get("Cache-Control") != "no-store" || headers.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: %v", path, headers)
		}
	}
}

// ---- Retention ----

func TestRetentionRollsUpAndForgets(t *testing.T) {
	h := newHarness(t)
	c, quiet := newTestClient(t), newTestClient(t)
	h.register(c)
	h.register(quiet)
	h.postHeartbeats(c, validHeartbeat(h.today()))
	id := h.postCrash(c, testCrashContext(), map[string]string{"a.ips": "1"}).id(t)
	h.postHeartbeats(quiet, validHeartbeat(h.today()))

	// 181 days on: the crash report is gone, the heartbeats stay.
	h.now = h.now.AddDate(0, 0, 181)
	h.postHeartbeats(c, validHeartbeat(h.today()))
	if err := h.svc.retentionPass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := h.count(`SELECT COUNT(*) FROM crash_reports`); n != 0 {
		t.Fatalf("%d crash reports past retention", n)
	}
	if _, err := os.Stat(filepath.Join(h.svc.CrashDir, "refrax", id)); !os.IsNotExist(err) {
		t.Fatalf("crash files past retention: %v", err)
	}
	if n := h.count(`SELECT COUNT(*) FROM heartbeats`); n != 3 {
		t.Fatalf("%d heartbeats", n)
	}

	// 401 days after the first: its day is a count, and the install silent
	// since then is forgotten.
	h.now = h.now.AddDate(0, 0, 220)
	if err := h.svc.retentionPass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := h.count(`SELECT COUNT(*) FROM heartbeats`); n != 1 {
		t.Fatalf("%d heartbeats past retention", n)
	}
	if n := h.count(`SELECT installs FROM daily_actives WHERE trust = 'unverified'`); n != 2 {
		t.Fatalf("rolled-up actives %d", n)
	}
	if n := h.count(`SELECT COUNT(*) FROM installs WHERE id = ?`, quiet.id); n != 0 {
		t.Fatal("a silent install outlived retention")
	}
	if n := h.count(`SELECT COUNT(*) FROM installs WHERE id = ?`, c.id); n != 1 {
		t.Fatal("an active install was forgotten")
	}
}

// ---- Config ----

func TestConfigChecks(t *testing.T) {
	for name, bad := range map[string]string{
		"no apps":      `{"apps": {}}`,
		"slug":         `{"apps": {"Refrax!": {"app_attest_id": "TEAMID1234.a.b"}}}`,
		"app id":       `{"apps": {"refrax": {"app_attest_id": "website.refrax.browser"}}}`,
		"type":         `{"apps": {"refrax": {"app_attest_id": "TEAMID1234.a.b", "properties": {"x": "date"}}}}`,
		"reserved":     `{"apps": {"refrax": {"app_attest_id": "TEAMID1234.a.b", "crash_context": {"os": "string"}}}}`,
		"missing .p8":  `{"apps": {"refrax": {"app_attest_id": "TEAMID1234.a.b", "device_check": {"key_path": "/nonexistent.p8", "key_id": "K"}}}}`,
		"not JSON":     `apps:`,
		"bit name":     `{"apps": {"refrax": {"app_attest_id": "TEAMID1234.a.b", "device_check": {"registered_bit": "2"}}}}`,
		"shared bit":   `{"apps": {"a": {"app_attest_id": "TEAMID1234.a.b", "device_check": {"registered_bit": "bit1"}}, "b": {"app_attest_id": "52K336H235.a.c", "device_check": {"registered_bit": "bit1"}}}}`,
		"crash budget": `{"apps": {"refrax": {"app_attest_id": "TEAMID1234.a.b", "crash_reports": {"max_bytes": 99999999}}}}`,
	} {
		config, err := ParseConfig([]byte(bad))
		if err == nil {
			_, err = New(nil, config, t.TempDir())
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	config, err := ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	sevo := config.Apps["sevoflurane"]
	if sevo.TeamID != "52K336H235" || sevo.CrashReports.MaxFiles != defaultCrashFiles || sevo.CrashReports.PerInstallPerDay != defaultCrashesPerDay {
		t.Fatalf("defaults %+v", sevo)
	}
}

package service

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/kageroumado/digoxin/server/identity/identitytest"
)

// TestAdminAnswersLoopbackNamesOnly: a page whose host name rebinds to
// 127.0.0.1 reaches the listener but not the API.
func TestAdminAnswersLoopbackNamesOnly(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		host, origin string
		want         int
	}{
		{"127.0.0.1:9131", "", http.StatusOK},
		{"localhost:9131", "", http.StatusOK},
		{"[::1]:9131", "", http.StatusOK},
		{"localhost", "", http.StatusOK},
		{"attacker.example", "", http.StatusForbidden},
		{"attacker.example:9131", "", http.StatusForbidden},
		{"127.0.0.1:9131", "http://attacker.example", http.StatusForbidden},
		{"localhost:9131", "null", http.StatusForbidden},
	}
	for _, c := range cases {
		request := httptest.NewRequest("GET", "/admin/apps", nil)
		request.Host = c.host
		if c.origin != "" {
			request.Header.Set("Origin", c.origin)
		}
		recorder := httptest.NewRecorder()
		h.admin.ServeHTTP(recorder, request)
		if recorder.Code != c.want {
			t.Errorf("Host %q Origin %q: %d, want %d", c.host, c.origin, recorder.Code, c.want)
		}
	}
}

func TestDeletedRowsAreOverwritten(t *testing.T) {
	h := newHarness(t)
	var on int
	if err := h.svc.Store.db.QueryRow(`PRAGMA secure_delete`).Scan(&on); err != nil || on != 1 {
		t.Fatalf("secure_delete %d %v", on, err)
	}
}

func TestConfigRefusesUnknownFieldsAndOpenKeys(t *testing.T) {
	if _, err := ParseConfig([]byte(`{"apps": {"a": {"app_attest_id": "52K336H235.a.b", "crash_report": {}}}}`)); err == nil {
		t.Fatal("a misspelled field was accepted")
	}
	if _, err := ParseConfig([]byte(`{"client_ip_headers": "CF-Connecting-IP", "apps": {"a": {"app_attest_id": "52K336H235.a.b"}}}`)); err == nil {
		t.Fatal("a misspelled top-level field was accepted")
	}
	_, key := identitytest.NewFakeApple(t)
	config := func() error {
		_, err := ParseConfig([]byte(fmt.Sprintf(`{"apps": {"a": {"app_attest_id": "52K336H235.a.b",
			"device_check": {"key_path": %q, "key_id": "K"}}}}`, key)))
		return err
	}
	for mode, ok := range map[os.FileMode]bool{0o600: true, 0o640: true, 0o644: false, 0o604: false} {
		_ = os.Chmod(key, mode)
		if err := config(); (err == nil) != ok {
			t.Errorf("a key with mode %o: %v", mode, err)
		}
	}
}

func TestBackupsAreNeverReadableByOthers(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(t.TempDir(), "copy.db")
	if err := h.svc.Store.Backup(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o640 || info.Size() == 0 {
		t.Fatalf("backup %v %v", info.Mode(), err)
	}
	if err := h.svc.Store.Backup(t.Context(), target); err == nil {
		t.Fatal("a backup overwrote an existing file")
	}
}

package service

import (
	"fmt"
	"net/http"
	"testing"
)

const eventsConfig = `{"apps": {
	"refrax": {"app_attest_id": "52K336H235.website.refrax.browser"},
	"spectra": {"events": ["view", "start", "complete"]}
}}`

func TestEventsCountByDayNameAndLabel(t *testing.T) {
	h := newHarnessWith(t, eventsConfig)
	post := func(body string) int {
		return h.do("POST", "/v1/spectra/events", []byte(body), nil).Code
	}
	for _, body := range []string{
		`{"name":"view","label":"raads-r"}`, `{"name":"start","label":"raads-r"}`,
		`{"name":"complete","label":"raads-r"}`, `{"name":"complete","label":"raads-r"}`,
		`{"name":"view"}`,
	} {
		if code := post(body); code != http.StatusNoContent {
			t.Fatalf("%s: %d", body, code)
		}
	}
	var got struct {
		From, To string
		Events   []EventCount
	}
	h.adminJSON("/admin/spectra/events?days=7", &got)
	want := []EventCount{
		{Day: "2026-10-05", Name: "complete", Label: "raads-r", Count: 2},
		{Day: "2026-10-05", Name: "start", Label: "raads-r", Count: 1},
		{Day: "2026-10-05", Name: "view", Label: "", Count: 1},
		{Day: "2026-10-05", Name: "view", Label: "raads-r", Count: 1},
	}
	if fmt.Sprint(got.Events) != fmt.Sprint(want) {
		t.Fatalf("events %v, want %v", got.Events, want)
	}
	if got.From != "2026-09-29" || got.To != "2026-10-05" {
		t.Fatalf("window %s..%s", got.From, got.To)
	}
}

func TestEventsRefuseWhatTheAllowlistLacks(t *testing.T) {
	h := newHarnessWith(t, eventsConfig)
	for body, code := range map[string]int{
		`{"name":"delete","label":"raads-r"}`: http.StatusBadRequest,
		`{"name":"view","label":"RAADS R"}`:   http.StatusBadRequest,
		`not json`:                            http.StatusBadRequest,
	} {
		if got := h.do("POST", "/v1/spectra/events", []byte(body), nil).Code; got != code {
			t.Errorf("%s: %d, want %d", body, got, code)
		}
	}
	for i := 0; i < maxLabelsPerDay; i++ {
		body := fmt.Sprintf(`{"name":"view","label":"t%d"}`, i)
		if code := h.do("POST", "/v1/spectra/events", []byte(body), nil).Code; code != http.StatusNoContent {
			t.Fatalf("label %d: %d", i, code)
		}
	}
	if code := h.do("POST", "/v1/spectra/events", []byte(`{"name":"view","label":"one-too-many"}`), nil).Code; code != http.StatusBadRequest {
		t.Fatalf("label past the cap: %d", code)
	}
	if code := h.do("POST", "/v1/spectra/events", []byte(`{"name":"view","label":"t3"}`), nil).Code; code != http.StatusNoContent {
		t.Fatalf("a known label past the cap: %d", code)
	}
}

func TestWebPageHasNoInstallRoutesAndAppsNoEvents(t *testing.T) {
	h := newHarnessWith(t, eventsConfig)
	for _, path := range []string{"/v1/spectra/challenge", "/v1/spectra/active"} {
		if code := h.do("GET", path, nil, nil).Code; code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, code)
		}
	}
	if code := h.do("POST", "/v1/refrax/events", []byte(`{"name":"view"}`), nil).Code; code != http.StatusNotFound {
		t.Errorf("events of an attested app: %d, want 404", code)
	}
	for _, raw := range []string{
		`{"apps": {"spectra": {}}}`,
		`{"apps": {"spectra": {"events": ["view"], "properties": {"x": "bool"}}}}`,
		`{"apps": {"spectra": {"events": ["view", "view"]}}}`,
	} {
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", raw)
		}
	}
}

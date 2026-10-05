package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kageroumado/digoxin/server/identity"
	"github.com/kageroumado/digoxin/server/identity/identitytest"
)

// registerFrom registers c from a peer address, with extra headers.
func (h *harness) registerFrom(app, peer string, c *testClient, extra map[string]any, headers ...string) *httptest.ResponseRecorder {
	h.t.Helper()
	fields := map[string]any{"version": "0.34", "challenge": h.challenge(app), "public_key": base64.StdEncoding.EncodeToString(c.der)}
	for k, v := range extra {
		fields[k] = v
	}
	body, _ := json.Marshal(fields)
	request := httptest.NewRequest("POST", "/v1/"+app+"/installs", bytes.NewReader(body))
	request.RemoteAddr = peer
	request.Header.Set(InstallHeader, c.id)
	request.Header.Set(SignatureHeader, c.sign(h.t, body))
	for i := 0; i+1 < len(headers); i += 2 {
		request.Header.Set(headers[i], headers[i+1])
	}
	recorder := httptest.NewRecorder()
	h.mux.ServeHTTP(recorder, request)
	return recorder
}

func trustIn(response *httptest.ResponseRecorder) string {
	var answer struct{ Trust string }
	_ = json.Unmarshal(response.Body.Bytes(), &answer)
	return answer.Trust
}

// slowAppleConfig is an apps file whose DeviceCheck answers after delay.
func slowAppleConfig(t *testing.T, delay time.Duration, bit string) string {
	apple, keyPath := identitytest.NewFakeApple(t)
	apple.Delay = delay
	return fmt.Sprintf(`{"apps": {
		"refrax": {"app_attest_id": "52K336H235.website.refrax.browser",
			"device_check": {"key_path": %q, "key_id": %q, "url": %q, "registered_bit": %q}},
		"sevoflurane": {"app_attest_id": "52K336H235.glass.kagerou.sevoflurane",
			"device_check": {"key_path": %q, "key_id": %q, "url": %q}}}}`,
		keyPath, identitytest.KeyID, apple.URL, bit, keyPath, identitytest.KeyID, apple.URL)
}

// TestClientHeadersCountOnlyFromTrustedProxies: a client that sends its
// own CF-Connecting-IP does not get a new address per request.
func TestClientHeadersCountOnlyFromTrustedProxies(t *testing.T) {
	h := newHarness(t)
	accepted := 0
	for i := 0; i < 20; i++ {
		if h.registerFrom("refrax", "203.0.113.9:5555", newTestClient(t), nil, "CF-Connecting-IP", fmt.Sprintf("198.51.100.%d", i)).Code == http.StatusCreated {
			accepted++
		}
	}
	if accepted != installsPerDay {
		t.Fatalf("spoofed headers, no proxy configured: %d accepted", accepted)
	}

	behind := newHarnessWith(t, `{"client_ip_header": "CF-Connecting-IP", "trusted_proxies": ["127.0.0.1/32", "::1/128"],
		"apps": {"refrax": {"app_attest_id": "52K336H235.website.refrax.browser"}}}`)
	accepted = 0
	for i := 0; i < 20; i++ {
		if behind.registerFrom("refrax", "203.0.113.9:5555", newTestClient(t), nil, "CF-Connecting-IP", fmt.Sprintf("198.51.100.%d", i)).Code == http.StatusCreated {
			accepted++
		}
	}
	if accepted != installsPerDay {
		t.Fatalf("spoofed headers from outside the proxy: %d accepted", accepted)
	}
	// Through the proxy, the header names the client.
	for i := 0; i < 3; i++ {
		if got := behind.registerFrom("refrax", "127.0.0.1:40000", newTestClient(t), nil, "CF-Connecting-IP", fmt.Sprintf("192.0.2.%d", i)).Code; got != http.StatusCreated {
			t.Fatalf("client %d through the proxy: %d", i, got)
		}
	}
}

func TestIPv6ClientsAreLimitedBySubnet(t *testing.T) {
	h := newHarness(t)
	accepted := 0
	for i := 0; i < 50; i++ {
		if h.registerFrom("refrax", fmt.Sprintf("[2001:db8::%x]:1234", i+1), newTestClient(t), nil).Code == http.StatusCreated {
			accepted++
		}
	}
	if accepted != installsPerDay {
		t.Fatalf("%d new installs from one /64", accepted)
	}
}

// TestConcurrentRegistrationsTakeTheirSlotsFirst: registrations waiting on
// Apple at once cannot all fit in the address's last slot.
func TestConcurrentRegistrationsTakeTheirSlotsFirst(t *testing.T) {
	h := newHarnessWith(t, slowAppleConfig(t, 150*time.Millisecond, "bit1"))
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 30; i++ {
		c := newTestClient(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			code := h.registerFrom("refrax", "198.51.100.7:1", c, map[string]any{"device_check": identitytest.Token(c.id, 1)}).Code
			mu.Lock()
			if code == http.StatusCreated {
				accepted++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if accepted != installsPerDay {
		t.Fatalf("%d concurrent new installs from one address", accepted)
	}
}

// TestAFailedRegistrationGivesItsSlotBack: Apple failing costs the address
// nothing; a registration that succeeded is never refunded.
func TestAFailedRegistrationGivesItsSlotBack(t *testing.T) {
	h := newHarnessWith(t, `{"apps": {"refrax": {"app_attest_id": "52K336H235.website.refrax.browser",
		"device_check": {"key_path": "`+writeKey(t)+`", "key_id": "K", "url": "http://127.0.0.1:1"}}}}`)
	for i := 0; i < installsPerDay+2; i++ {
		if got := h.registerFrom("refrax", "198.51.100.7:1", newTestClient(t), map[string]any{"device_check": identitytest.Token("mac", i)}).Code; got != http.StatusServiceUnavailable {
			t.Fatalf("Apple unreachable: %d", got)
		}
	}
	for i := 0; i < installsPerDay; i++ {
		if got := h.registerFrom("refrax", "198.51.100.7:1", newTestClient(t), nil).Code; got != http.StatusCreated {
			t.Fatalf("registration %d after Apple's failures: %d", i, got)
		}
	}
	if got := h.registerFrom("refrax", "198.51.100.7:1", newTestClient(t), nil).Code; got != http.StatusTooManyRequests {
		t.Fatalf("one past the cap: %d", got)
	}
}

// TestOneTokenForManyKeysCountsOnce: a DeviceCheck token copied behind
// several keys proves one device, even in an app without a bit.
func TestOneTokenForManyKeysCountsOnce(t *testing.T) {
	h := newHarnessWith(t, slowAppleConfig(t, 0, "bit1"))
	token := identitytest.Token("one genuine Mac", 1)
	tiers := map[string]int{}
	for i := 0; i < 5; i++ {
		tiers[trustIn(h.registerFrom("sevoflurane", fmt.Sprintf("203.0.113.%d:1", i+1), newTestClient(t), map[string]any{"device_check": token}))]++
	}
	if tiers[identity.TrustDevice] != 1 || tiers[identity.TrustUnverified] != 4 {
		t.Fatalf("five keys, one token: %v", tiers)
	}
}

func TestConcurrentKeysOnOneTokenAreOneDevice(t *testing.T) {
	h := newHarnessWith(t, slowAppleConfig(t, 150*time.Millisecond, "bit1"))
	token := identitytest.Token("one genuine Mac", 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	tiers := map[string]int{}
	for i := 0; i < 5; i++ {
		c := newTestClient(t)
		peer := fmt.Sprintf("203.0.113.%d:1", i+1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			trust := trustIn(h.registerFrom("refrax", peer, c, map[string]any{"device_check": token}))
			mu.Lock()
			tiers[trust]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if tiers[identity.TrustDevice] != 1 || tiers[identity.TrustUnverified] != 4 {
		t.Fatalf("five concurrent keys, one token: %v", tiers)
	}
}

// TestOneKeyCannotBelongToTwoApps: two apps registering one key at once,
// the second to save gets 409 and the row stays the first app's.
func TestOneKeyCannotBelongToTwoApps(t *testing.T) {
	h := newHarnessWith(t, slowAppleConfig(t, 200*time.Millisecond, "bit1"))
	c := newTestClient(t)
	var wg sync.WaitGroup
	var slow int
	wg.Add(1)
	go func() {
		defer wg.Done()
		slow = h.registerFrom("sevoflurane", "203.0.113.9:1", c, map[string]any{"device_check": identitytest.Token("mac", 1)}).Code
	}()
	time.Sleep(50 * time.Millisecond)
	fast := h.registerFrom("refrax", "203.0.113.9:1", c, nil).Code
	wg.Wait()
	var app string
	_ = h.svc.Store.db.QueryRow(`SELECT app FROM installs WHERE id = ?`, c.id).Scan(&app)
	if fast != http.StatusCreated || slow != http.StatusConflict || app != "refrax" {
		t.Fatalf("refrax %d, sevoflurane %d, row belongs to %q", fast, slow, app)
	}
}

func TestReregistrationIsLimitedPerInstall(t *testing.T) {
	h := newHarness(t)
	c := newTestClient(t)
	h.register(c)
	for i := 0; i < reregistrationsPerDay; i++ {
		if got := h.registerFrom("refrax", fmt.Sprintf("203.0.113.%d:1", i), c, nil).Code; got != http.StatusCreated {
			t.Fatalf("registering again %d: %d", i+1, got)
		}
	}
	if got := h.registerFrom("refrax", "203.0.113.200:1", c, nil).Code; got != http.StatusTooManyRequests {
		t.Fatalf("registering again past the allowance: %d", got)
	}
	h.now = h.now.Add(installsWindow + time.Minute)
	if got := h.registerFrom("refrax", "203.0.113.200:1", c, nil).Code; got != http.StatusCreated {
		t.Fatalf("a day later: %d", got)
	}
}

// writeKey writes a DeviceCheck .p8 key and answers its path.
func writeKey(t *testing.T) string {
	t.Helper()
	_, path := identitytest.NewFakeApple(t)
	return path
}

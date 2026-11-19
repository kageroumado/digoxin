package service

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

const proxiedConfig = `{"client_ip_header": "CF-Connecting-IP", "trusted_proxies": ["127.0.0.1/32"],
	"apps": {"refrax": {"app_attest_id": "52K336H235.website.refrax.browser"}}}`

// TestAnAllocationSharesItsDailyInstalls: rotating the /64 inside one /48 stops
// at the allocation's limit, records none of the /64s past it, and leaves
// another /48 alone.
func TestAnAllocationSharesItsDailyInstalls(t *testing.T) {
	h := newHarnessWith(t, proxiedConfig)
	from := func(address string) int {
		return h.registerFrom("refrax", "127.0.0.1:5555", newTestClient(t), nil, "CF-Connecting-IP", address).Code
	}
	accepted := 0
	for n := 0; n < allocationInstallsPerDay+15; n++ {
		if from(fmt.Sprintf("2001:db8:1:%x::1", n+1)) == http.StatusCreated {
			accepted++
		}
	}
	if accepted != allocationInstallsPerDay {
		t.Fatalf("%d new installs from one /48, want %d", accepted, allocationInstallsPerDay)
	}
	if got := from("2001:db8:2::1"); got != http.StatusCreated {
		t.Fatalf("another /48: %d", got)
	}
	if n := h.count(`SELECT COUNT(*) FROM installs`); n != allocationInstallsPerDay+1 {
		t.Fatalf("%d installs stored, want %d", n, allocationInstallsPerDay+1)
	}
}

// TestIdleUnverifiedInstallsAreForgotten: an unverified install that never sent
// anything goes after IdleInstallRetention; one with a heartbeat stays.
func TestIdleUnverifiedInstallsAreForgotten(t *testing.T) {
	h := newHarness(t)
	idle, active := newTestClient(t), newTestClient(t)
	h.register(idle)
	h.register(active)
	h.postHeartbeats(active, validHeartbeat(h.today()))

	h.now = h.now.AddDate(0, 0, 3)
	if err := h.svc.retentionPass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := h.count(`SELECT COUNT(*) FROM installs`); n != 2 {
		t.Fatalf("%d installs three days in, want 2", n)
	}
	h.now = h.now.AddDate(0, 0, 6)
	if err := h.svc.retentionPass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := h.count(`SELECT COUNT(*) FROM installs WHERE id = ?`, idle.id); n != 0 {
		t.Fatal("an install that never sent anything outlived its retention")
	}
	if n := h.count(`SELECT COUNT(*) FROM installs WHERE id = ?`, active.id); n != 1 {
		t.Fatal("an install with a heartbeat was forgotten")
	}
}

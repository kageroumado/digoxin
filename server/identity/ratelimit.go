package identity

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Limiter counts what one key did inside a sliding window.
type Limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	seen   map[string][]time.Time
	swept  time.Time
}

func NewLimiter(limit int, window time.Duration) *Limiter {
	return &Limiter{limit: limit, window: window, seen: make(map[string][]time.Time)}
}

// Admit records an attempt and answers whether it is within the limit.
// The attempt is recorded at now; Refund with the same now takes it back.
func (l *Limiter) Admit(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.prune(key, now)
	if len(kept) >= l.limit {
		l.store(key, kept)
		return false
	}
	l.seen[key] = append(kept, now)
	return true
}

// Refund takes back one attempt Admit recorded at `at`, for work that
// failed before it spent what the limit protects.
func (l *Limiter) Refund(key string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	times := l.seen[key]
	for i := len(times) - 1; i >= 0; i-- {
		if times[i].Equal(at) {
			l.store(key, append(times[:i:i], times[i+1:]...))
			return
		}
	}
}

// Room answers whether Admit would succeed, recording nothing.
func (l *Limiter) Room(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.prune(key, now)
	l.store(key, kept)
	return len(kept) < l.limit
}

// store keeps a key's attempts, and forgets a key that has none, so asking
// about addresses that never act costs no memory.
func (l *Limiter) store(key string, times []time.Time) {
	if len(times) == 0 {
		delete(l.seen, key)
		return
	}
	l.seen[key] = times
}

// keys is how many keys the limiter holds, for tests.
func (l *Limiter) keys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.seen)
}

// prune answers the key's attempts still inside the window. Keys nobody
// has used in a window leave rather than accumulate; that sweep runs at
// most once a window. The caller holds mu.
func (l *Limiter) prune(key string, now time.Time) []time.Time {
	since := now.Add(-l.window)
	kept := l.seen[key][:0:0]
	for _, at := range l.seen[key] {
		if at.After(since) {
			kept = append(kept, at)
		}
	}
	if now.Sub(l.swept) > l.window {
		for other, times := range l.seen {
			if other != key && (len(times) == 0 || times[len(times)-1].Before(since)) {
				delete(l.seen, other)
			}
		}
		l.swept = now
	}
	return kept
}

// ClientAddress decides which address a request comes from, for rate
// limits. The peer's address is the client's unless the peer is a trusted
// proxy and Header is set; then the header names the client. A header
// from anyone else is ignored, since any client can send one.
type ClientAddress struct {
	// Header is the request header a trusted proxy writes the client's
	// address into, such as CF-Connecting-IP or X-Forwarded-For. Empty:
	// the peer is the client.
	Header string
	// TrustedProxies are the peers whose Header is believed.
	TrustedProxies []netip.Prefix
}

// ParseClientAddress builds a ClientAddress from a header name and CIDR
// strings.
func ParseClientAddress(header string, trusted []string) (ClientAddress, error) {
	c := ClientAddress{Header: strings.TrimSpace(header)}
	for _, cidr := range trusted {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return ClientAddress{}, fmt.Errorf("trusted proxy %q: %w", cidr, err)
		}
		c.TrustedProxies = append(c.TrustedProxies, prefix.Masked())
	}
	if c.Header != "" && len(c.TrustedProxies) == 0 {
		return ClientAddress{}, fmt.Errorf("client IP header %s needs trusted proxies, or anyone can set it", c.Header)
	}
	return c, nil
}

func (c ClientAddress) trusted(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range c.TrustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Key answers the rate-limit key of the request's client: an IPv4 address,
// or an IPv6 address's /64, which is what one subscriber is handed and
// can rotate through at will.
func (c ClientAddress) Key(r *http.Request) string {
	addr := c.client(r)
	if !addr.IsValid() {
		return r.RemoteAddr
	}
	return LimitKey(addr)
}

// LimitKey is an address as rate limits count it: IPv4 whole, IPv6 by /64.
func LimitKey(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, _ := addr.WithZone("").Prefix(64)
	return prefix.String()
}

func (c ClientAddress) client(r *http.Request) netip.Addr {
	peer := peerAddr(r.RemoteAddr)
	if c.Header == "" || !peer.IsValid() || !c.trusted(peer) {
		return peer
	}
	values := r.Header.Values(c.Header)
	if len(values) == 0 {
		return peer
	}
	// A list (X-Forwarded-For) grows rightward with each proxy: the client
	// is the rightmost address no trusted proxy added.
	hops := strings.Split(strings.Join(values, ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer
		}
		if i == 0 || !c.trusted(addr) {
			return addr
		}
	}
	return peer
}

func peerAddr(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

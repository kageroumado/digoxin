package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Two apps register one Mac at once: both read the bits clear, then each
// sets its own. Apple keeps a bit an update omits, so both must survive.
func TestConcurrentAppsKeepEachOthersBit(t *testing.T) {
	var mu sync.Mutex
	var bits [2]bool
	var queried int
	bothQueried := make(chan struct{})
	apple := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/query_two_bits" {
			mu.Lock()
			snapshot := bits
			queried++
			if queried == 2 {
				close(bothQueried)
			}
			mu.Unlock()
			select {
			case <-bothQueried:
			case <-r.Context().Done():
				return
			}
			json.NewEncoder(w).Encode(map[string]bool{"bit0": snapshot[0], "bit1": snapshot[1]})
			return
		}
		var payload struct {
			Bit0 *bool `json:"bit0"`
			Bit1 *bool `json:"bit1"`
		}
		json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		if payload.Bit0 != nil {
			bits[0] = *payload.Bit0
		}
		if payload.Bit1 != nil {
			bits[1] = *payload.Bit1
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer apple.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeDC := func() *DeviceCheck {
		return &DeviceCheck{base: apple.URL, teamID: "TEAMID1234", keyID: "KEYID12345", key: key,
			client: apple.Client(), now: time.Now, seen: map[[sha256.Size]byte]spentToken{}}
	}
	first, second := makeDC(), makeDC()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() {
		_, err := first.MarkRegistered(ctx, []byte("same-device-token-A"), Bit0, "app-a")
		results <- err
	}()
	go func() {
		_, err := second.MarkRegistered(ctx, []byte("same-device-token-B"), Bit1, "app-b")
		results <- err
	}()
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if bits != [2]bool{true, true} {
		t.Fatalf("after both registrations, bits = %v; one app cleared the other app's registration", bits)
	}
}

// Package identitytest has test doubles for the identity package's Apple
// dependencies.
package identitytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// KeyID is the DeviceCheck key id FakeApple accepts.
	KeyID = "KEYID12345"
	// BogusToken is a device token FakeApple refuses as malformed.
	BogusToken = "bogus"
)

// FakeApple plays Apple's DeviceCheck API: two bits per device token, and
// a JWT it checks against the key's public half.
type FakeApple struct {
	*httptest.Server
	mu   sync.Mutex
	key  *ecdsa.PublicKey
	bits map[string][2]bool
	// Delay holds every answer, to widen races in tests.
	Delay time.Duration
}

// Token is a device token as FakeApple reads it: the device's name, then a
// nonce, as DCDevice hands a Mac a different token every time.
func Token(device string, nonce int) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s#%d", device, nonce)))
}

// device is the Mac a token belongs to.
func device(token string) string {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return token
	}
	name, _, _ := strings.Cut(string(raw), "#")
	return name
}

// NewFakeApple starts the fake and writes a matching .p8 key, answering
// the server and the key's path.
func NewFakeApple(t *testing.T) (*FakeApple, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	path := filepath.Join(t.TempDir(), "AuthKey_"+KeyID+".p8")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	apple := &FakeApple{key: &key.PublicKey, bits: map[string][2]bool{}}
	apple.Server = httptest.NewServer(http.HandlerFunc(apple.serve))
	t.Cleanup(apple.Close)
	return apple, path
}

// Bit0 answers whether the token's device has bit 0 set.
func (f *FakeApple) Bit0(token string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bits[device(token)][0]
}

// Bit1 answers whether the token's device has bit 1 set.
func (f *FakeApple) Bit1(token string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bits[device(token)][1]
}

func (f *FakeApple) serve(w http.ResponseWriter, r *http.Request) {
	time.Sleep(f.Delay)
	f.mu.Lock()
	defer f.mu.Unlock()
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		http.Error(w, "Missing or badly formatted authorization token", http.StatusUnauthorized)
		return
	}
	var header struct{ Alg, Kid string }
	decoded, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(decoded, &header)
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if header.Alg != "ES256" || header.Kid != KeyID || len(signature) != 64 ||
		!ecdsa.Verify(f.key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		http.Error(w, "Unable to verify authorization token", http.StatusUnauthorized)
		return
	}
	var body struct {
		DeviceToken string `json:"device_token"`
		Bit0        *bool  `json:"bit0"`
		Bit1        *bool  `json:"bit1"`
	}
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &body)
	if body.DeviceToken == "" || body.DeviceToken == base64.StdEncoding.EncodeToString([]byte(BogusToken)) {
		http.Error(w, "Missing or incorrectly formatted device token payload", http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	case "/v1/query_two_bits":
		if bits, ok := f.bits[device(body.DeviceToken)]; ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"bit0": bits[0], "bit1": bits[1], "last_update_time": "2026-09"})
			return
		}
		_, _ = w.Write([]byte("Failed to find bit state"))
	case "/v1/update_two_bits":
		// A bit the update omits keeps its value.
		bits := f.bits[device(body.DeviceToken)]
		if body.Bit0 != nil {
			bits[0] = *body.Bit0
		}
		if body.Bit1 != nil {
			bits[1] = *body.Bit1
		}
		f.bits[device(body.DeviceToken)] = bits
	default:
		http.NotFound(w, r)
	}
}

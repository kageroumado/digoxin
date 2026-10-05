package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	DeviceCheckProduction = "https://api.devicecheck.apple.com"
	DeviceCheckSandbox    = "https://api.development.devicecheck.apple.com"
)

// DeviceCheck trades a DCDevice token for this device's two bits, through
// Apple's DeviceCheck server API with an ES256 JWT made from the team's
// DeviceCheck key.
type DeviceCheck struct {
	base   string
	teamID string
	keyID  string
	key    *ecdsa.PrivateKey
	client *http.Client
	now    func() time.Time

	// stripes serialize MarkRegistered per token, so two registrations
	// carrying one token cannot both read a clear bit before either sets it.
	stripes [64]sync.Mutex
	seenMu  sync.Mutex
	// seen maps a token's hash to the install that spent it, for
	// TokenReuseWindow.
	seen  map[[sha256.Size]byte]spentToken
	swept time.Time
}

type spentToken struct {
	holder string
	until  time.Time
}

// TokenReuseWindow is how long a DeviceCheck token stays tied to the
// install that registered with it. A genuine client asks DCDevice for a new
// token at every registration, so one token behind several keys is a copy.
const TokenReuseWindow = 24 * time.Hour

// ErrTokenReused is a token another install registered with inside
// TokenReuseWindow: the evidence is void.
var ErrTokenReused = errors.New("device token already registered another install")

// LoadDeviceCheck reads the .p8 key; a missing configuration returns nil,
// and registration then skips DeviceCheck.
func LoadDeviceCheck(base, keyPath, keyID, teamID string) (*DeviceCheck, error) {
	if keyPath == "" || keyID == "" || teamID == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("DeviceCheck key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("DeviceCheck key is not ECDSA")
	}
	return &DeviceCheck{
		base: strings.TrimRight(base, "/"), teamID: teamID, keyID: keyID, key: key,
		client: &http.Client{Timeout: 15 * time.Second}, now: time.Now,
		seen: map[[sha256.Size]byte]spentToken{},
	}, nil
}

// jwt signs {"alg":"ES256","kid":…} . {"iss":team,"iat":now} with the raw
// r‖s signature JWS requires.
func (d *DeviceCheck) jwt() (string, error) {
	encode := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": d.keyID})
	claims, _ := json.Marshal(map[string]any{"iss": d.teamID, "iat": d.now().Unix()})
	signing := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, d.key, digest[:])
	if err != nil {
		return "", err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signing + "." + encode(signature), nil
}

func transactionID() string {
	value := make([]byte, 16)
	_, _ = rand.Read(value)
	return hex.EncodeToString(value)
}

// ErrDeviceToken is Apple refusing the token itself: the evidence is void.
var ErrDeviceToken = errors.New("device token refused")

func (d *DeviceCheck) call(ctx context.Context, path string, body map[string]any) ([]byte, error) {
	token, err := d.jwt()
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := d.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	switch {
	case response.StatusCode == http.StatusOK:
		return answer, nil
	case response.StatusCode == http.StatusBadRequest:
		return nil, fmt.Errorf("%w: %s", ErrDeviceToken, strings.TrimSpace(string(answer)))
	default:
		return nil, fmt.Errorf("DeviceCheck %s: %d %s", path, response.StatusCode, strings.TrimSpace(string(answer)))
	}
}

// The device's two bits are shared by every app of the developer team, so
// each bit can mark registration for one app only; sevostats marks
// Sevoflurane's with bit 0, which is also a Judge's zero value. An app given
// no bit proves the device with its token and cannot tell a reinstall.
const (
	Bit0  = 0
	Bit1  = 1
	NoBit = -1
)

// MarkRegistered reads the device's bits and sets bit when it is clear. It
// answers whether the device had registered before. With NoBit it only
// proves the token: Apple answers a query for a genuine device and refuses
// a forged token. holder is the install registering; a token another
// holder spent inside TokenReuseWindow answers ErrTokenReused unasked.
//
// Calls with one token run one at a time. Two different tokens from one
// Mac still race on Apple's bits, which nothing here can tell apart.
func (d *DeviceCheck) MarkRegistered(ctx context.Context, deviceToken []byte, bit int, holder string) (bool, error) {
	digest := sha256.Sum256(deviceToken)
	stripe := &d.stripes[int(digest[0])%len(d.stripes)]
	stripe.Lock()
	defer stripe.Unlock()
	if d.spentByAnother(digest, holder) {
		return false, ErrTokenReused
	}
	registered, err := d.markRegistered(ctx, deviceToken, bit)
	if err == nil {
		d.spend(digest, holder)
	}
	return registered, err
}

func (d *DeviceCheck) spentByAnother(digest [sha256.Size]byte, holder string) bool {
	d.seenMu.Lock()
	defer d.seenMu.Unlock()
	spent, ok := d.seen[digest]
	return ok && d.now().Before(spent.until) && spent.holder != holder
}

func (d *DeviceCheck) spend(digest [sha256.Size]byte, holder string) {
	d.seenMu.Lock()
	defer d.seenMu.Unlock()
	now := d.now()
	if now.Sub(d.swept) > time.Hour {
		for key, spent := range d.seen {
			if !now.Before(spent.until) {
				delete(d.seen, key)
			}
		}
		d.swept = now
	}
	d.seen[digest] = spentToken{holder: holder, until: now.Add(TokenReuseWindow)}
}

func (d *DeviceCheck) markRegistered(ctx context.Context, deviceToken []byte, bit int) (bool, error) {
	token := base64.StdEncoding.EncodeToString(deviceToken)
	answer, err := d.call(ctx, "/v1/query_two_bits", map[string]any{
		"device_token": token, "transaction_id": transactionID(), "timestamp": d.now().UnixMilli(),
	})
	if err != nil || bit == NoBit {
		return false, err
	}
	// A device whose bits were never set answers 200 with plain text.
	var bits struct {
		Bit0 bool `json:"bit0"`
		Bit1 bool `json:"bit1"`
	}
	_ = json.Unmarshal(answer, &bits)
	if bit == Bit0 && bits.Bit0 || bit == Bit1 && bits.Bit1 {
		return true, nil
	}
	_, err = d.call(ctx, "/v1/update_two_bits", map[string]any{
		"device_token": token, "transaction_id": transactionID(), "timestamp": d.now().UnixMilli(),
		"bit0": bits.Bit0 || bit == Bit0, "bit1": bits.Bit1 || bit == Bit1,
	})
	return false, err
}

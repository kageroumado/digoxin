// Package identity is the install identity core of Digoxin and any service
// that verifies the same evidence: install ids derived from a Secure Enclave key,
// request signatures, registration challenges, Apple's App Attest and
// DeviceCheck evidence, the trust tier that evidence earns, and per-address
// rate limits.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	// InstallIDLength is the install id's length: the first 26 base32
	// characters (130 bits) of the key's hash, matching the client's
	// InstallKey.installID.
	InstallIDLength = 26
	ChallengeLife   = 5 * time.Minute
	// A challenge is random bytes, an expiry as big-endian Unix seconds, and
	// an HMAC-SHA256 tag over both. The app signs it as opaque bytes.
	challengeRandomBytes = 16
	challengeBodyBytes   = challengeRandomBytes + 8
	ChallengeBytes       = challengeBodyBytes + sha256.Size
)

var lowerBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// InstallID derives the id from the public key's SubjectPublicKeyInfo DER:
// lowercase unpadded RFC 4648 base32 of its SHA-256, cut to 26 characters.
func InstallID(publicKeyDER []byte) string {
	sum := sha256.Sum256(publicKeyDER)
	return lowerBase32.EncodeToString(sum[:])[:InstallIDLength]
}

// ValidInstallID answers whether id has the shape InstallID produces.
func ValidInstallID(id string) bool {
	if len(id) != InstallIDLength {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// ParseP256 reads a SubjectPublicKeyInfo DER and accepts only P-256 ECDSA.
func ParseP256(der []byte) (*ecdsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key")
	}
	return ec, nil
}

// VerifyBody checks a base64 DER ECDSA signature over SHA-256 of the body,
// which is what CryptoKit's signature(for:) produces.
func VerifyBody(key *ecdsa.PublicKey, body []byte, signatureB64 string) bool {
	digest := sha256.Sum256(body)
	return VerifyDigest(key, digest[:], signatureB64)
}

// VerifyDigest is VerifyBody for a body hashed while it streamed.
func VerifyDigest(key *ecdsa.PublicKey, digest []byte, signatureB64 string) bool {
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil || len(signature) == 0 || len(signature) > 80 || len(digest) != sha256.Size {
		return false
	}
	return ecdsa.VerifyASN1(key, digest, signature)
}

// Challenges hands out single-use values that expire. A challenge carries
// its own proof: random bytes, its expiry, and an HMAC-SHA256 tag under a
// secret made when the process started, so nothing is stored at issue and
// a flood of requests fills no table. What is stored is the set of
// challenges already spent, each until it expires, which grows only with
// registrations that carried a valid challenge.
type Challenges struct {
	mu     sync.Mutex
	secret []byte
	used   map[string]time.Time
	swept  time.Time
	Now    func() time.Time
}

// sweepInterval is how often spent challenges past their expiry are
// dropped: sweeping on every registration costs time in the number held.
const sweepInterval = time.Minute

func NewChallenges() *Challenges {
	secret := make([]byte, sha256.Size)
	rand.Read(secret)
	return &Challenges{secret: secret, used: make(map[string]time.Time), Now: time.Now}
}

// tag is the HMAC over a challenge's random bytes and expiry.
func (c *Challenges) tag(body []byte) []byte {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write(body)
	return mac.Sum(nil)
}

// Issue returns a fresh challenge's raw bytes: random ‖ expiry ‖ tag.
func (c *Challenges) Issue() []byte {
	value := make([]byte, ChallengeBytes)
	rand.Read(value[:challengeRandomBytes])
	expires := c.Now().Add(ChallengeLife).Unix()
	binary.BigEndian.PutUint64(value[challengeRandomBytes:challengeBodyBytes], uint64(expires))
	copy(value[challengeBodyBytes:], c.tag(value[:challengeBodyBytes]))
	return value
}

// Consume answers whether the challenge is one this process issued, still
// live and not yet spent, and spends it. A spent challenge is held until it
// expires, so it can never be spent twice.
func (c *Challenges) Consume(value []byte) bool {
	if len(value) != ChallengeBytes || !hmac.Equal(value[challengeBodyBytes:], c.tag(value[:challengeBodyBytes])) {
		return false
	}
	expires := time.Unix(int64(binary.BigEndian.Uint64(value[challengeRandomBytes:challengeBodyBytes])), 0)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.Now()
	if now.Sub(c.swept) >= sweepInterval {
		for key, past := range c.used {
			if now.After(past) {
				delete(c.used, key)
			}
		}
		c.swept = now
	}
	if now.After(expires) {
		return false
	}
	if _, spent := c.used[string(value)]; spent {
		return false
	}
	c.used[string(value)] = expires
	return true
}

// spent is how many challenges are held as used, for tests.
func (c *Challenges) spent() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.used)
}

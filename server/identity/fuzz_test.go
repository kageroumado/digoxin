package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

func FuzzVerifyAttestation(f *testing.F) {
	roots := x509.NewCertPool()
	f.Add([]byte{0xa3}, []byte{1}, []byte{2})
	f.Fuzz(func(t *testing.T, obj, keyID, cdh []byte) {
		VerifyAttestation(roots, obj, keyID, cdh, "TEAMID1234.a.b", time.Now())
	})
}

func FuzzCheckAuthData(f *testing.F) {
	f.Add(make([]byte, 60), []byte{1})
	f.Fuzz(func(t *testing.T, a, k []byte) { checkAuthData(a, k, "X") })
}

func FuzzPolicyParsers(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0xa1, 0x01, 0x05})
	f.Fuzz(func(t *testing.T, der []byte) {
		taggedValues(der)
		accessControl(der)
	})
}

func FuzzConsume(f *testing.F) {
	c := NewChallenges()
	f.Add(c.Issue())
	f.Fuzz(func(t *testing.T, v []byte) { c.Consume(v) })
}

func FuzzVerifyBody(f *testing.F) {
	k := mustKey()
	f.Add([]byte("x"), "MEUCIQ==")
	f.Fuzz(func(t *testing.T, body []byte, sig string) { VerifyBody(k, body, sig) })
}

func mustKey() *ecdsaPub {
	der := mustDER()
	k, _ := ParseP256(der)
	return k
}

type ecdsaPub = ecdsa.PublicKey

func mustDER() []byte {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return d
}

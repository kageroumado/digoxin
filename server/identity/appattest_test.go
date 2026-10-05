package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// The SHA-256 of the root certificate's DER, as Apple publishes it and as
// `openssl x509 -fingerprint -sha256` prints it for the downloaded PEM.
const appleRootFingerprint = "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"

func TestEmbeddedRootIsApples(t *testing.T) {
	block, _ := pem.Decode(appleAppAttestRootPEM)
	if block == nil {
		t.Fatal("no PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	if got := hex.EncodeToString(sum[:]); got != appleRootFingerprint {
		t.Fatalf("root fingerprint %s", got)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.Subject.CommonName != "Apple App Attestation Root CA" {
		t.Fatalf("root %v %v", cert.Subject, err)
	}
}

type realVector struct {
	AppID       string `json:"app_id"`
	ClientData  string `json:"client_data"`
	KeyID       string `json:"key_id"`
	Attestation string `json:"attestation"`
	VerifyAt    string `json:"verify_at"`
}

// A real device attestation, chained to Apple's root: the full verifier
// against Apple's own bytes. Its leaf expired in April 2021, so the check
// runs at a time inside the leaf's validity.
func TestRealAppleAttestation(t *testing.T) {
	raw, err := os.ReadFile("testdata/appattest-real.json")
	if err != nil {
		t.Fatal(err)
	}
	var v realVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	object, _ := base64.StdEncoding.DecodeString(v.Attestation)
	keyID, _ := base64.StdEncoding.DecodeString(v.KeyID)
	at, _ := time.Parse(time.RFC3339, v.VerifyAt)
	clientDataHash := sha256.Sum256([]byte(v.ClientData))

	result, err := VerifyAppAttest(object, keyID, clientDataHash[:], v.AppID, at)
	if err != nil {
		t.Fatalf("real attestation: %v", err)
	}
	if result.Env != AttestEnvDevelopment {
		t.Fatalf("environment %s", result.Env)
	}

	wrongHash := sha256.Sum256([]byte("another challenge"))
	otherKey := append([]byte{}, keyID...)
	otherKey[0] ^= 1
	for name, check := range map[string]func() (Attested, error){
		"another App ID": func() (Attested, error) {
			return VerifyAppAttest(object, keyID, clientDataHash[:], "52K336H235.glass.kagerou.sevoflurane", at)
		},
		"another challenge": func() (Attested, error) { return VerifyAppAttest(object, keyID, wrongHash[:], v.AppID, at) },
		"another key id":    func() (Attested, error) { return VerifyAppAttest(object, otherKey, clientDataHash[:], v.AppID, at) },
		"an expired leaf": func() (Attested, error) {
			return VerifyAppAttest(object, keyID, clientDataHash[:], v.AppID, at.AddDate(1, 0, 0))
		},
		"a truncated object": func() (Attested, error) { return VerifyAppAttest(object[:100], keyID, clientDataHash[:], v.AppID, at) },
	} {
		if _, err := check(); err == nil {
			t.Errorf("%s verified", name)
		}
	}
}

// ---- A self-made chain, for each structural branch ----

type testCA struct {
	roots *x509.CertPool
	inter *x509.Certificate
	key   *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	interKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	interTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTemplate, root, &interKey.PublicKey, rootKey)
	inter, _ := x509.ParseCertificate(interDER)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &testCA{roots: pool, inter: inter, key: interKey}
}

type attestationParts struct {
	appID          string
	counter        uint32
	aaguid         []byte
	credentialID   []byte // defaults to the key id
	nonceOverride  []byte
	clientDataHash []byte
}

// attest builds an attestation object the way the Secure Enclave and Apple's
// CA would, with the given parts swapped in. It returns the object and the key id.
func (ca *testCA) attest(t *testing.T, p attestationParts) ([]byte, []byte) {
	t.Helper()
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	point, _ := credKey.PublicKey.Bytes()
	keyID := sha256.Sum256(point)
	credentialID := p.credentialID
	if credentialID == nil {
		credentialID = keyID[:]
	}
	rpIDHash := sha256.Sum256([]byte(p.appID))
	authData := append([]byte{}, rpIDHash[:]...)
	authData = append(authData, 0x40)
	authData = binary.BigEndian.AppendUint32(authData, p.counter)
	authData = append(authData, p.aaguid...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credentialID)))
	authData = append(authData, credentialID...)

	nonce := sha256.Sum256(append(append([]byte{}, authData...), p.clientDataHash...))
	nonceValue := nonce[:]
	if p.nonceOverride != nil {
		nonceValue = p.nonceOverride
	}
	extension, _ := asn1.Marshal(struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}{nonceValue})
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: hex.EncodeToString(keyID[:])},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidAppAttestNonce, Value: extension}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca.inter, &credKey.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := cbor.Marshal(map[string]any{
		"fmt":      "apple-appattest",
		"attStmt":  map[string]any{"x5c": [][]byte{leafDER, ca.inter.Raw}, "receipt": []byte("receipt")},
		"authData": authData,
	})
	return object, keyID[:]
}

func TestAttestationStructure(t *testing.T) {
	ca := newTestCA(t)
	appID := testAppID
	hash := sha256.Sum256([]byte("key ‖ challenge"))
	base := attestationParts{appID: appID, aaguid: aaguidProduction, clientDataHash: hash[:]}
	now := time.Now()

	object, keyID := ca.attest(t, base)
	if result, err := VerifyAttestation(ca.roots, object, keyID, hash[:], appID, now); err != nil || result.Env != AttestEnvProduction {
		t.Fatalf("production: %s %v", result.Env, err)
	}
	dev := base
	dev.aaguid = aaguidDevelopment
	object, keyID = ca.attest(t, dev)
	if result, err := VerifyAttestation(ca.roots, object, keyID, hash[:], appID, now); err != nil || result.Env != AttestEnvDevelopment {
		t.Fatalf("development: %s %v", result.Env, err)
	}

	cases := map[string]attestationParts{}
	c := base
	c.counter = 1
	cases["counter"] = c
	c = base
	c.aaguid = []byte("appattestfakeenv")
	cases["aaguid"] = c
	c = base
	c.appID = "OTHERTEAM.glass.kagerou.sevoflurane"
	cases["App ID"] = c
	c = base
	c.credentialID = []byte("another credential id, 32 bytes!")
	cases["credential id"] = c
	c = base
	c.nonceOverride = make([]byte, 32)
	cases["nonce"] = c
	for name, parts := range cases {
		object, keyID := ca.attest(t, parts)
		if _, err := VerifyAttestation(ca.roots, object, keyID, hash[:], appID, now); err == nil {
			t.Errorf("a wrong %s verified", name)
		}
	}

	// The self-made chain means nothing against Apple's root.
	object, keyID = ca.attest(t, base)
	if _, err := VerifyAppAttest(object, keyID, hash[:], appID, now); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("a foreign chain: %v", err)
	}
}

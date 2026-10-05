package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	_ "embed"

	"github.com/fxamacker/cbor/v2"
)

// Apple's App Attestation root, from
// https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem.
// Its SHA-256 fingerprint is pinned in appattest_test.go.
//
//go:embed apple_app_attestation_root_ca.pem
var appleAppAttestRootPEM []byte

// The leaf certificate extension that carries the attestation nonce.
var oidAppAttestNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// The two AAGUIDs App Attest writes into authData: one per environment.
var (
	aaguidDevelopment = []byte("appattestdevelop")
	aaguidProduction  = append([]byte("appattest"), make([]byte, 7)...)
)

const (
	AttestEnvDevelopment = "development"
	AttestEnvProduction  = "production"
)

type attestationObject struct {
	Format   string  `cbor:"fmt"`
	AttStmt  attStmt `cbor:"attStmt"`
	AuthData []byte  `cbor:"authData"`
}

type attStmt struct {
	X5C     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

func appAttestRoots() (*x509.CertPool, error) {
	block, _ := pem.Decode(appleAppAttestRootPEM)
	if block == nil {
		return nil, errors.New("embedded App Attest root is not PEM")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pool, nil
}

// VerifyAppAttest follows Apple's server-side validation of an attestation
// object (developer.apple.com, "Validating apps that connect to your
// server"). keyID is the raw key identifier (the base64-decoded string
// DCAppAttestService returned), clientDataHash is what the app passed to
// attestKey, and appID is "<team id>.<bundle id>". It returns which
// environment attested the key and the key's policy.
func VerifyAppAttest(object, keyID, clientDataHash []byte, appID string, now time.Time) (Attested, error) {
	roots, err := appAttestRoots()
	if err != nil {
		return Attested{}, err
	}
	return VerifyAttestation(roots, object, keyID, clientDataHash, appID, now)
}

// Attested is a verified attestation: the environment and what the leaf
// says about the key.
type Attested struct {
	Env    string
	Policy *KeyPolicy
	// PolicyErr is why Policy is nil when the leaf's policy extensions
	// did not parse; the attestation still verified.
	PolicyErr error
}

// VerifyAttestation is VerifyAppAttest against a given root pool. A key
// policy it cannot read leaves Policy nil: Apple's chain is the proof, and
// the policy extensions are undocumented.
func VerifyAttestation(roots *x509.CertPool, object, keyID, clientDataHash []byte, appID string, now time.Time) (Attested, error) {
	leaf, env, err := verifyChainAndKey(roots, object, keyID, clientDataHash, appID, now)
	if err != nil {
		return Attested{}, err
	}
	policy, err := ReadKeyPolicy(leaf)
	if err != nil {
		return Attested{Env: env, PolicyErr: err}, nil
	}
	return Attested{Env: env, Policy: policy}, nil
}

// verifyChainAndKey runs Apple's steps 1–9 and answers the leaf and the
// environment.
func verifyChainAndKey(roots *x509.CertPool, object, keyID, clientDataHash []byte, appID string, now time.Time) (*x509.Certificate, string, error) {
	var att attestationObject
	if err := cbor.Unmarshal(object, &att); err != nil {
		return nil, "", fmt.Errorf("cbor: %w", err)
	}
	if att.Format != "apple-appattest" {
		return nil, "", fmt.Errorf("format %q", att.Format)
	}
	if len(att.AttStmt.X5C) < 2 {
		return nil, "", errors.New("x5c needs the leaf and the intermediate")
	}

	// 1. The chain ends at Apple's App Attestation root.
	leaf, err := x509.ParseCertificate(att.AttStmt.X5C[0])
	if err != nil {
		return nil, "", fmt.Errorf("leaf: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range att.AttStmt.X5C[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, "", fmt.Errorf("intermediate: %w", err)
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, "", fmt.Errorf("chain: %w", err)
	}

	// 2–4. The leaf's nonce extension is SHA-256(authData ‖ clientDataHash).
	composite := append(append([]byte{}, att.AuthData...), clientDataHash...)
	nonce := sha256.Sum256(composite)
	certified, err := nonceExtension(leaf)
	if err != nil {
		return nil, "", err
	}
	if !bytes.Equal(certified, nonce[:]) {
		return nil, "", errors.New("nonce does not match")
	}

	// 5. The key id is the SHA-256 of the leaf's public key point.
	point, err := uncompressedPoint(leaf)
	if err != nil {
		return nil, "", err
	}
	pointHash := sha256.Sum256(point)
	if !bytes.Equal(pointHash[:], keyID) {
		return nil, "", errors.New("key id is not the attested key's")
	}

	// 6–9. authData: the App ID, a zero counter, the environment, the credential.
	env, err := checkAuthData(att.AuthData, keyID, appID)
	return leaf, env, err
}

// nonceExtension reads SEQUENCE { [1] EXPLICIT OCTET STRING } from the leaf.
func nonceExtension(leaf *x509.Certificate) ([]byte, error) {
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidAppAttestNonce) {
			continue
		}
		var wrapper struct {
			Nonce []byte `asn1:"tag:1,explicit"`
		}
		rest, err := asn1.Unmarshal(ext.Value, &wrapper)
		if err != nil {
			return nil, fmt.Errorf("nonce extension: %w", err)
		}
		if len(rest) != 0 || len(wrapper.Nonce) != sha256.Size {
			return nil, errors.New("nonce extension is malformed")
		}
		return wrapper.Nonce, nil
	}
	return nil, errors.New("no nonce extension")
}

func uncompressedPoint(cert *x509.Certificate) ([]byte, error) {
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("attested key is not P-256")
	}
	point, err := key.Bytes()
	if err != nil {
		return nil, err
	}
	return point, nil
}

// checkAuthData validates the authenticator data's fixed layout:
// rpIdHash(32) flags(1) counter(4) aaguid(16) credIdLen(2) credId(n) …
func checkAuthData(authData, keyID []byte, appID string) (string, error) {
	const header = 32 + 1 + 4 + 16 + 2
	if len(authData) < header {
		return "", errors.New("authData is short")
	}
	rpIDHash := sha256.Sum256([]byte(appID))
	if !bytes.Equal(authData[:32], rpIDHash[:]) {
		return "", errors.New("attested for another App ID")
	}
	if counter := binary.BigEndian.Uint32(authData[33:37]); counter != 0 {
		return "", fmt.Errorf("counter is %d", counter)
	}
	var env string
	switch aaguid := authData[37:53]; {
	case bytes.Equal(aaguid, aaguidDevelopment):
		env = AttestEnvDevelopment
	case bytes.Equal(aaguid, aaguidProduction):
		env = AttestEnvProduction
	default:
		return "", errors.New("unknown aaguid")
	}
	length := int(binary.BigEndian.Uint16(authData[53:55]))
	if len(authData) < header+length {
		return "", errors.New("credential id runs past authData")
	}
	if !bytes.Equal(authData[header:header+length], keyID) {
		return "", errors.New("credential id is not the key id")
	}
	return env, nil
}

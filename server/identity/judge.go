package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Trust tiers. Registration assigns the first four; an operator sets
// verified and blocked by hand, and registration keeps them.
const (
	TrustAttested     = "attested"
	TrustDevice       = "device"
	TrustReregistered = "reregistered"
	TrustUnverified   = "unverified"
	TrustVerified     = "verified"
	TrustBlocked      = "blocked"
)

// Evidence is what a registration carries besides the key: App Attest's
// key id and attestation object, and a DeviceCheck token, each base64 as
// the client sent it. Any of them may be empty.
type Evidence struct {
	AppAttestKeyID       string
	AppAttestAttestation string
	DeviceCheck          string
}

// Verdict is what registration makes of an install's evidence.
type Verdict struct {
	Trust string
	// Env and Policy are set when App Attest verified.
	Env    string
	Policy *KeyPolicy
}

// Judge turns evidence into a trust tier for one App ID.
type Judge struct {
	// AppID is "<team id>.<bundle id>", the App ID attestations must name.
	AppID string
	// RequireProductionAttest turns development attestations away.
	RequireProductionAttest bool
	// DeviceCheck is nil when no DeviceCheck key is configured; tokens are
	// then ignored.
	DeviceCheck *DeviceCheck
	// RegisteredBit is the DeviceCheck bit that marks this app's
	// registrations (Bit0, Bit1), or NoBit; see MarkRegistered.
	RegisteredBit int
	Now           func() time.Time
	Logf          func(format string, args ...any)

	noDCOnce sync.Once
	// roots replaces Apple's App Attestation root, for tests.
	roots *x509.CertPool
}

func (j *Judge) logf(format string, args ...any) {
	if j.Logf != nil {
		j.Logf(format, args...)
	}
}

// ClientDataHash is what App Attest signs at registration:
// SHA-256(keyDER ‖ challenge ‖ SHA-256(device token)), the token empty when
// none is sent. It ties the attestation to this key, this registration, and
// the DeviceCheck token sent beside it, so a token cannot be swapped for
// another Mac's under the same attestation.
func ClientDataHash(keyDER, challenge, deviceToken []byte) []byte {
	tokenHash := sha256.Sum256(deviceToken)
	data := make([]byte, 0, len(keyDER)+len(challenge)+len(tokenHash))
	data = append(append(append(data, keyDER...), challenge...), tokenHash[:]...)
	sum := sha256.Sum256(data)
	return sum[:]
}

// Judge answers the trust tier of a registration: attested when App Attest
// verifies, device when only DeviceCheck does, unverified when neither, and
// reregistered when the app's DeviceCheck bit says this device registered
// another key before. existingTrust is the tier the server already holds
// for this key, empty for a new one. It fails only when Apple could not be
// asked.
//
// An app that marks registrations with a bit earns attested only with a
// DeviceCheck token Apple accepts: App Attest alone proves a genuine Mac
// and app, but one Mac can mint any number of attested keys, and the bit is
// what tells the second from a new Mac.
func (j *Judge) Judge(ctx context.Context, e Evidence, keyDER, challenge []byte, existingTrust string) (Verdict, error) {
	v := Verdict{Trust: TrustUnverified}
	token, tokenErr := base64.StdEncoding.DecodeString(e.DeviceCheck)
	if tokenErr != nil {
		token = nil
	}
	if e.AppAttestKeyID != "" || e.AppAttestAttestation != "" {
		keyID, errKey := base64.StdEncoding.DecodeString(e.AppAttestKeyID)
		object, errObject := base64.StdEncoding.DecodeString(e.AppAttestAttestation)
		if errKey == nil && errObject == nil {
			result, err := j.verify(object, keyID, ClientDataHash(keyDER, challenge, token))
			switch {
			case err != nil:
				j.logf("App Attest refused: %v", err)
			case result.Env == AttestEnvDevelopment && j.RequireProductionAttest:
				j.logf("App Attest from the development environment, not counted")
			default:
				v = Verdict{Trust: TrustAttested, Env: result.Env, Policy: result.Policy}
				if result.PolicyErr != nil {
					j.logf("attested key's policy is unreadable: %v", result.PolicyErr)
				}
				if p := result.Policy; p != nil && !p.SignNeedsSecureBoot {
					j.logf("attested key's signing ACL is %q, not %q", p.ACL[ACLSign], ACLSecureBoot)
				}
			}
		}
	}

	proven, registeredBefore := false, false
	switch {
	case j.DeviceCheck == nil:
		if len(token) > 0 {
			j.noDCOnce.Do(func() { j.logf("no DeviceCheck key configured for %s; tokens are ignored", j.AppID) })
		}
	case len(token) > 0:
		var err error
		registeredBefore, err = j.DeviceCheck.MarkRegistered(ctx, token, j.RegisteredBit, InstallID(keyDER))
		switch {
		case errors.Is(err, ErrDeviceToken), errors.Is(err, ErrTokenReused):
			j.logf("DeviceCheck evidence void: %v", err)
		case err != nil:
			return Verdict{}, err
		default:
			proven = true
		}
	}
	if !proven {
		if v.Trust == TrustAttested && j.DeviceCheck != nil && j.RegisteredBit != NoBit {
			j.logf("App Attest without an accepted DeviceCheck token; unverified")
			v.Trust = TrustUnverified
		}
		return v, nil
	}
	// An install registering again sees the bit its first registration set.
	if registeredBefore && (existingTrust == "" || existingTrust == TrustReregistered || existingTrust == TrustUnverified) {
		v.Trust = TrustReregistered
		return v, nil
	}
	if v.Trust != TrustAttested {
		v.Trust = TrustDevice
	}
	return v, nil
}

func (j *Judge) verify(object, keyID, clientDataHash []byte) (Attested, error) {
	if j.roots != nil {
		return VerifyAttestation(j.roots, object, keyID, clientDataHash, j.AppID, j.Now())
	}
	return VerifyAppAttest(object, keyID, clientDataHash, j.AppID, j.Now())
}

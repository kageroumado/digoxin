package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kageroumado/digoxin/server/identity/identitytest"
)

const testAppID = "52K336H235.glass.kagerou.sevoflurane"

type testClient struct {
	key *ecdsa.PrivateKey
	der []byte
	id  string
}

func newTestClient(t *testing.T) *testClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{key: key, der: der, id: InstallID(der)}
}

func (c *testClient) sign(t *testing.T, body []byte) string {
	t.Helper()
	digest := sha256.Sum256(body)
	signature, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

// ---- Install ids, signatures, challenges ----

func TestInstallIDIsLowercaseBase32OfTheKeyHash(t *testing.T) {
	if got := lowerBase32.EncodeToString([]byte("foobar")); got != "mzxw6ytboi" {
		t.Fatalf("base32(foobar) = %q, want the RFC 4648 vector mzxw6ytboi", got)
	}
	input := make([]byte, 91)
	for i := range input {
		input[i] = byte(i)
	}
	// Computed independently: Python's base64.b32encode(sha256(bytes(range(91)))).lower()[:26].
	if got := InstallID(input); got != "ldjjiwnscmfc4fisklkarok6nw" {
		t.Fatalf("InstallID = %q", got)
	}
	if !ValidInstallID("ldjjiwnscmfc4fisklkarok6nw") || ValidInstallID("LDJJ") || ValidInstallID("ldjjiwnscmfc4fisklkarok6n1") {
		t.Fatal("ValidInstallID")
	}
}

func TestSignatureVerifiesOnlyTheSignedBody(t *testing.T) {
	c := newTestClient(t)
	key, err := ParseP256(c.der)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"seq":1}`)
	signature := c.sign(t, body)
	if !VerifyBody(key, body, signature) {
		t.Fatal("a body signed in-test does not verify")
	}
	if VerifyBody(key, []byte(`{"seq":2}`), signature) {
		t.Fatal("a signature verified another body")
	}
	if VerifyBody(key, body, "not base64!") {
		t.Fatal("garbage verified")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := ParseP256(der); err == nil {
		t.Fatal("a P-384 key parsed as P-256")
	}
}

func TestChallengesAreSingleUseAndExpire(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := NewChallenges()
	c.Now = func() time.Time { return now }
	value := c.Issue()
	if !c.Consume(value) || c.Consume(value) {
		t.Fatal("a challenge must work exactly once")
	}
	value = c.Issue()
	now = now.Add(ChallengeLife + time.Second)
	if c.Consume(value) {
		t.Fatal("an expired challenge was accepted")
	}
	if c.spent() != 0 {
		t.Fatalf("%d spent challenges kept past their expiry", c.spent())
	}
}

// TestChallengesCarryTheirOwnProof: a challenge is accepted only with this
// process's tag over its bytes and expiry, so nothing is stored at issue and
// a forged, altered or foreign one costs no memory.
func TestChallengesCarryTheirOwnProof(t *testing.T) {
	c := NewChallenges()
	value := c.Issue()
	forged := make([]byte, ChallengeBytes)
	rand.Read(forged)
	later := append([]byte(nil), value...)
	binary.BigEndian.PutUint64(later[challengeRandomBytes:challengeBodyBytes], uint64(time.Now().Add(time.Hour).Unix()))
	other := NewChallenges().Issue()
	for name, bad := range map[string][]byte{"forged": forged, "expiry moved": later, "another process's": other, "short": value[:ChallengeBytes-1], "empty": nil} {
		if c.Consume(bad) {
			t.Errorf("a %s challenge was accepted", name)
		}
	}
	if c.spent() != 0 {
		t.Fatalf("%d refused challenges were stored", c.spent())
	}
	if !c.Consume(value) || c.spent() != 1 {
		t.Fatal("the real challenge, still unspent, was refused")
	}
}

// ---- Key policy ----

func loadVector(t *testing.T, path string) (object, keyID, clientDataHash []byte, appID string, at time.Time) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v realVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	object, _ = base64.StdEncoding.DecodeString(v.Attestation)
	keyID, _ = base64.StdEncoding.DecodeString(v.KeyID)
	at, _ = time.Parse(time.RFC3339, v.VerifyAt)
	sum := sha256.Sum256([]byte(v.ClientData))
	return object, keyID, sum[:], v.AppID, at
}

// A Full Security MacBook Pro's attestation, made by a probe signed as
// Sevoflurane: the whole verifier and the key policy against Apple's bytes.
func TestMacAttestationAndItsKeyPolicy(t *testing.T) {
	object, keyID, hash, appID, at := loadVector(t, "testdata/appattest-macos.json")
	result, err := VerifyAppAttest(object, keyID, hash, appID, at)
	if err != nil {
		t.Fatalf("Mac attestation: %v", err)
	}
	if result.Env != AttestEnvProduction {
		t.Fatalf("environment %s", result.Env)
	}
	p := result.Policy
	if p.AppID != testAppID || p.OS != "27.0" || p.Build != "26A428" || p.Platform != "macosx" {
		t.Fatalf("policy identity: %+v", p)
	}
	want := map[string]string{"ok": "true", "oa": "true", "odel": "true", "osgn": "rsec([6]=1)"}
	if len(p.ACL) != len(want) {
		t.Fatalf("ACL %v", p.ACL)
	}
	for op, constraint := range want {
		if p.ACL[op] != constraint {
			t.Fatalf("ACL %s = %q, want %q", op, p.ACL[op], constraint)
		}
	}
	if !p.SignNeedsSecureBoot || p.Summary() != "full security" {
		t.Fatalf("secure boot: %v %q", p.SignNeedsSecureBoot, p.Summary())
	}
	if !strings.Contains(p.ACLText(), "osgn=rsec([6]=1)") {
		t.Fatalf("ACL text %q", p.ACLText())
	}

	wrongHash := sha256.Sum256([]byte("another challenge"))
	for name, check := range map[string]func() (Attested, error){
		"another challenge": func() (Attested, error) { return VerifyAppAttest(object, keyID, wrongHash[:], appID, at) },
		"another App ID": func() (Attested, error) {
			return VerifyAppAttest(object, keyID, hash, "52K336H235.glass.kagerou.other", at)
		},
		"an expired leaf": func() (Attested, error) { return VerifyAppAttest(object, keyID, hash, appID, at.AddDate(0, 0, 7)) },
	} {
		if _, err := check(); err == nil {
			t.Errorf("%s verified", name)
		}
	}
}

// ---- DeviceCheck and the trust ladder ----

func newDeviceCheckJudge(t *testing.T) (*Judge, *identitytest.FakeApple) {
	t.Helper()
	apple, path := identitytest.NewFakeApple(t)
	dc, err := LoadDeviceCheck(apple.URL, path, identitytest.KeyID, "52K336H235")
	if err != nil || dc == nil {
		t.Fatalf("load: %v", err)
	}
	return &Judge{AppID: testAppID, DeviceCheck: dc, RegisteredBit: Bit0, Now: time.Now}, apple
}

// judged registers c with only a DeviceCheck token and answers the trust.
func judged(t *testing.T, j *Judge, c *testClient, token, existing string) string {
	t.Helper()
	v, err := j.Judge(context.Background(), Evidence{DeviceCheck: token}, c.der, []byte("challenge"), existing)
	if err != nil {
		t.Fatal(err)
	}
	return v.Trust
}

func TestDeviceCheckTrustClasses(t *testing.T) {
	judge, apple := newDeviceCheckJudge(t)
	first := newTestClient(t)
	if got := judged(t, judge, first, identitytest.Token("mac", 1), ""); got != TrustDevice {
		t.Fatalf("first install: %s", got)
	}
	if !apple.Bit0(identitytest.Token("mac", 1)) {
		t.Fatal("bit 0 was not set")
	}
	// The same key registering again keeps its class.
	if got := judged(t, judge, first, identitytest.Token("mac", 2), TrustDevice); got != TrustDevice {
		t.Fatalf("same install again: %s", got)
	}
	// A new key on the same Mac is a re-registration.
	if got := judged(t, judge, newTestClient(t), identitytest.Token("mac", 3), ""); got != TrustReregistered {
		t.Fatalf("second install: %s", got)
	}
	// A token Apple refuses leaves the install unverified.
	bogus := base64.StdEncoding.EncodeToString([]byte(identitytest.BogusToken))
	if got := judged(t, judge, newTestClient(t), bogus, ""); got != TrustUnverified {
		t.Fatalf("refused token: %s", got)
	}
}

// TestAppsShareTheDevicesBits: two apps of one team see the same two bits,
// so each marks its own, and an app without a bit is never reregistered.
func TestAppsShareTheDevicesBits(t *testing.T) {
	first, apple := newDeviceCheckJudge(t)
	second := &Judge{AppID: testAppID, DeviceCheck: first.DeviceCheck, RegisteredBit: Bit1, Now: time.Now}
	other := &Judge{AppID: testAppID, DeviceCheck: first.DeviceCheck, RegisteredBit: NoBit, Now: time.Now}
	nonce := 0
	token := func() string { nonce++; return identitytest.Token("a Mac running all three", nonce) }
	for name, j := range map[string]*Judge{"bit 0": first, "bit 1": second, "no bit": other} {
		if got := judged(t, j, newTestClient(t), token(), ""); got != TrustDevice {
			t.Fatalf("%s: a first install is %s", name, got)
		}
	}
	if !apple.Bit0(token()) || !apple.Bit1(token()) {
		t.Fatal("each app set its own bit, keeping the other")
	}
	if judged(t, first, newTestClient(t), token(), "") != TrustReregistered || judged(t, second, newTestClient(t), token(), "") != TrustReregistered {
		t.Fatal("a second install in an app with a bit is a reinstall")
	}
	if got := judged(t, other, newTestClient(t), token(), ""); got != TrustDevice {
		t.Fatalf("a second install in an app without a bit: %s", got)
	}
	bogus := base64.StdEncoding.EncodeToString([]byte(identitytest.BogusToken))
	if got := judged(t, other, newTestClient(t), bogus, ""); got != TrustUnverified {
		t.Fatalf("a refused token without a bit: %s", got)
	}
}

// TestOneTokenBehindManyKeysIsVoid: a token copied to other keys proves
// nothing, even when the registrations race.
func TestOneTokenBehindManyKeysIsVoid(t *testing.T) {
	judge, apple := newDeviceCheckJudge(t)
	judge.RegisteredBit = Bit1
	apple.Delay = 100 * time.Millisecond
	token := identitytest.Token("one genuine Mac", 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	tiers := map[string]int{}
	for i := 0; i < 5; i++ {
		c := newTestClient(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := judge.Judge(context.Background(), Evidence{DeviceCheck: token}, c.der, nil, "")
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			tiers[v.Trust]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if tiers[TrustDevice] != 1 || tiers[TrustUnverified] != 4 {
		t.Fatalf("five keys, one token: %v", tiers)
	}
	// The window closes: a day later the token is spent no more, and Apple
	// says this Mac registered before.
	judge.DeviceCheck.now = func() time.Time { return time.Now().Add(TokenReuseWindow + time.Minute) }
	if got := judged(t, judge, newTestClient(t), token, ""); got != TrustReregistered {
		t.Fatalf("after the window: %s", got)
	}
}

func TestNoDeviceCheckKeyMeansUnverified(t *testing.T) {
	judge := &Judge{AppID: testAppID, Now: time.Now}
	if got := judged(t, judge, newTestClient(t), identitytest.Token("mac", 1), ""); got != TrustUnverified {
		t.Fatalf("trust %s", got)
	}
	if dc, err := LoadDeviceCheck(DeviceCheckProduction, "", "", "52K336H235"); dc != nil || err != nil {
		t.Fatalf("an unconfigured key loaded: %v %v", dc, err)
	}
}

func TestClientDataHashBindsKeyChallengeAndToken(t *testing.T) {
	tokenHash := sha256.Sum256([]byte("token"))
	want := sha256.Sum256(append([]byte("keychallenge"), tokenHash[:]...))
	if got := ClientDataHash([]byte("key"), []byte("challenge"), []byte("token")); !bytes.Equal(got, want[:]) {
		t.Fatalf("hash %x", got)
	}
	empty := sha256.Sum256(nil)
	want = sha256.Sum256(append([]byte("keychallenge"), empty[:]...))
	if got := ClientDataHash([]byte("key"), []byte("challenge"), nil); !bytes.Equal(got, want[:]) {
		t.Fatalf("hash without a token %x", got)
	}
}

// TestAttestationNeedsItsOwnToken: App Attest earns attested only over the
// token sent beside it, and, where the app marks registrations with a bit,
// only with a token Apple accepts.
func TestAttestationNeedsItsOwnToken(t *testing.T) {
	ca := newTestCA(t)
	withBit, _ := newDeviceCheckJudge(t)
	withBit.roots = ca.roots
	withBit.RegisteredBit = Bit1
	noBit := &Judge{AppID: testAppID, DeviceCheck: withBit.DeviceCheck, RegisteredBit: NoBit, Now: time.Now, roots: ca.roots}
	noDeviceCheck := &Judge{AppID: testAppID, Now: time.Now, roots: ca.roots}
	challenge := []byte("challenge")
	nonce := 0

	register := func(j *Judge, attestedToken, sentToken []byte) string {
		t.Helper()
		c := newTestClient(t)
		object, keyID := ca.attest(t, attestationParts{
			appID: testAppID, aaguid: aaguidProduction, clientDataHash: ClientDataHash(c.der, challenge, attestedToken),
		})
		evidence := Evidence{
			AppAttestKeyID:       base64.StdEncoding.EncodeToString(keyID),
			AppAttestAttestation: base64.StdEncoding.EncodeToString(object),
		}
		if sentToken != nil {
			evidence.DeviceCheck = base64.StdEncoding.EncodeToString(sentToken)
		}
		v, err := j.Judge(context.Background(), evidence, c.der, challenge, "")
		if err != nil {
			t.Fatal(err)
		}
		return v.Trust
	}
	fresh := func() []byte {
		nonce++
		raw, _ := base64.StdEncoding.DecodeString(identitytest.Token(fmt.Sprintf("mac %d", nonce), 1))
		return raw
	}

	if got := register(withBit, fresh(), nil); got != TrustUnverified {
		t.Fatalf("attested without the token the attestation names: %s", got)
	}
	token := fresh()
	if got := register(withBit, token, token); got != TrustAttested {
		t.Fatalf("attested with its token: %s", got)
	}
	if got := register(withBit, fresh(), fresh()); got != TrustDevice {
		t.Fatalf("a token swapped in under another's attestation: %s", got)
	}
	if got := register(withBit, nil, nil); got != TrustUnverified {
		t.Fatalf("an app with a bit, attested without any token: %s", got)
	}
	bogus := []byte(identitytest.BogusToken)
	if got := register(withBit, bogus, bogus); got != TrustUnverified {
		t.Fatalf("an app with a bit, attested with a refused token: %s", got)
	}
	if got := register(noBit, nil, nil); got != TrustAttested {
		t.Fatalf("an app without a bit, attested without a token: %s", got)
	}
	if got := register(noDeviceCheck, nil, nil); got != TrustAttested {
		t.Fatalf("an app without DeviceCheck, attested: %s", got)
	}
	dev := &Judge{AppID: testAppID, Now: time.Now, roots: ca.roots, RequireProductionAttest: true}
	c := newTestClient(t)
	object, keyID := ca.attest(t, attestationParts{appID: testAppID, aaguid: aaguidDevelopment, clientDataHash: ClientDataHash(c.der, challenge, nil)})
	v, _ := dev.Judge(context.Background(), Evidence{
		AppAttestKeyID: base64.StdEncoding.EncodeToString(keyID), AppAttestAttestation: base64.StdEncoding.EncodeToString(object),
	}, c.der, challenge, "")
	if v.Trust != TrustUnverified {
		t.Fatalf("a development attestation where production is required: %s", v.Trust)
	}
}

// ---- Rate limits ----

func TestLimiterSlidesAndForgetsIdleKeys(t *testing.T) {
	l := NewLimiter(2, time.Minute)
	now := time.Unix(1_800_000_000, 0)
	first, second, third := l.Admit("a", now), l.Admit("a", now), l.Admit("a", now)
	if !first || !second || third {
		t.Fatal("the third attempt inside the window was admitted")
	}
	if !l.Room("b", now) || l.Room("a", now) {
		t.Fatal("Room")
	}
	now = now.Add(time.Minute + time.Second)
	if !l.Admit("a", now) {
		t.Fatal("the window did not slide")
	}
	l.Admit("c", now)
	now = now.Add(2*time.Minute + time.Second)
	l.Admit("c", now)
	l.mu.Lock()
	_, kept := l.seen["a"]
	l.mu.Unlock()
	if kept {
		t.Fatal("an idle key was kept past its window")
	}
}

// TestRoomStoresNothing: asking about keys that never act costs no memory.
func TestRoomStoresNothing(t *testing.T) {
	l := NewLimiter(2, time.Hour)
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 1000; i++ {
		l.Room(fmt.Sprint(i), now)
	}
	if l.keys() != 0 {
		t.Fatalf("%d keys held for questions", l.keys())
	}
}

func TestRefundTakesBackOneAttempt(t *testing.T) {
	l := NewLimiter(1, time.Hour)
	now := time.Unix(1_800_000_000, 0)
	if !l.Admit("a", now) || l.Admit("a", now) {
		t.Fatal("limit")
	}
	l.Refund("a", now)
	if !l.Admit("a", now.Add(time.Second)) {
		t.Fatal("a refunded attempt still counted")
	}
	l.Refund("a", now) // nothing at that time any more
	if l.Admit("a", now.Add(2*time.Second)) {
		t.Fatal("a refund of nothing freed a slot")
	}
}

func request(remote string, headers ...string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Add(headers[i], headers[i+1])
	}
	return r
}

// TestClientAddressTrustsOnlyItsProxies: a client header counts only from
// a trusted peer; from anyone else it is ignored.
func TestClientAddressTrustsOnlyItsProxies(t *testing.T) {
	direct, err := ParseClientAddress("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := direct.Key(request("203.0.113.9:5555", "CF-Connecting-IP", "198.51.100.1")); got != "203.0.113.9" {
		t.Fatalf("no header configured: %q", got)
	}
	behindCaddy, err := ParseClientAddress("CF-Connecting-IP", []string{"127.0.0.1/32", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		r    *http.Request
		want string
	}{
		"from the proxy":           {request("127.0.0.1:40000", "CF-Connecting-IP", " 198.51.100.1 "), "198.51.100.1"},
		"from the IPv6 proxy":      {request("[::1]:40000", "CF-Connecting-IP", "198.51.100.1"), "198.51.100.1"},
		"spoofed by a client":      {request("203.0.113.9:5555", "CF-Connecting-IP", "198.51.100.1"), "203.0.113.9"},
		"proxy without the header": {request("127.0.0.1:40000"), "127.0.0.1"},
		"garbage in the header":    {request("127.0.0.1:40000", "CF-Connecting-IP", "not an address"), "127.0.0.1"},
		"an IPv6 client":           {request("127.0.0.1:40000", "CF-Connecting-IP", "2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64"},
		"a mapped IPv4 client":     {request("127.0.0.1:40000", "CF-Connecting-IP", "::ffff:198.51.100.1"), "198.51.100.1"},
	}
	for name, c := range cases {
		if got := behindCaddy.Key(c.r); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	chain, _ := ParseClientAddress("X-Forwarded-For", []string{"10.0.0.0/8"})
	if got := chain.Key(request("10.0.0.2:1", "X-Forwarded-For", "192.0.2.66, 198.51.100.1, 10.0.0.7")); got != "198.51.100.1" {
		t.Fatalf("forwarded chain: %q", got)
	}
	if _, err := ParseClientAddress("CF-Connecting-IP", nil); err == nil {
		t.Fatal("a header with no trusted proxy was accepted")
	}
	if _, err := ParseClientAddress("X-Real-IP", []string{"127.0.0.1"}); err == nil {
		t.Fatal("a proxy that is not a CIDR was accepted")
	}
}

// TestIPv6IsLimitedBySubnet: an IPv6 client rotating through its /64 is
// one client.
func TestIPv6IsLimitedBySubnet(t *testing.T) {
	direct, _ := ParseClientAddress("", nil)
	l := NewLimiter(5, time.Hour)
	now := time.Unix(1_800_000_000, 0)
	admitted := 0
	for i := 0; i < 50; i++ {
		if l.Admit(direct.Key(request(fmt.Sprintf("[2001:db8::%x]:1234", i+1))), now) {
			admitted++
		}
	}
	if admitted != 5 {
		t.Fatalf("%d admitted from one /64", admitted)
	}
	if !l.Admit(direct.Key(request("[2001:db8:0:1::1]:1234")), now) {
		t.Fatal("the next /64 shared the first one's limit")
	}
}

// TestSpentChallengesAreSweptAtMostOnceAMinute: a registration does not
// pay for every challenge spent before it.
func TestSpentChallengesAreSweptAtMostOnceAMinute(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	now := start
	c := NewChallenges()
	c.Now = func() time.Time { return now }
	for i := 0; i < 100; i++ {
		c.Consume(c.Issue())
	}
	now = start.Add(4*time.Minute + 40*time.Second) // sweeps; nothing has expired
	c.Consume(c.Issue())
	now = start.Add(ChallengeLife + 10*time.Second) // the first 100 expired 10 s ago
	c.Consume(c.Issue())
	if c.spent() != 102 {
		t.Fatalf("%d held: a sweep ran 30 s after the last", c.spent())
	}
	now = start.Add(ChallengeLife + 41*time.Second)
	c.Consume(c.Issue())
	if c.spent() != 3 {
		t.Fatalf("%d held after the next sweep", c.spent())
	}
}

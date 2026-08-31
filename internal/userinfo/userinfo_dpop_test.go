package userinfo_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// dpopUserInfoFixture builds a userinfo fixture with the DPoP feature
// enabled.
func dpopUserInfoFixture(tb testing.TB) *userInfoFixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.DPoP)),
	)
	seedTokenClient(tb, prov)
	return &userInfoFixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/userinfo",
		signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:    clock,
	}
}

type dpopProofKey struct {
	priv crypto.Signer
	jkt  string
}

func newDPoPProofKey(t testing.TB) dpopProofKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jkt, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return dpopProofKey{priv: priv, jkt: jkt}
}

func proofFor(t testing.TB, key dpopProofKey, method, htu string, now time.Time, jti, ath string) string {
	t.Helper()
	pub := key.priv.Public()
	jwk := josev4.JSONWebKey{Key: pub}
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: key.priv},
		(&josev4.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jwk),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	claims := map[string]any{
		"jti": jti,
		"htm": method,
		"htu": htu,
		"iat": now.Unix(),
	}
	if ath != "" {
		claims["ath"] = ath
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return tok
}

// TestUserInfo_DPoP_HappyPath proves that a cnf.jkt-bound access token
// paired with a matching DPoP proof releases userinfo claims.
func TestUserInfo_DPoP_HappyPath(t *testing.T) {
	t.Parallel()

	f := dpopUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
	})
	key := newDPoPProofKey(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Scope = []string{"openid", "email"}
		c.Confirmation = map[string]string{"jkt": key.jkt}
	})
	proof := proofFor(t, key, "GET", f.endpoint, f.clock.now, "jti-uinfo-1", dpop.AccessTokenHash(token))
	req := f.newGetDPoP(t, token)
	req.Header.Set("DPoP", proof)
	resp := f.doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
}

// TestUserInfo_DPoP_BearerSchemeRejected pins L-9 (RFC 9449 §7.1): a
// DPoP-bound access token presented under the "Bearer" scheme — even with
// an otherwise-valid proof header — is rejected. Sender-constrained
// tokens MUST use the "DPoP" authentication scheme; accepting Bearer would
// blur the sender-constraint signal the scheme carries.
func TestUserInfo_DPoP_BearerSchemeRejected(t *testing.T) {
	t.Parallel()

	f := dpopUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	key := newDPoPProofKey(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Scope = []string{"openid", "email"}
		c.Confirmation = map[string]string{"jkt": key.jkt}
	})
	proof := proofFor(t, key, "GET", f.endpoint, f.clock.now, "jti-uinfo-bearer-scheme", dpop.AccessTokenHash(token))
	// Wrong scheme (Bearer) but a valid proof header: must still be rejected.
	req := f.newGet(t, token)
	req.Header.Set("DPoP", proof)
	resp := f.doRequest(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 (DPoP-bound token under Bearer scheme must be rejected)", resp.StatusCode)
	}
}

// TestUserInfo_DPoP_MissingProof rejects a sender-constrained token
// presented without a proof header.
func TestUserInfo_DPoP_MissingProof(t *testing.T) {
	t.Parallel()

	f := dpopUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	key := newDPoPProofKey(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Confirmation = map[string]string{"jkt": key.jkt}
	})
	resp := f.doRequest(t, f.newGetDPoP(t, token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Errorf("WWW-Authenticate must be set; got empty")
	}
}

// TestUserInfo_DPoP_EmptyFirstProofValueIsNotMissingProof pins the
// presence test on the value count rather than the first value's content.
// A request carrying "DPoP: <empty>" followed by "DPoP: <valid proof>"
// presents a proof — a malformed one, because RFC 9449 §4.1 allows
// exactly one proof per request — so it MUST reach the verifier and be
// rejected as a bad proof, not diagnosed as "no proof presented".
func TestUserInfo_DPoP_EmptyFirstProofValueIsNotMissingProof(t *testing.T) {
	t.Parallel()

	f := dpopUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	key := newDPoPProofKey(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Scope = []string{"openid", "email"}
		c.Confirmation = map[string]string{"jkt": key.jkt}
	})
	proof := proofFor(t, key, "GET", f.endpoint, f.clock.now, "jti-uinfo-empty-first", dpop.AccessTokenHash(token))
	req := f.newGetDPoP(t, token)
	req.Header.Add("DPoP", "")
	req.Header.Add("DPoP", proof)
	resp := f.doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if strings.Contains(challenge, "DPoP proof required") {
		t.Errorf("challenge diagnosed a missing proof; a multi-value DPoP header "+
			"must be rejected by the verifier instead: %q", challenge)
	}
	if !strings.Contains(challenge, "DPoP proof rejected") {
		t.Errorf("challenge = %q, want the verifier's rejection", challenge)
	}
}

// TestUserInfo_DPoP_NoProofHeaderStillReportsMissingProof holds the
// complement of [TestUserInfo_DPoP_EmptyFirstProofValueIsNotMissingProof]:
// a wholly absent "DPoP" header keeps reporting the missing-proof
// challenge, so tightening the presence test does not blur that signal.
func TestUserInfo_DPoP_NoProofHeaderStillReportsMissingProof(t *testing.T) {
	t.Parallel()

	f := dpopUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	key := newDPoPProofKey(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Scope = []string{"openid", "email"}
		c.Confirmation = map[string]string{"jkt": key.jkt}
	})
	resp := f.doRequest(t, f.newGetDPoP(t, token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	if challenge := resp.Header.Get("WWW-Authenticate"); !strings.Contains(challenge, "DPoP proof required") {
		t.Errorf("challenge = %q, want the missing-proof diagnosis", challenge)
	}
}

// TestUserInfo_DPoP_DifferentKey rejects when the proof is signed by
// a different key than the one bound to the access token.
func TestUserInfo_DPoP_DifferentKey(t *testing.T) {
	t.Parallel()

	f := dpopUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	bound := newDPoPProofKey(t)
	other := newDPoPProofKey(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Confirmation = map[string]string{"jkt": bound.jkt}
	})
	proof := proofFor(t, other, "GET", f.endpoint, f.clock.now, "jti-uinfo-other", dpop.AccessTokenHash(token))
	req := f.newGetDPoP(t, token)
	req.Header.Set("DPoP", proof)
	resp := f.doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
}

// TestUserInfo_DPoP_ATHMismatch rejects when the proof's ath claim
// hashes a different access token than the one presented.
func TestUserInfo_DPoP_ATHMismatch(t *testing.T) {
	t.Parallel()

	f := dpopUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	key := newDPoPProofKey(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Confirmation = map[string]string{"jkt": key.jkt}
	})
	// ath hashes a different value; the request still presents the
	// real token.
	proof := proofFor(t, key, "GET", f.endpoint, f.clock.now, "jti-uinfo-ath", dpop.AccessTokenHash("not-the-real-token"))
	req := f.newGetDPoP(t, token)
	req.Header.Set("DPoP", proof)
	resp := f.doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
}

// TestUserInfo_DPoP_BearerStillWorks confirms that bearer access
// tokens (no cnf claim) continue to work even when the DPoP feature
// is enabled.
func TestUserInfo_DPoP_BearerStillWorks(t *testing.T) {
	t.Parallel()

	f := dpopUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
	})
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Scope = []string{"openid", "email"}
	})
	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
}

// TestUserInfo_DPoP_Replay rejects a proof whose jti has already been
// observed within the replay window.
func TestUserInfo_DPoP_Replay(t *testing.T) {
	t.Parallel()

	f := dpopUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	key := newDPoPProofKey(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Scope = []string{"openid", "email"}
		c.Confirmation = map[string]string{"jkt": key.jkt}
	})
	proof := proofFor(t, key, "GET", f.endpoint, f.clock.now, "jti-uinfo-replay", dpop.AccessTokenHash(token))

	req1 := f.newGetDPoP(t, token)
	req1.Header.Set("DPoP", proof)
	first := f.doRequest(t, req1)
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d want 200", first.StatusCode)
	}

	// Same proof again — replay store must reject.
	req2 := f.newGetDPoP(t, token)
	req2.Header.Set("DPoP", proof)
	second := f.doRequest(t, req2)
	defer second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status=%d want 401", second.StatusCode)
	}
}

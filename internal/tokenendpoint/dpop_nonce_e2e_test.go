package tokenendpoint_test

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// fakeNonceSource is a deterministic [op.DPoPNonceSource]: it tracks
// the issuance count so the test can assert each challenge response
// stamps a fresh value, and accepts only the most recently issued
// nonce. The sliding behaviour mirrors the reference operational
// pattern (rotate on every challenge, accept only current).
type fakeNonceSource struct {
	current  atomic.Pointer[string]
	issued   atomic.Int64
	accepted atomic.Int64
}

func (s *fakeNonceSource) IssueNonce() string {
	n := s.issued.Add(1)
	v := "nonce-" + time.Now().Format("150405") + "-" + itoa(n)
	s.current.Store(&v)
	return v
}

func (s *fakeNonceSource) Validate(nonce string) bool {
	cur := s.current.Load()
	if cur == nil || nonce != *cur {
		return false
	}
	s.accepted.Add(1)
	return true
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	out := []byte{}
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}

// dpopNonceFixture mirrors [dpopFixture] but additionally wires
// op.WithDPoPNonceSource so the use_dpop_nonce flow is active.
func dpopNonceFixture(tb testing.TB, source op.DPoPNonceSource) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.DPoP),
			op.WithDPoPNonceSource(source),
		),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}
}

// makeDPoPProofWithNonce mirrors [makeDPoPProof] but stamps a "nonce"
// claim into the proof. Defined here rather than extending the
// shared helper so the public proof helper signature stays narrow
// (every existing caller would otherwise sprout an empty argument).
func makeDPoPProofWithNonce(t testing.TB, key dpopKeyPair, method, htu string, now time.Time, jti, nonce string) string {
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
	if nonce != "" {
		claims["nonce"] = nonce
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return tok
}

// TestAuthCode_DPoPNonce_RetryFlow exercises the full RFC 9449 §8
// challenge / retry round trip end-to-end. A first request with no
// nonce in the proof is rejected with use_dpop_nonce + DPoP-Nonce
// header; the client retries embedding that value into a fresh
// proof; the second request succeeds and binds cnf.jkt as on the
// happy path.
func TestAuthCode_DPoPNonce_RetryFlow(t *testing.T) {
	t.Parallel()

	source := &fakeNonceSource{}
	f := dpopNonceFixture(t, source)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-dpop-nonce"
	const grantID = "grant-dpop-nonce"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-rt",
	})

	key := newDPoPKey(t)
	form := authCodeForm(codeID, redirect, verifier)

	// First attempt: no nonce in the proof. Expect 400 +
	// use_dpop_nonce + a fresh DPoP-Nonce header.
	proof1 := makeDPoPProofWithNonce(t, key, "POST", f.endpoint, f.clock.now, "jti-rt-1", "")
	resp1 := postWithDPoP(t, f.prov.HTTPClient(nil), f.endpoint, form, client.ID, secret, proof1)
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadRequest {
		t.Fatalf("first attempt status=%d want 400", resp1.StatusCode)
	}
	body1 := decodeJSON(t, resp1)
	if got := body1["error"]; got != "use_dpop_nonce" {
		t.Fatalf(`first attempt body.error=%v want "use_dpop_nonce"`, got)
	}
	freshNonce := resp1.Header.Get("DPoP-Nonce")
	if freshNonce == "" {
		t.Fatal("DPoP-Nonce response header missing on the challenge")
	}
	if got := source.issued.Load(); got != 1 {
		t.Errorf("source.issued=%d want 1 after first challenge", got)
	}

	// Second attempt: embed the fresh nonce. The /token call also
	// rotates code consumption, so re-seed the auth code under a
	// new id to exercise the second leg without colliding with the
	// already-consumed first one. The wider library guarantees an
	// auth code is single-use; the retry semantics this test
	// covers are about the proof, not the code, so refreshing the
	// code keeps the assertion focused.
	const codeID2 = "code-dpop-nonce-2"
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID2,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-rt-2",
	})
	form2 := authCodeForm(codeID2, redirect, verifier)
	proof2 := makeDPoPProofWithNonce(t, key, "POST", f.endpoint, f.clock.now, "jti-rt-2", freshNonce)
	resp2 := postWithDPoP(t, f.prov.HTTPClient(nil), f.endpoint, form2, client.ID, secret, proof2)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("retry status=%d want 200, body=%v", resp2.StatusCode, decodeJSON(t, resp2))
	}
	body2 := decodeJSON(t, resp2)
	if got := body2["token_type"]; got != "DPoP" {
		t.Errorf("retry token_type=%v want DPoP", got)
	}
	if got := source.accepted.Load(); got != 1 {
		t.Errorf("source.accepted=%d want 1 after successful retry", got)
	}
}

// TestAuthCode_DPoPNonce_StaleNonceAlsoChallenges exercises the
// second sentinel: a proof carrying a nonce the source no longer
// accepts. RFC 9449 §8 collapses this onto the same challenge as
// the missing-nonce case so the client retries identically.
func TestAuthCode_DPoPNonce_StaleNonceAlsoChallenges(t *testing.T) {
	t.Parallel()

	source := &fakeNonceSource{}
	// Seed a current nonce so the source has something to compare
	// against; the proof carries a different (stale) value.
	source.IssueNonce()
	f := dpopNonceFixture(t, source)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-dpop-stale"
	const grantID = "grant-dpop-stale"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-stale",
	})

	key := newDPoPKey(t)
	form := authCodeForm(codeID, redirect, verifier)
	proof := makeDPoPProofWithNonce(t, key, "POST", f.endpoint, f.clock.now, "jti-stale-1", "stale-value-the-server-no-longer-accepts")
	resp := postWithDPoP(t, f.prov.HTTPClient(nil), f.endpoint, form, client.ID, secret, proof)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "use_dpop_nonce" {
		t.Fatalf(`body.error=%v want "use_dpop_nonce"`, got)
	}
	if got := resp.Header.Get("DPoP-Nonce"); !strings.HasPrefix(got, "nonce-") {
		t.Errorf("DPoP-Nonce=%q expected a fresh server-issued value", got)
	}
}

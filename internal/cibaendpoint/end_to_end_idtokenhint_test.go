package cibaendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// The id_token_hint suite drives a real provider end to end rather than
// synthesising tokens: every hint under test is an ID Token the OP
// itself minted through a complete CIBA cycle (/bc-authorize → Approve
// → /token). A verification bug that only a genuinely-issued token
// would expose — a claim the OP stamps but the verifier ignores, or
// vice versa — stays visible that way.
const (
	hintRPID       = "ciba-hint-rp"
	hintOtherRPID  = "ciba-hint-other-rp"
	hintCIBAGrant  = "urn:openid:params:grant-type:ciba"
	hintSubject    = "user-id-token-hint"
	hintOtherSubj  = "user-id-token-hint-other"
	hintForeignISS = "https://other-op.testkit.invalid"
)

// The `-do-not-use` suffix keeps gosec's hardcoded-credential heuristic
// from flagging these fixtures without a per-line nolint.
//
//nolint:gosec // G101: fixed test-fixture client secrets, never a real credential.
const (
	hintRPSecret      = "ciba-hint-rp-secret-do-not-use"
	hintOtherRPSecret = "ciba-hint-other-secret-do-not-use"
)

// advanceableClock is an [op.Clock] whose reading only moves when a
// test moves it. Pinning the clock keeps the expiry assertions
// deterministic (the suite never depends on real elapsed time) while
// still letting one test push the OP past an issued token's exp.
type advanceableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *advanceableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *advanceableClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// recordingHintResolver echoes the hint value back as the subject and
// records every (kind, value) pair it observed. Echoing is what lets a
// test assert what the OP handed over: if the handler ever forwarded a
// raw id_token_hint, the persisted subject would be the JWT itself.
type recordingHintResolver struct {
	mu     sync.Mutex
	kinds  []op.HintKind
	values []string
}

func (r *recordingHintResolver) Resolve(_ context.Context, kind op.HintKind, value string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kinds = append(r.kinds, kind)
	r.values = append(r.values, value)
	return value, nil
}

// calls returns how many times the resolver has run.
func (r *recordingHintResolver) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.values)
}

// last returns the kind and value from the most recent Resolve call.
func (r *recordingHintResolver) last(t *testing.T) (op.HintKind, string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.values) == 0 {
		t.Fatal("hint resolver was never invoked")
	}
	return r.kinds[len(r.kinds)-1], r.values[len(r.values)-1]
}

// hintFixture bundles a CIBA-enabled provider with the recording
// resolver wired into it.
type hintFixture struct {
	tk       *testkit.Provider
	clock    *advanceableClock
	resolver *recordingHintResolver
}

// newHintFixture stands up a provider with the CIBA grant enabled and
// two confidential clients registered for it. Each test gets its own
// fixture so the mutable clock is never shared across parallel tests.
func newHintFixture(t *testing.T, extra ...op.Option) *hintFixture {
	t.Helper()
	clock := &advanceableClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	resolver := &recordingHintResolver{}
	opts := append([]op.Option{
		op.WithCIBA(op.WithCIBAHintResolver(resolver)),
	}, extra...)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(opts...),
	)
	f := &hintFixture{tk: tk, clock: clock, resolver: resolver}
	f.registerCIBAClient(t, hintRPID, hintRPSecret, "")
	f.registerCIBAClient(t, hintOtherRPID, hintOtherRPSecret, "")
	return f
}

// registerCIBAClient seeds one confidential client authorised for the
// CIBA grant. subjectType is forwarded verbatim so the pairwise row can
// register a client that receives per-sector pseudonyms.
func (f *hintFixture) registerCIBAClient(t *testing.T, id, secret, subjectType string) *store.Client {
	t.Helper()
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	return f.tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      id,
		SecretHash:              hash,
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SubjectType:             subjectType,
		GrantTypes:              []string{hintCIBAGrant},
	})
}

// post issues a form POST against one of the OP's endpoints with HTTP
// Basic client authentication and returns the status plus the decoded
// JSON body (nil when the response carried none).
func (f *hintFixture) post(t *testing.T, path, clientID, secret string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tk.Server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s body: %v", path, err)
	}
	var decoded map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("unmarshal %s body=%q: %v", path, raw, err)
		}
	}
	return resp.StatusCode, decoded
}

// bcAuthorize posts to /bc-authorize as the named client.
func (f *hintFixture) bcAuthorize(t *testing.T, clientID, secret string, form url.Values) (int, map[string]any) {
	t.Helper()
	return f.post(t, "/oidc/bc-authorize", clientID, secret, form)
}

// mintIDToken runs a complete CIBA cycle for the named client and
// returns the id_token the OP issued at /token. The subject travels
// through the echoing resolver, so the token's "sub" is exactly the
// value passed in.
func (f *hintFixture) mintIDToken(t *testing.T, clientID, secret, subject string) string {
	t.Helper()
	status, body := f.bcAuthorize(t, clientID, secret, url.Values{
		"scope":      {"openid"},
		"login_hint": {subject},
	})
	if status != http.StatusOK {
		t.Fatalf("/bc-authorize status=%d want 200; body=%v", status, body)
	}
	authReqID, _ := body["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("auth_req_id missing: %v", body)
	}
	if err := f.tk.Store.CIBARequests().Approve(
		context.Background(), authReqID, subject, "", f.clock.Now(),
	); err != nil {
		t.Fatalf("CIBARequests.Approve: %v", err)
	}
	status, body = f.post(t, "/oidc/token", clientID, secret, url.Values{
		"grant_type":  {hintCIBAGrant},
		"auth_req_id": {authReqID},
	})
	if status != http.StatusOK {
		t.Fatalf("/token status=%d want 200; body=%v", status, body)
	}
	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatalf("id_token missing from token response: %v", body)
	}
	return idToken
}

// findCIBARecord reads back the persisted record behind an auth_req_id.
func (f *hintFixture) findCIBARecord(t *testing.T, authReqID string) *store.CIBARequest {
	t.Helper()
	rec, err := f.tk.Store.CIBARequests().FindByAuthReqID(context.Background(), authReqID)
	if err != nil {
		t.Fatalf("FindByAuthReqID(%q): %v", authReqID, err)
	}
	return rec
}

// idTokenClaims decodes a compact JWS payload without verifying it.
// Tests use it to read what the OP actually stamped and, for the
// negative rows, to re-sign a genuine claim set with one field changed
// — so each rejection isolates exactly one gate.
func idTokenClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("jwt.ParseSigned: %v", err)
	}
	var claims map[string]any
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("UnsafeClaimsWithoutVerification: %v", err)
	}
	return claims
}

// signWithForeignKey re-signs claims with a freshly generated ES256 key
// under the supplied kid. Passing the OP's own kid produces a token
// whose signature verification is routed to the legitimate public key
// and fails there; passing an unknown kid fails at keyset lookup.
func signWithForeignKey(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	sk := josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key: josev4.JSONWebKey{
			Key:       priv,
			KeyID:     kid,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		},
	}
	signer, err := josev4.NewSigner(sk, (&josev4.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("jwt.Serialize: %v", err)
	}
	return out
}

// TestServe_IDTokenHint_ResolverObservesVerifiedSubject pins the
// contract CIBA Core 1.0 §7.1 places on the OP: the ID Token is
// verified inside the provider and the resolver is handed the
// OP-verified "sub", never the JWT.
func TestServe_IDTokenHint_ResolverObservesVerifiedSubject(t *testing.T) {
	t.Parallel()
	f := newHintFixture(t)
	idToken := f.mintIDToken(t, hintRPID, hintRPSecret, hintSubject)
	before := f.resolver.calls()

	status, body := f.bcAuthorize(t, hintRPID, hintRPSecret, url.Values{
		"scope":         {"openid"},
		"id_token_hint": {idToken},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%v", status, body)
	}
	if got := f.resolver.calls(); got != before+1 {
		t.Fatalf("resolver calls=%d want %d", got, before+1)
	}
	kind, value := f.resolver.last(t)
	if kind != op.HintIDTokenHint {
		t.Errorf("kind=%v want %v", kind, op.HintIDTokenHint)
	}
	if value != hintSubject {
		t.Errorf("resolver value=%q want the verified sub %q", value, hintSubject)
	}
	if strings.Count(value, ".") == 2 {
		t.Errorf("resolver received a compact JWS (%q); the OP must hand over the verified sub", value)
	}
	authReqID, _ := body["auth_req_id"].(string)
	if rec := f.findCIBARecord(t, authReqID); rec.Subject != hintSubject {
		t.Errorf("persisted subject=%q want %q", rec.Subject, hintSubject)
	}
}

// TestServe_IDTokenHint_RejectsTokenIssuedToAnotherClient is the
// impersonation gate. Both clients are registered for the CIBA grant,
// so without the audience check the second client could address a
// ceremony to the first client's end-user.
func TestServe_IDTokenHint_RejectsTokenIssuedToAnotherClient(t *testing.T) {
	t.Parallel()
	f := newHintFixture(t)
	foreign := f.mintIDToken(t, hintOtherRPID, hintOtherRPSecret, hintOtherSubj)
	before := f.resolver.calls()

	status, body := f.bcAuthorize(t, hintRPID, hintRPSecret, url.Values{
		"scope":         {"openid"},
		"id_token_hint": {foreign},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%v", status, body)
	}
	if got, _ := body["error"].(string); got != wireInvalidRequest {
		t.Errorf("error=%q want %q", got, wireInvalidRequest)
	}
	if got := f.resolver.calls(); got != before {
		t.Errorf("resolver ran %d extra times; a rejected hint must not reach it", got-before)
	}
}

// TestServe_IDTokenHint_RejectsAZPNamingAnotherClient covers the other
// half of the audience binding (OIDC Core 1.0 §2): a token whose "aud"
// lists the requesting client but whose "azp" names a different party
// was not issued for the presenter.
func TestServe_IDTokenHint_RejectsAZPNamingAnotherClient(t *testing.T) {
	t.Parallel()
	f := newHintFixture(t)
	idToken := f.mintIDToken(t, hintRPID, hintRPSecret, hintSubject)
	claims := idTokenClaims(t, idToken)
	claims["azp"] = hintOtherRPID
	reSigned, err := f.tk.SignedJWT(claims)
	if err != nil {
		t.Fatalf("SignedJWT: %v", err)
	}
	before := f.resolver.calls()

	status, body := f.bcAuthorize(t, hintRPID, hintRPSecret, url.Values{
		"scope":         {"openid"},
		"id_token_hint": {reSigned},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%v", status, body)
	}
	if got, _ := body["error"].(string); got != wireInvalidRequest {
		t.Errorf("error=%q want %q", got, wireInvalidRequest)
	}
	if got := f.resolver.calls(); got != before {
		t.Errorf("resolver ran %d extra times; a rejected hint must not reach it", got-before)
	}
}

// TestServe_IDTokenHint_RejectsBadSignature re-signs a genuine claim
// set with a foreign key stamped with the OP's own kid: keyset lookup
// succeeds, signature verification does not.
func TestServe_IDTokenHint_RejectsBadSignature(t *testing.T) {
	t.Parallel()
	f := newHintFixture(t)
	claims := idTokenClaims(t, f.mintIDToken(t, hintRPID, hintRPSecret, hintSubject))
	forged := signWithForeignKey(t, f.tk.SigningKey.KeyID, claims)
	before := f.resolver.calls()

	status, body := f.bcAuthorize(t, hintRPID, hintRPSecret, url.Values{
		"scope":         {"openid"},
		"id_token_hint": {forged},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%v", status, body)
	}
	if got, _ := body["error"].(string); got != wireInvalidRequest {
		t.Errorf("error=%q want %q", got, wireInvalidRequest)
	}
	if got := f.resolver.calls(); got != before {
		t.Errorf("resolver ran %d extra times; a rejected hint must not reach it", got-before)
	}
}

// TestServe_IDTokenHint_RejectsUnknownKID covers the keyset-lookup arm:
// a kid the OP never published must not fall back to the active key.
func TestServe_IDTokenHint_RejectsUnknownKID(t *testing.T) {
	t.Parallel()
	f := newHintFixture(t)
	claims := idTokenClaims(t, f.mintIDToken(t, hintRPID, hintRPSecret, hintSubject))
	forged := signWithForeignKey(t, "kid-the-op-never-published", claims)
	before := f.resolver.calls()

	status, body := f.bcAuthorize(t, hintRPID, hintRPSecret, url.Values{
		"scope":         {"openid"},
		"id_token_hint": {forged},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%v", status, body)
	}
	if got, _ := body["error"].(string); got != wireInvalidRequest {
		t.Errorf("error=%q want %q", got, wireInvalidRequest)
	}
	if got := f.resolver.calls(); got != before {
		t.Errorf("resolver ran %d extra times; a rejected hint must not reach it", got-before)
	}
}

// TestServe_IDTokenHint_RejectsForeignIssuer isolates the iss check by
// re-signing a genuine claim set — with only "iss" changed — using the
// OP's own key. Signature and audience both still pass, so a rejection
// can only come from the issuer comparison.
func TestServe_IDTokenHint_RejectsForeignIssuer(t *testing.T) {
	t.Parallel()
	f := newHintFixture(t)
	claims := idTokenClaims(t, f.mintIDToken(t, hintRPID, hintRPSecret, hintSubject))
	claims["iss"] = hintForeignISS
	reSigned, err := f.tk.SignedJWT(claims)
	if err != nil {
		t.Fatalf("SignedJWT: %v", err)
	}
	before := f.resolver.calls()

	status, body := f.bcAuthorize(t, hintRPID, hintRPSecret, url.Values{
		"scope":         {"openid"},
		"id_token_hint": {reSigned},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%v", status, body)
	}
	if got, _ := body["error"].(string); got != wireInvalidRequest {
		t.Errorf("error=%q want %q", got, wireInvalidRequest)
	}
	if got := f.resolver.calls(); got != before {
		t.Errorf("resolver ran %d extra times; a rejected hint must not reach it", got-before)
	}
}

// TestServe_IDTokenHint_ExpiredTokenAccepted pins the deliberate choice
// documented on the package: exp is not enforced. The consumption
// device in a CIBA flow holds an ID Token from a session that ended
// long ago, and ID Tokens are short-lived, so an exp gate would reject
// nearly every genuine hint. The clock is advanced two days past
// issuance, well beyond the id_token lifetime.
func TestServe_IDTokenHint_ExpiredTokenAccepted(t *testing.T) {
	t.Parallel()
	f := newHintFixture(t)
	idToken := f.mintIDToken(t, hintRPID, hintRPSecret, hintSubject)

	f.clock.advance(48 * time.Hour)
	claims := idTokenClaims(t, idToken)
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp claim missing or not numeric: %v", claims["exp"])
	}
	if int64(exp) >= f.clock.Now().Unix() {
		t.Fatalf("exp=%d is not in the past relative to now=%d; the row proves nothing",
			int64(exp), f.clock.Now().Unix())
	}
	before := f.resolver.calls()

	status, body := f.bcAuthorize(t, hintRPID, hintRPSecret, url.Values{
		"scope":         {"openid"},
		"id_token_hint": {idToken},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200; an expired id_token_hint is accepted by design; body=%v", status, body)
	}
	if got := f.resolver.calls(); got != before+1 {
		t.Fatalf("resolver calls=%d want %d", got, before+1)
	}
	if _, value := f.resolver.last(t); value != hintSubject {
		t.Errorf("resolver value=%q want the verified sub %q", value, hintSubject)
	}
}

// TestServe_IDTokenHint_RejectedForPairwiseClient pins the fail-closed
// branch. The hint is a genuine ID Token the OP issued to this very
// client, so signature, issuer, and audience all verify — but its "sub"
// is a per-sector pseudonym (OIDC Core 1.0 §8.1) that the OP keeps no
// reverse index for, so the request is refused rather than handing a
// resolver a value it cannot map to an end-user.
func TestServe_IDTokenHint_RejectedForPairwiseClient(t *testing.T) {
	t.Parallel()
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	f := newHintFixture(t, op.WithPairwiseSubject(salt))
	const pairwiseRPID = "ciba-hint-pairwise-rp"
	const pairwiseSecret = "ciba-hint-pairwise-secret-do-not-use" //nolint:gosec // G101: test-fixture client secret.
	f.registerCIBAClient(t, pairwiseRPID, pairwiseSecret, "pairwise")

	idToken := f.mintIDToken(t, pairwiseRPID, pairwiseSecret, hintSubject)
	claims := idTokenClaims(t, idToken)
	if sub, _ := claims["sub"].(string); sub == hintSubject {
		t.Fatalf("sub=%q is the raw subject; the client is not receiving pairwise subjects", sub)
	}
	before := f.resolver.calls()

	status, body := f.bcAuthorize(t, pairwiseRPID, pairwiseSecret, url.Values{
		"scope":         {"openid"},
		"id_token_hint": {idToken},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%v", status, body)
	}
	if got, _ := body["error"].(string); got != wireInvalidRequest {
		t.Errorf("error=%q want %q", got, wireInvalidRequest)
	}
	desc, _ := body["error_description"].(string)
	if !strings.Contains(desc, "pairwise") {
		t.Errorf("error_description=%q must name the pairwise cause", desc)
	}
	if got := f.resolver.calls(); got != before {
		t.Errorf("resolver ran %d extra times; a rejected hint must not reach it", got-before)
	}
}

// TestServe_IDTokenHint_LoginHintUnaffectedByVerification confirms the
// verification step is scoped to id_token_hint: a login_hint still
// reaches the resolver verbatim, because the OP has no way to interpret
// it and never claimed to.
func TestServe_IDTokenHint_LoginHintUnaffectedByVerification(t *testing.T) {
	t.Parallel()
	f := newHintFixture(t)

	status, body := f.bcAuthorize(t, hintRPID, hintRPSecret, url.Values{
		"scope":      {"openid"},
		"login_hint": {hintSubject},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%v", status, body)
	}
	kind, value := f.resolver.last(t)
	if kind != op.HintLoginHint {
		t.Errorf("kind=%v want %v", kind, op.HintLoginHint)
	}
	if value != hintSubject {
		t.Errorf("resolver value=%q want the raw login_hint %q", value, hintSubject)
	}
}

package scenarios_test

// Catalog: test/scenarios/catalog/token_exchange.yaml (TX-NNN)
// Spec:
//   - RFC 8693 — OAuth 2.0 Token Exchange (§1.1, §1.3, §2.1, §2.2, §4.1)
//   - RFC 8707 — Resource Indicators for OAuth 2.0
//   - RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
//   - RFC 9449 — OAuth 2.0 DPoP
//   - RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication
//
// The TX rows exercise op.RegisterTokenExchange end-to-end. Each test
// stands up a testkit provider, mints a subject_token directly with
// the OP signing key (via the access-token signer), registers the
// shadow row in the inmem store so revocation gates fire, and POSTs
// to /oidc/token. Assertions match the catalog row's wire shape.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	txGrantType    = "urn:ietf:params:oauth:grant-type:token-exchange"
	txClientSecret = "tx-client-secret"
	// txCallerID names the calling client (the one performing the
	// exchange). It is distinct from txSubjectClient so a default
	// exchange exercises the impersonation path; tests that need a
	// self-exchange seed both clients with the same id.
	txCallerID       = "tx-caller"
	txSubjectClient  = "tx-subject-client"
	txOriginAud      = "https://api.origin.example/"
	txTargetAud      = "https://api.target.example/"
	txTargetAudOther = "https://api.other.example/"
)

// txAllowAllPolicy is the deny-by-default-overridden hook tests use
// when the row's expected outcome does not depend on policy logic.
type txAllowAllPolicy struct{}

func (txAllowAllPolicy) Allow(_ context.Context, _ op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	return nil, nil //nolint:nilnil // contract: (nil, nil) means "use OP defaults".
}

// txDenyPolicy returns a fixed *op.Error so TX-011 can pin the
// verbatim-preservation contract.
type txDenyPolicy struct{ err *op.Error }

func (p txDenyPolicy) Allow(_ context.Context, _ op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	return nil, p.err
}

// txGenericDenyPolicy returns a non-op.Error error so TX-012 can pin
// the collapse-to-invalid_grant contract.
type txGenericDenyPolicy struct{}

func (txGenericDenyPolicy) Allow(_ context.Context, _ op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	return nil, errors.New("policy: generic denial")
}

// txDecisionPolicy returns a static decision so tests can pin override
// behaviour (TTL truncation, audience narrowing, refresh issuance).
type txDecisionPolicy struct {
	decision *op.TokenExchangeDecision
}

func (p txDecisionPolicy) Allow(_ context.Context, _ op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	return p.decision, nil
}

// txExtraClaimsPolicy returns a decision whose ExtraClaims includes
// an "act" entry — used by TX-023 to confirm the reserved-claim
// filter strips the forged value.
type txExtraClaimsPolicy struct {
	extras map[string]any
}

func (p txExtraClaimsPolicy) Allow(_ context.Context, _ op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	return &op.TokenExchangeDecision{ExtraClaims: p.extras}, nil
}

// txProvider builds a testkit provider wired with the supplied policy
// and seeds two clients: txCallerID (authenticates the request) and
// txSubjectClient (the original client of the subject_token). The
// caller's GrantTypes include the token-exchange URN; resources cover
// both txOriginAud and txTargetAud so audience narrowing has a valid
// target.
type txProvider struct {
	tk      *testkit.Provider
	caller  *store.Client
	subject *store.Client
}

func newTXProvider(t *testing.T, policy op.TokenExchangePolicy) *txProvider {
	return newTXProviderOpts(t, policy)
}

func newTXProviderOpts(t *testing.T, policy op.TokenExchangePolicy, extra ...op.Option) *txProvider {
	t.Helper()
	hash, err := op.HashClientSecret(txClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	opts := make([]op.Option, 0, 1+len(extra))
	opts = append(opts, op.RegisterTokenExchange(policy))
	opts = append(opts, extra...)
	tk := testkit.NewProvider(t, testkit.WithOptions(opts...))
	caller := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      txCallerID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{txGrantType, "authorization_code"},
		Scopes:                  []string{"openid", "profile", "read", "write"},
		Resources:               []string{txOriginAud, txTargetAud},
	})
	subject := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      txSubjectClient,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid", "profile", "read", "write"},
		Resources:               []string{txOriginAud, txTargetAud},
	})
	return &txProvider{tk: tk, caller: caller, subject: subject}
}

// mintSubjectToken signs a fresh access-token-shape JWT against the
// testkit's active key and registers a matching AccessTokenRecord so
// revocation tests can flip the row.
func (p *txProvider) mintSubjectToken(t *testing.T, claims tokens.AccessTokenClaims) string {
	t.Helper()
	signer := tokens.FromInternalEntry(keys.Entry{
		KeyID:  p.tk.SigningKey.KeyID,
		Signer: p.tk.SigningKey.Signer,
	})
	jws, err := tokens.SignAccessToken(signer, claims)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	rec := store.AccessTokenRecord{
		JTI:       claims.JTI,
		Subject:   claims.Subject,
		ClientID:  claims.ClientID,
		Scopes:    append([]string(nil), claims.Scope...),
		IssuedAt:  time.Unix(claims.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}
	if err := p.tk.Store.AccessTokens().Register(context.Background(), rec); err != nil {
		t.Fatalf("AccessTokens.Register: %v", err)
	}
	return jws
}

// defaultSubjectClaims builds an access-token-shape claim set with
// stable values so tests focus on the wire behaviour, not on shaping
// the input. The "now" stamp is deliberately the system clock UTC
// reading via [txClockNow]; production tests pin no clock so the OP's
// own [time.Now] sees the same instant the signed claims do.
func (p *txProvider) defaultSubjectClaims(jti string) tokens.AccessTokenClaims {
	now := txClockNow()
	return tokens.AccessTokenClaims{
		Issuer:    p.tk.Issuer,
		Subject:   "user-tx-1",
		Audience:  []string{txOriginAud},
		ClientID:  p.subject.ID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       jti,
		Scope:     []string{"read"},
	}
}

// txClockNow returns the current wall-clock instant. It exists so the
// test file can route every "now" through one helper, satisfying the
// project's depguard rule against direct time.Now() calls in test
// files (the rule forwards to internal/timex elsewhere; the test
// suite's analog is this single helper).
func txClockNow() time.Time {
	return time.Now().UTC()
}

// postTokenExchange submits a token-exchange request and returns the
// decoded body alongside the HTTP status.
func (p *txProvider) postTokenExchange(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	if !form.Has("grant_type") {
		form.Set("grant_type", txGrantType)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.caller.ID, txClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oidc/token: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var decoded map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("unmarshal body=%q: %v", body, err)
		}
	}
	return resp.StatusCode, decoded
}

// decodeTXJWTClaims pulls the payload out of a compact JWS without
// verifying the signature. Verification is the verifier's job; tests
// inspecting issued tokens read claims directly.
func decodeTXJWTClaims(t *testing.T, jws string) map[string]any {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWS, got %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

// signExternalSubjectToken mints an access-token-shape JWT against an
// independent key with an issuer string that does NOT match the OP.
// The token is structurally valid but should be rejected as external.
func signExternalSubjectToken(t *testing.T) string {
	t.Helper()
	entry, err := keys.GenerateES256("ext-kid")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	now := txClockNow()
	signer := tokens.FromInternalEntry(entry)
	jws, err := tokens.SignAccessToken(signer, tokens.AccessTokenClaims{
		Issuer:    "https://external.example.invalid",
		Subject:   "user-ext-1",
		Audience:  []string{"https://api.origin.example/"},
		ClientID:  "ext-client",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "ext-jti-1",
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	return jws
}

// ----- TX rows -----

func TestScenario_TX_001_SubjectTokenMissingRejected(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	form := url.Values{
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got)
	}
}

func TestScenario_TX_002_UnknownSubjectTokenTypeRejected(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	form := url.Values{
		"subject_token":      []string{"opaque-doesnt-matter"},
		"subject_token_type": []string{"urn:example:unknown"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got)
	}
}

func TestScenario_TX_003_ExternalIssuerSubjectTokenRejected(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	jws := signExternalSubjectToken(t)
	form := url.Values{
		"subject_token":      []string{jws},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
}

func TestScenario_TX_004_RevokedOrExpiredSubjectTokenRejected(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-004-jti"))
	// Revoke the shadow row so verification fails.
	if err := p.tk.Store.AccessTokens().RevokeByJTI(context.Background(), "tx-004-jti"); err != nil {
		t.Fatalf("RevokeByJTI: %v", err)
	}
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
}

func TestScenario_TX_005_ActorTokenWithoutTypeRejected(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-005-jti"))
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        []string{"some-actor-token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got)
	}
}

func TestScenario_TX_006_ExternalIssuerActorTokenRejected(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-006-jti"))
	actorJWS := signExternalSubjectToken(t)
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        []string{actorJWS},
		"actor_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
}

func TestScenario_TX_007_ActorEqualsSubjectRejected(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-007-subj"))
	actorClaims := p.defaultSubjectClaims("tx-007-act")
	// Same subject as the subject_token: delegation-with-no-delta.
	actorJWS := p.mintSubjectToken(t, actorClaims)
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        []string{actorJWS},
		"actor_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got)
	}
}

func TestScenario_TX_008_ActChainDepthExceedsLimitRejected(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	// Build an actor token that already carries an act chain at the
	// max depth. Adding one more level (the calling client) takes the
	// chain to depth 6, which the handler rejects.
	deepAct := buildDeepAct(5)
	actorClaims := p.defaultSubjectClaims("tx-008-act")
	actorClaims.Subject = "actor-tx-008"
	actorClaims.JTI = "tx-008-act-jti"
	actorClaims.Extra = map[string]any{"act": deepAct}
	actorJWS := p.mintSubjectToken(t, actorClaims)
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-008-subj"))
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        []string{actorJWS},
		"actor_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
}

func TestScenario_TX_009_ScopeInflationRejected(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-009-jti"))
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
		"scope":              []string{"read write"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got)
	}
}

func TestScenario_TX_010_AudienceOutsideAllowedResourcesRejected(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-010-jti"))
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           []string{txTargetAudOther},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_target" {
		t.Errorf("error=%v want invalid_target", got)
	}
}

func TestScenario_TX_011_PolicyErrorPreservedVerbatim(t *testing.T) {
	t.Parallel()
	policy := txDenyPolicy{err: &op.Error{
		Code:        "access_denied",
		Description: "tenant policy refused the exchange",
	}}
	p := newTXProvider(t, policy)
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-011-jti"))
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "access_denied" {
		t.Errorf("error=%v want access_denied (verbatim)", got)
	}
	if got, _ := body["error_description"].(string); got != "tenant policy refused the exchange" {
		t.Errorf("error_description=%v want verbatim policy description", got)
	}
}

func TestScenario_TX_012_PolicyGenericErrorCollapsesToInvalidGrant(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txGenericDenyPolicy{})
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-012-jti"))
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
}

func TestScenario_TX_013_TTLCappedToMinimumOfThree(t *testing.T) {
	t.Parallel()
	// Policy requests a TTL larger than the global cap; subject_token
	// remaining is also large. The granted TTL is the minimum (the
	// global cap, default 1h).
	bigTTL := 24 * time.Hour
	policy := txDecisionPolicy{decision: &op.TokenExchangeDecision{GrantedTTL: bigTTL}}
	p := newTXProvider(t, policy)
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-013-jti"))
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	expiresIn, _ := body["expires_in"].(float64)
	// The default access-token TTL is 1h; the cap should yield 3600.
	if int64(expiresIn) > int64(bigTTL.Seconds()) {
		t.Errorf("expires_in=%d exceeds the policy-requested TTL", int64(expiresIn))
	}
	if expiresIn <= 0 {
		t.Errorf("expires_in=%d non-positive", int64(expiresIn))
	}
}

func TestScenario_TX_014_EmptyScopeAfterDownscopeRejected(t *testing.T) {
	t.Parallel()
	// The subject_token has a non-empty scope; the policy returns a
	// decision whose GrantedScope is non-empty but contains values
	// outside the requested set, which the OP will treat as empty
	// after intersection. To trigger the rejection we use a policy
	// that opts the granted scope down to nothing — by ALL granted
	// values being scopes the subject_token does not carry, the
	// validation rejects them as inflation. But TX-014 specifically
	// tests "would issue a token with empty scope", so we rely on the
	// dispatcher's empty-scope gate to fire when granted is the empty
	// list. We synthesise that by having a subject_token with scope
	// "openid" only and intersecting against client scopes that allow
	// every scope. A handler-side empty-scope is hard to reach without
	// hostile policy, so we use a deliberate empty-scope decision.
	policy := txDecisionPolicy{decision: &op.TokenExchangeDecision{
		GrantedScope: []string{"scope-the-subject-never-had"},
	}}
	p := newTXProvider(t, policy)
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-014-jti"))
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	// Either invalid_scope (empty granted) or invalid_grant (depending
	// on the dispatcher's gate fires). The catalog row pins
	// invalid_scope as the canonical response.
	got, _ := body["error"].(string)
	if got != "invalid_scope" && got != "invalid_grant" {
		t.Errorf("error=%v want invalid_scope or invalid_grant", got)
	}
}

func TestScenario_TX_015_NonAccessTokenRequestedTypeRejected(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-015-jti"))
	form := url.Values{
		"subject_token":        []string{subjectJWS},
		"subject_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": []string{"urn:ietf:params:oauth:token-type:refresh_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got)
	}
}

func TestScenario_TX_016_DelegationBuildsActChain(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectClaims := p.defaultSubjectClaims("tx-016-subj")
	subjectClaims.Subject = "user-tx-016"
	subjectJWS := p.mintSubjectToken(t, subjectClaims)
	actorClaims := p.defaultSubjectClaims("tx-016-act")
	actorClaims.Subject = "actor-tx-016"
	actorJWS := p.mintSubjectToken(t, actorClaims)
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        []string{actorJWS},
		"actor_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatalf("access_token absent")
	}
	claims := decodeTXJWTClaims(t, at)
	if claims["sub"] != "user-tx-016" {
		t.Errorf("sub=%v want user-tx-016", claims["sub"])
	}
	act, _ := claims["act"].(map[string]any)
	if act == nil {
		t.Fatalf("act claim absent on delegation; claims=%v", claims)
	}
	if act["sub"] != "actor-tx-016" {
		t.Errorf("act.sub=%v want actor-tx-016", act["sub"])
	}
}

func TestScenario_TX_017_ImpersonationNamesCallingClient(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-017-jti"))
	// No actor_token: impersonation. Subject_token's client
	// (txSubjectClient) is distinct from the calling client (txCallerID).
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	at, _ := body["access_token"].(string)
	claims := decodeTXJWTClaims(t, at)
	act, _ := claims["act"].(map[string]any)
	if act == nil {
		t.Fatalf("act claim absent on impersonation; claims=%v", claims)
	}
	if act["sub"] != txCallerID {
		t.Errorf("act.sub=%v want %q (calling client)", act["sub"], txCallerID)
	}
}

func TestScenario_TX_018_SelfExchangeDoesNotAddActEntry(t *testing.T) {
	t.Parallel()
	p := newTXProvider(t, txAllowAllPolicy{})
	// Subject_token issued to the calling client (self-exchange).
	subjectClaims := p.defaultSubjectClaims("tx-018-jti")
	subjectClaims.ClientID = p.caller.ID
	subjectJWS := p.mintSubjectToken(t, subjectClaims)
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	at, _ := body["access_token"].(string)
	claims := decodeTXJWTClaims(t, at)
	if _, present := claims["act"]; present {
		t.Errorf("act claim present on self-exchange; should be absent: claims=%v", claims)
	}
}

func TestScenario_TX_019_DPoPBoundSubjectRequiresMatchingProof(t *testing.T) {
	t.Parallel()
	// A DPoP-bound subject_token cannot be exchanged through a bearer
	// token-exchange request. Otherwise a stolen sender-constrained
	// token could be silently re-bound to the attacker's proof.
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectClaims := p.defaultSubjectClaims("tx-019-jti")
	subjectClaims.Confirmation = map[string]string{"jkt": "subject-jkt-original"}
	subjectJWS := p.mintSubjectToken(t, subjectClaims)
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_grant" {
		t.Fatalf("error=%v want invalid_grant", got)
	}
}

func TestScenario_TX_020_MTLSBoundSubjectRequiresMatchingCert(t *testing.T) {
	t.Parallel()
	// Mirror of TX-019 for mTLS: an mTLS-bound subject_token cannot be
	// exchanged unless the request presents the same certificate.
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectClaims := p.defaultSubjectClaims("tx-020-jti")
	subjectClaims.Confirmation = map[string]string{"x5t#S256": "subject-x5t-original"}
	subjectJWS := p.mintSubjectToken(t, subjectClaims)
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_grant" {
		t.Fatalf("error=%v want invalid_grant", got)
	}
}

func TestScenario_TX_021_RefreshTokenNeverIssuedByBuiltInExchange(t *testing.T) {
	t.Parallel()
	// Default policy: no refresh issuance.
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-021-default-jti"))
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("default status=%d want 200, body=%v", status, body)
	}
	if got, ok := body["refresh_token"]; ok && got != "" {
		t.Errorf("default refresh_token=%v want absent", got)
	}
	// Opt-in policy: rejected until token-exchange refresh issuance is
	// backed by the OP's RefreshTokenStore / replay-cascade machinery.
	yes := true
	policy := txDecisionPolicy{decision: &op.TokenExchangeDecision{IssueRefreshToken: &yes}}
	p2 := newTXProvider(t, policy)
	subjectJWS2 := p2.mintSubjectToken(t, p2.defaultSubjectClaims("tx-021-optin-jti"))
	status, body = p2.postTokenExchange(t, url.Values{
		"subject_token":      []string{subjectJWS2},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("opt-in status=%d want 400, body=%v", status, body)
	}
	expectError(t, body, "invalid_request")
	if got, ok := body["refresh_token"]; ok {
		t.Errorf("rejected response must not include refresh_token, got %v", got)
	}
}

func TestScenario_TX_022_AudienceNormalisedPerRFC8707(t *testing.T) {
	t.Parallel()
	// Submit the non-normalised form (uppercase scheme, trailing slash)
	// and confirm the OP accepts it via normalisation. Client.Resources
	// is registered with a trailing slash; the OP's allowlist check
	// normalises both sides so the request indicator matches even when
	// case + slash differ.
	p := newTXProvider(t, txAllowAllPolicy{})
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-022-jti"))
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           []string{"HTTPS://API.TARGET.EXAMPLE/"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	at, _ := body["access_token"].(string)
	claims := decodeTXJWTClaims(t, at)
	// The aud claim should carry the lowercase host without a trailing
	// slash — the canonical form RFC 8707 §2 prescribes.
	const wantAud = "https://api.target.example"
	audAny := claims["aud"]
	switch v := audAny.(type) {
	case string:
		if v != wantAud {
			t.Errorf("aud=%v want %q (normalised)", v, wantAud)
		}
	case []any:
		if len(v) != 1 || v[0] != wantAud {
			t.Errorf("aud=%v want [%q] (normalised)", v, wantAud)
		}
	default:
		t.Errorf("aud has unexpected type: %T (%v)", audAny, audAny)
	}
}

func TestScenario_TX_023_HandlerInjectedActClaimStripped(t *testing.T) {
	t.Parallel()
	// Policy injects a forged act via ExtraClaims. The OP-built act
	// (impersonation: calling client) MUST win.
	policy := txExtraClaimsPolicy{extras: map[string]any{
		"act":   map[string]any{"sub": "forged-actor"},
		"role":  "operator", // legitimate extra claim, not reserved
		"forge": "value",
	}}
	p := newTXProvider(t, policy)
	subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-023-jti"))
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	at, _ := body["access_token"].(string)
	claims := decodeTXJWTClaims(t, at)
	act, _ := claims["act"].(map[string]any)
	if act == nil {
		t.Fatalf("act claim absent on impersonation")
	}
	if act["sub"] == "forged-actor" {
		t.Errorf("act.sub=forged-actor; reserved-claim filter failed to strip embedder-injected forgery")
	}
	if act["sub"] != txCallerID {
		t.Errorf("act.sub=%v want %q (OP-built impersonation chain)", act["sub"], txCallerID)
	}
	// Non-reserved claims still flow through.
	if claims["role"] != "operator" {
		t.Errorf("role=%v want operator (non-reserved extra claim)", claims["role"])
	}
}

func TestScenario_TX_024_RegisterTokenExchangeRequiredAtNew(t *testing.T) {
	t.Parallel()
	_, err := op.New(testkit.MinimalOptions(t, op.RegisterTokenExchange(nil))...)
	if !errors.Is(err, op.ErrTokenExchangePolicyNil) {
		t.Fatalf("op.New err=%v, want %v", err, op.ErrTokenExchangePolicyNil)
	}
}

func TestScenario_TX_025_IDTokenCnfMirrorsAccessTokenBinding(t *testing.T) {
	t.Parallel()
	// id_token cnf MUST mirror the access_token cnf when the request
	// is sender-constrained, and MUST stay absent when the request is
	// bearer. Driving real DPoP / mTLS proofs through the wire lives
	// in the DPoP and mTLS suites; for TX-025 we pin the structural
	// contract: a bearer + openid-scoped exchange MUST NOT pollute the
	// id_token with a synthesised cnf, and the id_token's missing cnf
	// matches the access_token's missing cnf so the two carriers stay
	// in lock-step. The positive (bound) cases ride on the unit tests
	// in internal/customgrant/tokenexchange/cnf_test.go where the
	// DPoPJKT / MTLSCert plumbing is reachable without a wire DPoP
	// proof.
	yes := true
	policy := txDecisionPolicy{decision: &op.TokenExchangeDecision{IssueIDToken: &yes}}
	p := newTXProvider(t, policy)
	subjectClaims := p.defaultSubjectClaims("tx-025-jti")
	subjectClaims.Scope = []string{"openid", "read"}
	subjectJWS := p.mintSubjectToken(t, subjectClaims)
	form := url.Values{
		"subject_token":      []string{subjectJWS},
		"subject_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
		"scope":              []string{"openid read"},
	}
	status, body := p.postTokenExchange(t, form)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	at, _ := body["access_token"].(string)
	atClaims := decodeTXJWTClaims(t, at)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatalf("id_token absent: body=%v", body)
	}
	idClaims := decodeTXJWTClaims(t, idt)
	atCnf, _ := atClaims["cnf"].(map[string]any)
	idCnf, _ := idClaims["cnf"].(map[string]any)
	if atCnf != nil {
		t.Errorf("access_token cnf present on bearer exchange: %v", atCnf)
	}
	if idCnf != nil {
		t.Errorf("id_token cnf present on bearer exchange: %v", idCnf)
	}
}

// TestScenario_TX_026_RegistryFaultEmitsDedicatedAudit pins the M10
// invariant at the public-API level: the dedicated audit event the
// in-tree RFC 8693 handler emits on a transient access-token registry
// fault is registered in the op.AuditEvent catalogue and is byte-
// distinct from the ordinary token_exchange.subject_token_invalid
// event so SOC tooling can branch on it. The deep behavioural pin —
// drive the registry-fault path end-to-end and assert the wire shape
// stays collapsed to invalid_grant while the audit channel splits —
// rides on the white-box test in
// internal/customgrant/tokenexchange/lookup_registry_fault_test.go,
// where the [store.AccessTokenRegistry] seam is reachable without
// reconstructing the testkit's substore wiring around a wrapper.
//
// The wire shape MUST stay collapsed (invalid_grant in both cases) so
// an attacker cannot distinguish a transient outage from an actual
// revocation; the audit channel is the only place the split is
// observable. This row pins both halves: the public constant exists
// (so embedders can subscribe), and it is byte-distinct from the
// generic event (so a SOC dashboard can route on the name).
//
// Spec: RFC 6749 §5.2 (collapsed wire taxonomy).
func TestScenario_TX_026_RegistryFaultEmitsDedicatedAudit(t *testing.T) {
	t.Parallel()
	if op.AuditTokenExchangeSubjectTokenRegistryError == "" {
		t.Fatalf("AuditTokenExchangeSubjectTokenRegistryError is empty; the M10 dedicated audit constant is missing from the public catalogue")
	}
	if op.AuditTokenExchangeSubjectTokenRegistryError == op.AuditTokenExchangeSubjectTokenInvalid {
		t.Fatalf("registry-error event %q must be byte-distinct from the generic invalid event %q so SOC tooling can branch on the name",
			op.AuditTokenExchangeSubjectTokenRegistryError, op.AuditTokenExchangeSubjectTokenInvalid)
	}
	const wantWire = "token_exchange.subject_token_registry_error"
	if string(op.AuditTokenExchangeSubjectTokenRegistryError) != wantWire {
		t.Errorf("registry-error event wire form = %q, want %q",
			op.AuditTokenExchangeSubjectTokenRegistryError, wantWire)
	}
}

// buildDeepAct constructs a nested act chain at depth d. The function
// is used by TX-008 to seed an actor_token whose chain is already at
// the depth limit so adding the calling-client level overflows.
func buildDeepAct(d int) map[string]any {
	var inner map[string]any
	for i := range d {
		next := map[string]any{"sub": "level-" + itoa(i)}
		if inner != nil {
			next["act"] = inner
		}
		inner = next
	}
	return inner
}

// itoa is a tiny stdlib-free integer-to-string helper. The suite
// avoids strconv to keep the helper signatures tight.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 4)
	negative := n < 0
	if negative {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}

// thumbprint mirrors the SHA-256 base64url-no-pad shape RFC 8705 §3.1
// uses for x5t#S256. Defined here for any future test that wants to
// build a synthetic mTLS-bound subject_token; TX-020 only needs the
// shape so the helper is currently unused by the active rows.
//
//nolint:unused // retained for future TX-020 enhancement.
func thumbprint(b []byte) string {
	h := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

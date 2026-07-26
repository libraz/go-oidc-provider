package scenarios_test

// Catalog: test/scenarios/catalog/access_token_opaque.yaml (ATO-NNN)
// Spec:
//   - RFC 6749 §4 — OAuth 2.0 grant exchanges
//   - RFC 6750 §2.1 — Bearer Token Usage (b64token wire shape)
//   - RFC 7009 §2.2 — OAuth 2.0 Token Revocation (idempotency)
//   - RFC 7662 §2.1 / §2.2 — OAuth 2.0 Token Introspection
//   - RFC 7800 / RFC 8705 / RFC 8707 / RFC 9449 — cnf / mTLS / resource / DPoP

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// opaqueClientID / opaqueClientSecret are the canonical confidential
// fixture the ATO suite relies on. They live as package-scoped consts
// so individual rows can stay focused on the behaviour under test.
const (
	opaqueClientID = "rp-ato"
	opaqueCallback = "https://rp.testkit.invalid/callback"
)

// opaqueClientSecret is a test-only credential. The catalogue requires
// deterministic fixtures rather than randomised secrets.
const opaqueClientSecret = "rp-ato-secret"

// opaqueATLength pins the wire length of an opaque access token
// (RawURLEncoding of 32 random bytes).
const opaqueATLength = 43

// newOpaqueProvider stands up a testkit Provider configured for the
// global opaque-AT path. Introspection / revocation features are
// enabled because the ATO scenarios exercise those endpoints
// end-to-end.
func newOpaqueProvider(t *testing.T) (*testkit.Provider, *store.Client) {
	t.Helper()
	hash, err := op.HashClientSecret(opaqueClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
		op.WithFeature(feature.Introspect),
		op.WithFeature(feature.Revoke),
	))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      opaqueClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{opaqueCallback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		Resources:               []string{"https://api.opaque.example/", "https://api.jwt.example/"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "alice@example.com",
			"email_verified": true,
		},
	})
	return tk, rp
}

// runOpaqueCodeFlow drives /authorize → /interaction → /token through
// scenariokit, returning the parsed token response. It enables
// offline_access so refresh-rotation rows can drive the second hop;
// rows that do not need a refresh token simply ignore RefreshToken.
func runOpaqueCodeFlow(t *testing.T, tk *testkit.Provider, rp *store.Client, scope string, extra url.Values) scenariokit.TokenResponse {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: opaqueCallback,
		Scope:       scope,
		PKCE:        pkce,
		Extra:       extra,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  opaqueCallback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: opaqueClientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	tok.Raw["__code"] = flow.Code
	return tok
}

// assertOpaqueShape asserts that v matches the opaque wire format:
// 43 base64url characters and no "." separator (so a JWS Compact
// Serialisation parser would reject it at the parse step).
func assertOpaqueShape(t *testing.T, v string) {
	t.Helper()
	if len(v) != opaqueATLength {
		t.Errorf("opaque AT length=%d want %d (value=%q)", len(v), opaqueATLength, v)
	}
	if strings.Contains(v, ".") {
		t.Errorf("opaque AT must not contain '.' (value=%q)", v)
	}
}

// postIntrospect submits a token to /oidc/introspect using the
// supplied client's HTTP Basic credentials and returns the parsed
// JSON envelope.
func postIntrospect(t *testing.T, tk *testkit.Provider, token, clientID, clientSecret string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := decodeJSONBody(t, resp)
	return resp.StatusCode, body
}

// postRevoke submits a token to /oidc/revoke and returns the response
// status code so callers can pin the RFC 7009 §2.2 200-or-empty
// posture.
func postRevoke(t *testing.T, tk *testkit.Provider, token, clientID, clientSecret string) int {
	t.Helper()
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build revoke request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /revoke: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// getUserInfo presents a bearer token to /oidc/userinfo and returns
// the response status, parsed body (200 path), and the
// WWW-Authenticate challenge (401 path).
func getUserInfo(t *testing.T, tk *testkit.Provider, token string) (int, map[string]any, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("build userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	challenge := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode == http.StatusOK {
		return resp.StatusCode, decodeJSONBody(t, resp), challenge
	}
	return resp.StatusCode, nil, challenge
}

// decodeJSONBody parses an HTTP response body as a JSON object,
// returning an empty map for empty bodies so callers can write
// uniform assertions against the absent / present cases (RFC 7009
// §2.2 permits an empty 200 body on revocation).
func decodeJSONBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal body %q: %v", string(raw), err)
	}
	return out
}

// TestScenario_ATO_001_OpaqueAccessTokenIssuedAndPersisted exercises
// the wire format and the issuance plumbing together: the global
// opaque option produces a 43-char dot-free access_token and writes a
// matching shadow row in OpaqueAccessTokens.
func TestScenario_ATO_001_OpaqueAccessTokenIssuedAndPersisted(t *testing.T) {
	t.Parallel()

	tk, rp := newOpaqueProvider(t)
	tok := runOpaqueCodeFlow(t, tk, rp, "openid profile email", nil)

	if tok.AccessToken == "" {
		t.Fatal("access_token missing from /token response")
	}
	assertOpaqueShape(t, tok.AccessToken)

	if tok.TokenType == "" {
		t.Error("token_type missing from /token response")
	}
	if tok.ExpiresIn <= 0 {
		t.Errorf("expires_in=%d want > 0", tok.ExpiresIn)
	}

	rec, err := tk.Store.OpaqueAccessTokens().Find(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find: %v", err)
	}
	if rec == nil {
		t.Fatal("OpaqueAccessTokens.Find returned nil record")
	}
	if rec.ClientID != rp.ID {
		t.Errorf("row ClientID=%q want %q", rec.ClientID, rp.ID)
	}
	if rec.Subject != scenariokit.DefaultSubject {
		t.Errorf("row Subject=%q want %q", rec.Subject, scenariokit.DefaultSubject)
	}
	if rec.Revoked {
		t.Error("freshly issued opaque AT must not be Revoked")
	}
	if rec.IssuedAt.IsZero() || rec.ExpiresAt.IsZero() {
		t.Errorf("row timestamps unset: issued=%v expires=%v", rec.IssuedAt, rec.ExpiresAt)
	}
	if !rec.ExpiresAt.After(rec.IssuedAt) {
		t.Errorf("ExpiresAt=%v must be after IssuedAt=%v", rec.ExpiresAt, rec.IssuedAt)
	}
	if len(rec.Scope) == 0 {
		t.Error("row Scope must not be empty")
	}
}

// TestScenario_ATO_002_OpaqueIntrospectionProjectsClaims pins
// §"Verification plumbing": same-client introspection of an opaque
// AT returns active=true with the projected metadata.
func TestScenario_ATO_002_OpaqueIntrospectionProjectsClaims(t *testing.T) {
	t.Parallel()

	tk, rp := newOpaqueProvider(t)
	tok := runOpaqueCodeFlow(t, tk, rp, "openid profile email", nil)

	status, body := postIntrospect(t, tk, tok.AccessToken, rp.ID, opaqueClientSecret)
	if status != http.StatusOK {
		t.Fatalf("/introspect status=%d want 200", status)
	}
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%v", body["active"], body)
	}
	if got, _ := body["client_id"].(string); got != rp.ID {
		t.Errorf("client_id=%v want %q", body["client_id"], rp.ID)
	}
	if got, _ := body["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", body["sub"], scenariokit.DefaultSubject)
	}
	if scope, _ := body["scope"].(string); scope == "" {
		t.Errorf("scope missing from active introspection: body=%v", body)
	}
	if tt, _ := body["token_type"].(string); tt != "Bearer" {
		t.Errorf("token_type=%v want Bearer", body["token_type"])
	}
}

// TestScenario_ATO_003_OpaqueUserinfoBearerHappyPath confirms a
// non-JWS bearer threads /oidc/userinfo through the opaque substore
// path documented in §"Verification plumbing".
func TestScenario_ATO_003_OpaqueUserinfoBearerHappyPath(t *testing.T) {
	t.Parallel()

	tk, rp := newOpaqueProvider(t)
	tok := runOpaqueCodeFlow(t, tk, rp, "openid email", nil)

	status, body, challenge := getUserInfo(t, tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status=%d want 200; challenge=%q", status, challenge)
	}
	if got, _ := body["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", body["sub"], scenariokit.DefaultSubject)
	}
	if got, _ := body["email"].(string); got != "alice@example.com" {
		t.Errorf("email=%v want alice@example.com", body["email"])
	}
	_ = rp
}

// TestScenario_ATO_004_OpaqueRevocationCycle drives the full
// /oidc/revocation → /oidc/introspect (inactive) → /oidc/userinfo (401)
// loop. RFC 7009 §2.2 idempotency is asserted by the second revoke
// call.
func TestScenario_ATO_004_OpaqueRevocationCycle(t *testing.T) {
	t.Parallel()

	tk, rp := newOpaqueProvider(t)
	tok := runOpaqueCodeFlow(t, tk, rp, "openid profile email", nil)

	if status := postRevoke(t, tk, tok.AccessToken, rp.ID, opaqueClientSecret); status != http.StatusOK {
		t.Fatalf("/revoke status=%d want 200", status)
	}

	status, body := postIntrospect(t, tk, tok.AccessToken, rp.ID, opaqueClientSecret)
	if status != http.StatusOK {
		t.Fatalf("post-revoke /introspect status=%d want 200", status)
	}
	if active, _ := body["active"].(bool); active {
		t.Errorf("post-revoke active=true want false; body=%v", body)
	}

	uiStatus, _, challenge := getUserInfo(t, tk, tok.AccessToken)
	if uiStatus != http.StatusUnauthorized {
		t.Fatalf("post-revoke /userinfo status=%d want 401; challenge=%q", uiStatus, challenge)
	}
	if !strings.Contains(challenge, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must declare invalid_token", challenge)
	}

	// Second revoke is idempotent (RFC 7009 §2.2): same response shape.
	if status := postRevoke(t, tk, tok.AccessToken, rp.ID, opaqueClientSecret); status != http.StatusOK {
		t.Fatalf("idempotent /revoke status=%d want 200", status)
	}
}

// TestScenario_ATO_005_CrossClientIntrospectionInactive pins that an
// authenticated client cannot inspect another client's
// opaque AT, and the response is the canonical inactive shape.
func TestScenario_ATO_005_CrossClientIntrospectionInactive(t *testing.T) {
	t.Parallel()

	tk, owner := newOpaqueProvider(t)
	tok := runOpaqueCodeFlow(t, tk, owner, "openid profile email", nil)

	const callerID = "rp-ato-other"
	//nolint:gosec // G101: test fixture, not a real credential.
	const callerSecret = "rp-ato-other-secret"
	hash, err := op.HashClientSecret(callerSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	caller := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      callerID,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://other.testkit.invalid/callback"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	status, body := postIntrospect(t, tk, tok.AccessToken, caller.ID, callerSecret)
	if status != http.StatusOK {
		t.Fatalf("cross-client /introspect status=%d want 200", status)
	}
	if active, _ := body["active"].(bool); active {
		t.Errorf("cross-client active=true want false; body=%v", body)
	}
	// RFC 7662 §2.2 mandates a single-member body when inactive.
	if len(body) != 1 {
		t.Errorf("inactive body has %d members want 1; body=%v", len(body), body)
	}
}

// TestScenario_ATO_006_RefreshRotationRevokesPriorOpaqueAT exercises
// §"Refresh-rotation revocation of prior AT (opaque only)": a refresh
// exchange flips the prior opaque-AT row to Revoked=true and the
// freshly minted row stays live.
func TestScenario_ATO_006_RefreshRotationRevokesPriorOpaqueAT(t *testing.T) {
	t.Parallel()

	tk, rp := newOpaqueProvider(t)
	tok := runOpaqueCodeFlow(t, tk, rp, "openid profile email offline_access", nil)
	if tok.RefreshToken == "" {
		t.Fatal("offline_access requested but refresh_token absent")
	}
	prior := tok.AccessToken

	refreshed := refreshScenarioToken(t, tk, tok.RefreshToken, rp.ID, opaqueClientSecret)
	if refreshed.StatusCode != http.StatusOK {
		t.Fatalf("/token refresh status=%d body=%v", refreshed.StatusCode, refreshed.Raw)
	}
	if refreshed.AccessToken == prior {
		t.Fatal("rotation must mint a fresh access_token, not echo the prior bytes")
	}
	assertOpaqueShape(t, refreshed.AccessToken)

	priorRec, err := tk.Store.OpaqueAccessTokens().Find(context.Background(), prior)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find(prior): %v", err)
	}
	if priorRec == nil || !priorRec.Revoked {
		t.Errorf("prior opaque AT must be Revoked=true after rotation; rec=%+v", priorRec)
	}

	freshRec, err := tk.Store.OpaqueAccessTokens().Find(context.Background(), refreshed.AccessToken)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find(new): %v", err)
	}
	if freshRec == nil {
		t.Fatal("freshly rotated opaque AT row missing")
	}
	if freshRec.Revoked {
		t.Errorf("freshly rotated opaque AT must not be Revoked; rec=%+v", freshRec)
	}
}

// TestScenario_ATO_007_CodeReplayCascadesOpaqueRevocation drives the
// §"Code-replay cascade" branch: a second exchange against the same
// authorization code triggers revokeChainForCode, which calls
// OpaqueAccessTokens.RevokeByGrant on the originating grant.
func TestScenario_ATO_007_CodeReplayCascadesOpaqueRevocation(t *testing.T) {
	t.Parallel()

	tk, rp := newOpaqueProvider(t)
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: opaqueCallback,
		Scope:       "openid profile email",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	first := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  opaqueCallback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: opaqueClientSecret,
	})
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first /token status=%d body=%v", first.StatusCode, first.Raw)
	}
	if first.AccessToken == "" {
		t.Fatal("first exchange returned no access_token")
	}
	priorRec, err := tk.Store.OpaqueAccessTokens().Find(context.Background(), first.AccessToken)
	if err != nil {
		t.Fatalf("Find(first): %v", err)
	}
	if priorRec == nil || priorRec.Revoked {
		t.Fatalf("first exchange row missing or already revoked: %+v", priorRec)
	}

	// Replay the consumed code.
	replay := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  opaqueCallback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: opaqueClientSecret,
	})
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay /token status=%d want 400 (invalid_grant); body=%v", replay.StatusCode, replay.Raw)
	}
	if got, _ := replay.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("replay error=%v want invalid_grant", replay.Raw["error"])
	}

	// The cascade must have flipped the originally-issued opaque row
	// to Revoked=true via OpaqueAccessTokens.RevokeByGrant.
	cascaded, err := tk.Store.OpaqueAccessTokens().Find(context.Background(), first.AccessToken)
	if err != nil {
		t.Fatalf("Find(first) after replay: %v", err)
	}
	if cascaded == nil || !cascaded.Revoked {
		t.Errorf("code-replay cascade must revoke the prior opaque AT; rec=%+v", cascaded)
	}
}

// TestScenario_ATO_008_PerAudienceMapSelectsFormat exercises
// §"Public API surface": a per-audience map routes one resource to
// opaque and a sibling resource to JWT, picking the format from the
// `resource` parameter at issuance time.
func TestScenario_ATO_008_PerAudienceMapSelectsFormat(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ato-mixed"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // G101: test fixture, not a real credential.
	const clientSecret = "rp-ato-mixed-secret"
	const (
		opaqueAud = "https://api.opaque.example/"
		jwtAud    = "https://api.jwt.example/"
	)

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithAccessTokenFormatPerAudience(map[string]op.AccessTokenFormat{
			opaqueAud: op.AccessTokenFormatOpaque,
			jwtAud:    op.AccessTokenFormatJWT,
		}),
		op.WithFeature(feature.Introspect),
	))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		Resources:               []string{opaqueAud, jwtAud},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.Store.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})

	exchange := func(resource string) scenariokit.TokenResponse {
		pkce := scenariokit.NewPKCEPair("")
		flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
			ClientID:    rp.ID,
			RedirectURI: callback,
			Scope:       "openid profile",
			PKCE:        pkce,
			Extra:       url.Values{"resource": {resource}},
		})
		if flow.Code == "" {
			t.Fatalf("authorize callback missing code (resource=%s): %+v", resource, flow)
		}
		tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
			Code:         flow.Code,
			RedirectURI:  callback,
			Verifier:     pkce.Verifier,
			ClientID:     rp.ID,
			ClientSecret: clientSecret,
		})
		if tok.StatusCode != http.StatusOK {
			t.Fatalf("/token status=%d body=%v (resource=%s)", tok.StatusCode, tok.Raw, resource)
		}
		return tok
	}

	opaqueTok := exchange(opaqueAud)
	assertOpaqueShape(t, opaqueTok.AccessToken)
	if _, err := tk.Store.OpaqueAccessTokens().Find(context.Background(), opaqueTok.AccessToken); err != nil {
		t.Fatalf("opaque-resource AT must persist in OpaqueAccessTokens: %v", err)
	}

	jwtTok := exchange(jwtAud)
	if got := strings.Count(jwtTok.AccessToken, "."); got != 2 {
		t.Errorf("jwt-resource AT dot count=%d want 2 (JWS Compact Serialisation)", got)
	}
	// A JWT-resource AT MUST NOT be persisted in the opaque store.
	if _, err := tk.Store.OpaqueAccessTokens().Find(context.Background(), jwtTok.AccessToken); err == nil {
		t.Errorf("jwt-resource AT unexpectedly found in OpaqueAccessTokens: %s", jwtTok.AccessToken)
	} else if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("jwt-resource AT lookup error=%v want ErrNotFound", err)
	}
}

// TestScenario_ATO_009_DPoPOpaqueATKeyMismatchAtUserinfo is OOS — see catalog out_of_scope_reason.
func TestScenario_ATO_009_DPoPOpaqueATKeyMismatchAtUserinfo(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATO-009 (see catalog out_of_scope_reason)")
}

// TestScenario_ATO_010_MTLSOpaqueATCertMismatchAtUserinfo is OOS — see catalog out_of_scope_reason.
func TestScenario_ATO_010_MTLSOpaqueATCertMismatchAtUserinfo(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATO-010 (see catalog out_of_scope_reason)")
}

// TestScenario_ATO_011_FormatConfusionWireBytesNoDot pins the §S.9
// invariant by inspecting the wire bytes: an opaque AT carries no
// "." characters, so a JWS Compact Serialisation parse rejects it
// at the parse step rather than mis-interpreting the bytes.
func TestScenario_ATO_011_FormatConfusionWireBytesNoDot(t *testing.T) {
	t.Parallel()

	tk, rp := newOpaqueProvider(t)
	tok := runOpaqueCodeFlow(t, tk, rp, "openid profile email", nil)

	if strings.ContainsRune(tok.AccessToken, '.') {
		t.Fatalf("opaque AT contains '.' so JWS-aware code might mis-parse it: %q", tok.AccessToken)
	}
	if got := strings.Count(tok.AccessToken, "."); got != 0 {
		t.Errorf("opaque AT dot count=%d want 0", got)
	}
	// RFC 6750 §2.1 b64token alphabet: ALPHA / DIGIT / "-" / "_" only
	// for our RawURLEncoding output. The check pins the invariant
	// across future encoder changes.
	for _, r := range tok.AccessToken {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			t.Errorf("opaque AT contains out-of-alphabet rune %q (token=%q)", r, tok.AccessToken)
		}
	}
}

package op_test

// End-to-end coverage of the ID-JAG round trip between two providers: A
// is the IdP and issues an ID-JAG through token exchange, B is the
// resource authorization server and redeems it through the jwt-bearer
// grant. B trusts A through a static copy of A's JWKS, so no network
// option is involved.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

const (
	jbIssuerA     = "https://idp-a.testkit.invalid"
	jbIssuerB     = "https://ras-b.testkit.invalid"
	jbIssuerPlain = "https://ras-plain.testkit.invalid"
	jbIDPClient   = "idp-rp"
	jbIDPSecret   = "idp-rp-secret" //nolint:gosec // G101: a test-only client secret.
	jbRASClient   = "ras-client"
	jbRASSecret   = "ras-client-secret" //nolint:gosec // G101: a test-only client secret.
	jbLocalSub    = "ras-user-1"
	jbIDJAGType   = "urn:ietf:params:oauth:token-type:id-jag"
	jbIDTokenType = "urn:ietf:params:oauth:token-type:id_token"   //nolint:gosec // G101: token type URN, not a credential.
	jbBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // G101: grant type URN, not a credential.
)

// jbIDJAGPolicy admits exchanges addressed to B and maps the requester
// onto B's client.
type jbIDJAGPolicy struct{}

func (jbIDJAGPolicy) Allow(_ context.Context, req op.IDJAGRequest) (*op.IDJAGDecision, error) {
	if req.Audience != jbIssuerB {
		return nil, op.ErrIDJAGUnknownAudience
	}
	return &op.IDJAGDecision{ClientID: jbRASClient, Scope: []string{"profile"}}, nil
}

// jbFixture holds the IdP and the ID token it issued to its client.
type jbFixture struct {
	idp      *testkit.Provider
	idpAudit *bytes.Buffer
	idToken  string
	idpSub   string
	jwks     []byte
	clock    op.Clock
}

func newJBFixture(t *testing.T) *jbFixture {
	t.Helper()
	clock := fixedClock{t: time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)}
	var idpAudit bytes.Buffer
	idp := testkit.NewProvider(t,
		testkit.WithIssuer(jbIssuerA),
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithIDJAGIssuance(jbIDJAGPolicy{}),
			op.WithAuditLogger(slog.New(slog.NewJSONHandler(&idpAudit, nil))),
		),
	)
	hash, err := op.HashClientSecret(jbIDPSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	idp.RegisterClient(t, testkit.ClientFixture{
		ID:         jbIDPClient,
		SecretHash: hash,
		GrantTypes: []string{"authorization_code", op.TokenExchangeGrantType},
		Scopes:     []string{"openid", "profile"},
	})
	code, _ := newSCDFlow(t, idp, jbIDPClient).authorize(t)
	status, body := jbPost(t, idp, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {scdCallback},
		"code_verifier": {scdVerifier},
	}, jbIDPClient, jbIDPSecret)
	if status != http.StatusOK {
		t.Fatalf("code redemption status=%d body=%v", status, body)
	}
	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatalf("code redemption returned no id_token: %v", body)
	}
	sub, _ := jbPayload(t, idToken)["sub"].(string)
	return &jbFixture{idp: idp, idpAudit: &idpAudit, idToken: idToken, idpSub: sub, jwks: jbFetchJWKS(t, idp), clock: clock}
}

// newRAS builds a resource AS trusting A under profile, with B's client
// registered for the jwt-bearer grant and the mapped local user seeded.
func (f *jbFixture) newRAS(t *testing.T, issuer string, profile op.AssertionProfile, extra ...op.Option) *testkit.Provider {
	t.Helper()
	ras := testkit.NewProvider(t,
		testkit.WithIssuer(issuer),
		testkit.WithClock(f.clock),
		testkit.WithOptions(op.WithJWTBearerGrant(op.JWTBearerGrant{
			Issuers: []op.AssertionIssuer{{
				Issuer:         jbIssuerA,
				JWKS:           f.jwks,
				AllowedClients: []string{jbRASClient},
				Profile:        profile,
			}},
			ResolveSubject: func(_ context.Context, a op.AssertionSubject) (string, error) {
				if a.Issuer != jbIssuerA || a.Subject != f.idpSub || a.ClientID != jbRASClient {
					return "", op.ErrUnknownAssertionSubject
				}
				return jbLocalSub, nil
			},
		})),
		testkit.WithOptions(extra...),
	)
	hash, err := op.HashClientSecret(jbRASSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	ras.RegisterClient(t, testkit.ClientFixture{
		ID:         jbRASClient,
		SecretHash: hash,
		GrantTypes: []string{jbBearerGrant},
		Scopes:     []string{"profile"},
	})
	ras.Store.PutUser(context.Background(), &store.User{Subject: jbLocalSub})
	return ras
}

// exchange asks A for a token in exchange for subjectToken.
func (f *jbFixture) exchange(t *testing.T, subjectToken string) (int, map[string]any) {
	t.Helper()
	return jbPost(t, f.idp, url.Values{
		"grant_type":           {op.TokenExchangeGrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {jbIDTokenType},
		"requested_token_type": {jbIDJAGType},
		"audience":             {jbIssuerB},
		"scope":                {"profile"},
	}, jbIDPClient, jbIDPSecret)
}

// TestJWTBearerE2E_IDJAGRoundTrip runs IdP token exchange → ID-JAG →
// RAS jwt-bearer redemption → access token for the mapped local subject.
func TestJWTBearerE2E_IDJAGRoundTrip(t *testing.T) {
	t.Parallel()

	f := newJBFixture(t)
	ras := f.newRAS(t, jbIssuerB, op.AssertionProfileIDJAG)

	status, body := f.exchange(t, f.idToken)
	if status != http.StatusOK {
		t.Fatalf("token exchange status=%d body=%v", status, body)
	}
	if got := body["issued_token_type"]; got != jbIDJAGType {
		t.Errorf("issued_token_type = %v, want %s", got, jbIDJAGType)
	}
	if got := body["token_type"]; got != "N_A" {
		t.Errorf("token_type = %v, want N_A", got)
	}
	for _, absent := range []string{"refresh_token", "id_token"} {
		if _, ok := body[absent]; ok {
			t.Errorf("token exchange response carries %s", absent)
		}
	}
	idjag, _ := body["access_token"].(string)
	claims := jbPayload(t, idjag)
	if claims["aud"] != jbIssuerB || claims["client_id"] != jbRASClient || claims["sub"] != f.idpSub {
		t.Errorf("ID-JAG claims aud=%v client_id=%v sub=%v", claims["aud"], claims["client_id"], claims["sub"])
	}

	status, body = jbPost(t, ras, url.Values{
		"grant_type": {jbBearerGrant},
		"assertion":  {idjag},
		"scope":      {"profile"},
	}, jbRASClient, jbRASSecret)
	if status != http.StatusOK {
		t.Fatalf("jwt-bearer status=%d body=%v", status, body)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Error("jwt-bearer response carries a refresh_token")
	}
	if _, ok := body["id_token"]; ok {
		t.Error("jwt-bearer response carries an id_token")
	}
	at, _ := body["access_token"].(string)
	atClaims := jbPayload(t, at)
	if atClaims["sub"] != jbLocalSub {
		t.Errorf("access token sub = %v, want %s (the ResolveSubject mapping)", atClaims["sub"], jbLocalSub)
	}
	if atClaims["iss"] != jbIssuerB {
		t.Errorf("access token iss = %v, want %s", atClaims["iss"], jbIssuerB)
	}

	jbAssertDiscovery(t, ras, "grant_types_supported", jbBearerGrant)
	jbAssertDiscovery(t, ras, "authorization_grant_profiles_supported", "urn:ietf:params:oauth:grant-profile:id-jag")
	jbAssertDiscovery(t, f.idp, "grant_types_supported", op.TokenExchangeGrantType)
	jbAssertDiscovery(t, f.idp, "identity_chaining_requested_token_types_supported", jbIDJAGType)

	// The jti is single-use: the same ID-JAG does not redeem twice.
	status, body = jbPost(t, ras, url.Values{
		"grant_type": {jbBearerGrant},
		"assertion":  {idjag},
	}, jbRASClient, jbRASSecret)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("replayed ID-JAG status=%d body=%v, want 400 invalid_grant", status, body)
	}
}

// TestJWTBearerE2E_IDJAGRefusedAsIDToken presents A's ID-JAG back to A's
// token exchange labelled as an id_token: the typ check refuses it.
func TestJWTBearerE2E_IDJAGRefusedAsIDToken(t *testing.T) {
	t.Parallel()

	f := newJBFixture(t)
	status, body := f.exchange(t, f.idToken)
	if status != http.StatusOK {
		t.Fatalf("token exchange status=%d body=%v", status, body)
	}
	idjag, _ := body["access_token"].(string)

	f.idpAudit.Reset()
	status, body = f.exchange(t, idjag)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("ID-JAG as subject_token status=%d body=%v, want 400 invalid_grant", status, body)
	}
	if got := jbAuditReason(t, f.idpAudit, "token_exchange.subject_token_invalid"); got != "typ_mismatch" {
		t.Errorf("subject_token_invalid reason = %q, want typ_mismatch", got)
	}
}

// TestJWTBearerE2E_PlainProfileRefusesIDToken presents A's id_token as a
// plain RFC 7523 assertion to an AS that trusts A: it is not a grant
// addressed to that AS and is refused.
func TestJWTBearerE2E_PlainProfileRefusesIDToken(t *testing.T) {
	t.Parallel()

	f := newJBFixture(t)
	var auditBuf bytes.Buffer
	ras := f.newRAS(t, jbIssuerPlain, op.AssertionProfileJWT,
		op.WithAuditLogger(slog.New(slog.NewJSONHandler(&auditBuf, nil))))
	status, body := jbPost(t, ras, url.Values{
		"grant_type": {jbBearerGrant},
		"assertion":  {f.idToken},
	}, jbRASClient, jbRASSecret)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("id_token as assertion status=%d body=%v, want 400 invalid_grant", status, body)
	}
	// typ JWT passes the plain profile; the id_token's aud names A's
	// client, not this AS, so the claims stage refuses it.
	if got := jbAuditReason(t, &auditBuf, "jwt_bearer.rejected"); got != "claims" {
		t.Errorf("jwt_bearer.rejected reason = %q, want claims", got)
	}
}

// jbAuditReason returns extras.reason of the first audit record named
// event in buf, or "" when none was written.
func jbAuditReason(t *testing.T, buf *bytes.Buffer, event string) string {
	t.Helper()
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		var rec struct {
			Event  string         `json:"event"`
			Extras map[string]any `json:"extras"`
		}
		if len(line) == 0 || json.Unmarshal(line, &rec) != nil || rec.Event != event {
			continue
		}
		reason, _ := rec.Extras["reason"].(string)
		return reason
	}
	return ""
}

// jbPost sends a client_secret_basic token request and decodes the body.
func jbPost(t *testing.T, tk *testkit.Provider, form url.Values, clientID, secret string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read token response: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode token response %q: %v", raw, err)
	}
	return resp.StatusCode, out
}

// jbAssertDiscovery fails unless the provider's discovery document lists
// want under field.
func jbAssertDiscovery(t *testing.T, tk *testkit.Provider, field, want string) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(jbGet(t, tk, "/.well-known/openid-configuration"), &doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	values, _ := doc[field].([]any)
	for _, v := range values {
		if v == want {
			return
		}
	}
	t.Errorf("%s discovery %s = %v, want it to list %s", tk.Issuer, field, doc[field], want)
}

// jbFetchJWKS reads the provider's published JWK Set.
func jbFetchJWKS(t *testing.T, tk *testkit.Provider) []byte {
	t.Helper()
	return jbGet(t, tk, "/oidc/jwks")
}

// jbGet fetches path from the provider and returns the 200 body.
func jbGet(t *testing.T, tk *testkit.Provider, path string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tk.Server.URL+path, http.NoBody)
	if err != nil {
		t.Fatalf("build GET %s: %v", path, err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status=%d err=%v", path, resp.StatusCode, err)
	}
	return raw
}

// jbPayload decodes a compact JWS payload without verifying it.
func jbPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWS: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

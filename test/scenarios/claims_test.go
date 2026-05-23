package scenarios_test

// Catalog: test/scenarios/catalog/claims.yaml (CL-NN)
// Spec:
//   - OIDC Core 1.0 §5.5, §5.5.1, §5.5.1.1, §5.5.2
//   - OIDC Core 1.0 §3.1.2.1, §15
//   - RFC 9101 — JWT Secured Authorization Request (JAR)
//   - RFC 9126 — Pushed Authorization Requests (PAR)

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// clRegisterRP installs a confidential code-flow client on tk, configured
// to release the standard "openid email profile" scope set. The returned
// secret is the plaintext credential the test passes to /token.
func clRegisterRP(t *testing.T, tk *testkit.Provider, id string) (*store.Client, string) {
	t.Helper()
	const callback = "https://rp.testkit.invalid/callback"
	secret := id + "-secret"
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      id,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	return rp, secret
}

// clSeedAlice puts the canonical Alice user record on tk's store with
// the email and profile claims the §5.5 projection rows assert against.
func clSeedAlice(t *testing.T, tk *testkit.Provider) {
	t.Helper()
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "alice@example.com",
			"email_verified": true,
			"name":           "Alice Example",
			"given_name":     "Alice",
			"family_name":    "Example",
		},
	})
}

// clRunCodeFlow drives /authorize → /token with optional Extra params
// (typically the "claims" parameter) and returns the parsed token
// response. Authorize-time errors short-circuit by returning a zero
// TokenResponse alongside the captured CodeFlowResult.
func clRunCodeFlow(t *testing.T, tk *testkit.Provider, rp *store.Client, secret, scope string, extra url.Values) (scenariokit.CodeFlowResult, scenariokit.TokenResponse) {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: rp.RedirectURIs[0],
		Scope:       scope,
		PKCE:        pkce,
		Extra:       extra,
	})
	if flow.Error != "" || flow.Code == "" {
		return flow, scenariokit.TokenResponse{}
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  rp.RedirectURIs[0],
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: secret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	return flow, tok
}

// TestScenario_CL_01_AbsentClaimsParameter checks that when the request
// omits the claims parameter entirely, the OP issues an id_token whose
// claim payload contains nothing beyond the standard set; the §5.5
// projector applies no rules.
//
// Spec: OIDC Core 1.0 §5.5.
func TestScenario_CL_01_AbsentClaimsParameter(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-01")
	clSeedAlice(t, tk)

	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", nil)
	if tok.IDToken == "" {
		t.Fatal("id_token missing from /token response")
	}
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	// With no claims parameter, the id_token must not carry the
	// scope-derived "email" claim — Core §5.4 releases scoped claims
	// at /userinfo, not in the id_token.
	if v, ok := idClaims["email"]; ok {
		t.Errorf("id_token leaked email=%v with no claims parameter", v)
	}
	// And the userinfo endpoint should still emit the email claim
	// (driven solely by the granted "email" scope) rather than the
	// claims-parameter projection.
	status, _, body := callUserinfo(t, tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status=%d body=%v", status, body)
	}
	if got := body["email"]; got != "alice@example.com" {
		t.Errorf("/userinfo email=%v want alice@example.com", got)
	}
}

// clAuthorizeBadClaims issues a GET /oidc/auth with the supplied
// "claims" wire form and the canonical fixture parameters, and
// returns the parsed JSON error envelope alongside the response
// status. Because the claims parser fires before the redirect_uri is
// trusted (writeAuthorizeParseError path), v1.0 surfaces the failure
// as a self-contained 400 response rather than a redirect with the
// error parameters — see CL-02/03/05 for the assertion shape.
func clAuthorizeBadClaims(t *testing.T, tk *testkit.Provider, rp *store.Client, claimsRaw string) (int, map[string]any) {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	q := url.Values{
		"client_id":             {rp.ID},
		"response_type":         {"code"},
		"redirect_uri":          {rp.RedirectURIs[0]},
		"scope":                 {"openid"},
		"state":                 {scenariokit.DefaultState},
		"nonce":                 {scenariokit.DefaultNonce},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
		"claims":                {claimsRaw},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+q.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("build /authorize: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("/authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /authorize body: %v", err)
	}
	out := map[string]any{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &out)
	}
	return resp.StatusCode, out
}

// TestScenario_CL_02_NonObjectTopLevelRejected checks that when the
// claims parameter is syntactically valid JSON but its top-level value
// is not an object (here a JSON array), the OP rejects the request
// with HTTP 400 and a JSON envelope carrying error=invalid_request.
//
// Note on v1.0 wiring: the claims parser is invoked from
// authorize.ParseValues before the redirect_uri is validated, which
// means the error is rendered through writeAuthorizeParseError as a
// self-contained 400 envelope rather than a redirect with the OAuth
// error parameters. v1.0 also surfaces every claims-parser failure
// (non-object top-level, unparseable JSON, non-object id_token /
// userinfo location, malformed entry body) through the single
// ErrClaimsRequestInvalid sentinel — the error_description is the
// shared "claims parameter is not valid JSON" rather than a more
// granular per-shape message.
//
// Spec: OIDC Core 1.0 §5.5.
func TestScenario_CL_02_NonObjectTopLevelRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, _ := clRegisterRP(t, tk, "rp-cl-02")
	clSeedAlice(t, tk)

	status, env := clAuthorizeBadClaims(t, tk, rp, `["not","an","object"]`)
	if status != http.StatusBadRequest {
		t.Fatalf("/authorize status=%d want 400", status)
	}
	if got, _ := env["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (env=%v)", got, env)
	}
	if got, _ := env["error_description"].(string); got == "" {
		t.Errorf("error_description missing from %v", env)
	}
}

// TestScenario_CL_03_UnparsableClaimsRejected checks that JSON whose
// bytes cannot be parsed at all (truncated object) yields a 400
// invalid_request envelope on the same wire path as CL-02.
//
// Spec: OIDC Core 1.0 §5.5.
func TestScenario_CL_03_UnparsableClaimsRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, _ := clRegisterRP(t, tk, "rp-cl-03")
	clSeedAlice(t, tk)

	status, env := clAuthorizeBadClaims(t, tk, rp, `{"userinfo":{`) // truncated
	if status != http.StatusBadRequest {
		t.Fatalf("/authorize status=%d want 400", status)
	}
	if got, _ := env["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (env=%v)", got, env)
	}
}

// TestScenario_CL_04_MissingIDTokenAndUserinfoRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_04_MissingIDTokenAndUserinfoRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-04 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_05_NonObjectSectionRejected checks that when the
// top-level claims object is parseable but the value of "id_token" or
// "userinfo" is not itself an object (here a JSON array), the OP
// rejects the request with HTTP 400 + error=invalid_request. v1.0
// surfaces the failure via the shared ErrClaimsRequestInvalid
// sentinel — the parser's parseClaimsLocation bails on the non-object
// location.
//
// Spec: OIDC Core 1.0 §5.5.
func TestScenario_CL_05_NonObjectSectionRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, _ := clRegisterRP(t, tk, "rp-cl-05")
	clSeedAlice(t, tk)

	status, env := clAuthorizeBadClaims(t, tk, rp, `{"id_token":["not","an","object"]}`)
	if status != http.StatusBadRequest {
		t.Fatalf("/authorize status=%d want 400", status)
	}
	if got, _ := env["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (env=%v)", got, env)
	}
}

// TestScenario_CL_06_NullOrEmptySectionAccepted checks that a claims
// payload whose id_token / userinfo members are JSON null or an empty
// object parses without error: parseClaimsLocation treats both shapes
// as "absent member" and the projector behaves identically to "no
// claims requested". Issuance proceeds and no claim leaks beyond the
// scope-derived release.
//
// Spec: OIDC Core 1.0 §5.5.
func TestScenario_CL_06_NullOrEmptySectionAccepted(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-06")
	clSeedAlice(t, tk)

	// Mix the two accepted shapes: id_token=null, userinfo={}.
	extra := url.Values{"claims": {`{"id_token":null,"userinfo":{}}`}}
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", extra)
	if tok.IDToken == "" {
		t.Fatal("id_token missing — null/empty section must not block issuance")
	}
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if v, ok := idClaims["email"]; ok {
		t.Errorf("id_token leaked email=%v from an empty claims section", v)
	}
}

// TestScenario_CL_07_UnknownTopLevelKeysIgnored checks that the parser
// silently drops top-level members other than id_token / userinfo —
// per §5.5 the wire form "MAY be supplemented by additional members".
// A request that pairs a real id_token claim with a vendor-extension
// _claim_names sibling parses normally and the projector still
// honours the recognised member.
//
// Spec: OIDC Core 1.0 §5.5.
func TestScenario_CL_07_UnknownTopLevelKeysIgnored(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-07")
	clSeedAlice(t, tk)

	extra := url.Values{"claims": {
		`{"_claim_names":{"foo":"bar"},"id_token":{"email":{"essential":true}}}`,
	}}
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", extra)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got := idClaims["email"]; got != "alice@example.com" {
		t.Errorf("id_token email=%v want alice@example.com (recognised member must still project)", got)
	}
	if v, ok := idClaims["_claim_names"]; ok {
		t.Errorf("id_token leaked _claim_names=%v — vendor extension must not be re-emitted", v)
	}
}

// TestScenario_CL_08_ClaimsWithResponseTypeNoneRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_08_ClaimsWithResponseTypeNoneRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-08 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_09_UserinfoRequestedWithoutEndpoint is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_09_UserinfoRequestedWithoutEndpoint(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-09 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_10_UserinfoRequestedWithoutAccessToken is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_10_UserinfoRequestedWithoutAccessToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-10 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_20_NullClaimEntryAcceptedAsVoluntary checks that an
// individual claim entry whose body is JSON null parses as a voluntary
// request (no constraint, not essential) and the projector releases
// the claim when the source has a value for it.
//
// Spec: OIDC Core 1.0 §5.5.1 (an entry that is "null" requests the
// claim "in the default manner").
func TestScenario_CL_20_NullClaimEntryAcceptedAsVoluntary(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-20")
	clSeedAlice(t, tk)

	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email": nil, // voluntary request, no constraint
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", extra)
	if tok.IDToken == "" {
		t.Fatal("id_token missing")
	}
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got := idClaims["email"]; got != "alice@example.com" {
		t.Errorf("id_token email=%v want alice@example.com (voluntary request)", got)
	}
}

// TestScenario_CL_21_EmptyObjectClaimEntryAcceptedAsVoluntary checks
// that an entry whose body is "{}" — an empty object — is treated
// identically to JSON null (voluntary, no constraint) by the parser
// and projector.
//
// Spec: OIDC Core 1.0 §5.5.1.
func TestScenario_CL_21_EmptyObjectClaimEntryAcceptedAsVoluntary(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-21")
	clSeedAlice(t, tk)

	// {} for the entry body — voluntary, no essential, no value.
	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{},
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", extra)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got := idClaims["email"]; got != "alice@example.com" {
		t.Errorf("id_token email=%v want alice@example.com (empty-object voluntary)", got)
	}
}

// TestScenario_CL_22_EssentialMissingClaimOmitted checks the OP's
// "MUST attempt" reading of OIDC Core 1.0 §5.5.1: an essential request
// for a claim that the user store has no value for is silently omitted
// from the response rather than triggering an error or a null value.
//
// Spec: OIDC Core 1.0 §5.5.1 ("essential"=true, but spec only mandates
// "OP MUST attempt").
func TestScenario_CL_22_EssentialMissingClaimOmitted(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-22")
	// Seed a user that lacks the requested "phone_number" claim.
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims:  map[string]any{"email": "alice@example.com"},
	})

	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"phone_number": map[string]any{"essential": true},
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", extra)
	if tok.IDToken == "" {
		t.Fatal("id_token missing — essential request must not block issuance")
	}
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if v, ok := idClaims["phone_number"]; ok {
		t.Errorf("id_token leaked phone_number=%v despite missing source value", v)
	}
}

// TestScenario_CL_23_ValueMismatchOmitsClaim checks that when a claim
// is requested with a "value" constraint that the source value does
// not match, the OP omits the claim from the response.
//
// Spec: OIDC Core 1.0 §5.5.1 ("value": claim is delivered only if the
// stored value matches).
func TestScenario_CL_23_ValueMismatchOmitsClaim(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-23")
	clSeedAlice(t, tk)

	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{"value": "bob@example.com"}, // mismatch
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", extra)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if v, ok := idClaims["email"]; ok {
		t.Errorf("id_token released email=%v despite value-constraint mismatch", v)
	}
}

// TestScenario_CL_24_ValuesArrayMatchReleasesClaim checks that when a
// claim is requested with a "values" array constraint, the OP releases
// the claim if the stored value matches any element and omits it
// otherwise. This test exercises the match path; the omit path is
// covered structurally by CL-23.
//
// Spec: OIDC Core 1.0 §5.5.1 ("values": claim is delivered only if
// the stored value matches one of the listed values).
func TestScenario_CL_24_ValuesArrayMatchReleasesClaim(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-24")
	clSeedAlice(t, tk)

	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{
				"values": []any{"bob@example.com", "alice@example.com", "carol@example.com"},
			},
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", extra)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got := idClaims["email"]; got != "alice@example.com" {
		t.Errorf("id_token email=%v want alice@example.com (values-array match)", got)
	}
}

// TestScenario_CL_25_ValueComparisonUsesJSONEquality checks that the
// projector's value/values comparison observes JSON equality across
// the primitive shapes the spec admits: strings compare by byte
// equality (match path releases the claim, mismatch omits it), and
// booleans compare by identity. Numeric and array shapes share the
// same jsonEqual path; CL-23 / CL-24 already exercise the value /
// values constraints positively at the wire layer.
//
// Spec: OIDC Core 1.0 §5.5.1.
func TestScenario_CL_25_ValueComparisonUsesJSONEquality(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-25")
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "alice@example.com",
			"email_verified": true,
		},
	})

	// Match path: requested string equals the source string AND the
	// boolean matches its source value.
	extraMatch := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email":          map[string]any{"value": "alice@example.com"},
			"email_verified": map[string]any{"value": true},
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid", extraMatch)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got := idClaims["email"]; got != "alice@example.com" {
		t.Errorf("id_token email=%v want alice@example.com (string equality)", got)
	}
	if got := idClaims["email_verified"]; got != true {
		t.Errorf("id_token email_verified=%v want true (bool equality)", got)
	}

	// Mismatch path: a different string and a flipped boolean must
	// both fall out of the projection.
	rp2, secret2 := clRegisterRP(t, tk, "rp-cl-25b")
	extraMiss := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email":          map[string]any{"value": "bob@example.com"},
			"email_verified": map[string]any{"value": false},
		},
	})
	_, tok2 := clRunCodeFlow(t, tk, rp2, secret2, "openid", extraMiss)
	idClaims2 := decodeScenarioJWTClaims(t, tok2.IDToken)
	if v, ok := idClaims2["email"]; ok {
		t.Errorf("id_token leaked email=%v despite string-value mismatch", v)
	}
	if v, ok := idClaims2["email_verified"]; ok {
		t.Errorf("id_token leaked email_verified=%v despite bool-value mismatch", v)
	}
}

// TestScenario_CL_26_NonStandardEntryShapesIgnored is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_26_NonStandardEntryShapesIgnored(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-26 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_27_LanguageTaggedKeysPreserved checks that the parser
// admits OIDC Core §5.5.2 language tag suffixes ("name#ja-JP") on a
// claim entry verbatim, and the projector releases the matching key
// from the user store.
//
// Spec: OIDC Core 1.0 §5.5.2.
func TestScenario_CL_27_LanguageTaggedKeysPreserved(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-27")
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"name":       "Alice Example",
			"name#ja-JP": "アリス・エグザンプル",
		},
	})

	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"name#ja-JP": map[string]any{"essential": true},
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid", extra)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got := idClaims["name#ja-JP"]; got != "アリス・エグザンプル" {
		t.Errorf("id_token[name#ja-JP]=%v want %q (language tag must be preserved verbatim)",
			got, "アリス・エグザンプル")
	}
}

// TestScenario_CL_30_IDTokenClaimEmbeddedDirectly checks that a claim
// requested under the top-level "id_token" location is embedded
// directly in the issued id_token, regardless of whether the same
// claim would have been released by the granted scopes.
//
// Spec: OIDC Core 1.0 §5.5 ("id_token" location targets the ID Token).
func TestScenario_CL_30_IDTokenClaimEmbeddedDirectly(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-30")
	clSeedAlice(t, tk)

	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{"essential": true},
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", extra)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got := idClaims["email"]; got != "alice@example.com" {
		t.Errorf("id_token email=%v want alice@example.com", got)
	}
}

// TestScenario_CL_31_UserinfoClaimDoesNotLeakToIDToken checks that a
// claim requested only under the "userinfo" location is included in
// the /userinfo response and never appears in the id_token.
//
// Spec: OIDC Core 1.0 §5.5 ("userinfo" location targets the UserInfo
// endpoint response).
func TestScenario_CL_31_UserinfoClaimDoesNotLeakToIDToken(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-31")
	clSeedAlice(t, tk)

	// Request "name" exclusively in the userinfo location. We use the
	// "openid" scope only — without "profile", a scope-driven release
	// would not include "name", so its presence in /userinfo proves
	// the §5.5 projector did the work.
	extra := claimsRequestExtra(t, map[string]any{
		"userinfo": map[string]any{
			"name": map[string]any{"essential": true},
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid", extra)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if v, ok := idClaims["name"]; ok {
		t.Errorf("id_token leaked name=%v from a userinfo-only claims request", v)
	}
	status, _, body := callUserinfo(t, tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status=%d body=%v", status, body)
	}
	if got := body["name"]; got != "Alice Example" {
		t.Errorf("/userinfo name=%v want Alice Example (userinfo location request)", got)
	}
}

// TestScenario_CL_32_BothSectionsProjectedIndependently checks that
// when the same claim name appears under both "id_token" and
// "userinfo", each location is projected independently — neither
// overrides nor cross-contaminates the other. The id_token carries
// the claim because the id_token location requested it; the
// /userinfo response carries the claim because the userinfo location
// requested it.
//
// Spec: OIDC Core 1.0 §5.5.
func TestScenario_CL_32_BothSectionsProjectedIndependently(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-32")
	clSeedAlice(t, tk)

	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{"essential": true},
		},
		"userinfo": map[string]any{
			"email": map[string]any{"essential": true},
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", extra)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got := idClaims["email"]; got != "alice@example.com" {
		t.Errorf("id_token email=%v want alice@example.com", got)
	}
	status, _, body := callUserinfo(t, tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status=%d body=%v", status, body)
	}
	if got := body["email"]; got != "alice@example.com" {
		t.Errorf("/userinfo email=%v want alice@example.com", got)
	}
}

// TestScenario_CL_33_ClaimsBypassScopeRelease checks that the §5.5
// projector releases an individually-requested claim even when the
// granted scope alone would not have surfaced it. The request asks
// for "email" in the id_token while the granted scope is bare
// "openid"; the released id_token carries the email claim, proving
// the claims parameter is read independently of the scope-derived
// allow-list.
//
// Spec: OIDC Core 1.0 §5.5 ("the claims parameter MAY be used to
// request that specific Claims be returned ... in addition to those
// returned by the use of specific scope values").
func TestScenario_CL_33_ClaimsBypassScopeRelease(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-33")
	clSeedAlice(t, tk)

	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{"essential": true},
		},
	})
	// Bare "openid" — no "email" scope. A scope-only release would
	// keep email out of the id_token.
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid", extra)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got := idClaims["email"]; got != "alice@example.com" {
		t.Errorf("id_token email=%v want alice@example.com (claims must bypass scope-only release)", got)
	}
}

// TestScenario_CL_34_MissingSourceValueOmitted pins the projector's
// "omit on absent" stance at the userinfo location: a claim requested
// in claims.userinfo whose key is missing from the user store record
// is silently dropped from the response. The OP never emits a JSON
// null on the wire to signal absence — the same posture as CL-22 for
// the id_token location.
//
// Spec: OIDC Core 1.0 §5.5.
func TestScenario_CL_34_MissingSourceValueOmitted(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-34")
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims:  map[string]any{"email": "alice@example.com"},
	})

	extra := claimsRequestExtra(t, map[string]any{
		"userinfo": map[string]any{
			"phone_number": map[string]any{"essential": true},
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", extra)
	status, _, body := callUserinfo(t, tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status=%d body=%v", status, body)
	}
	if v, ok := body["phone_number"]; ok {
		t.Errorf("/userinfo released phone_number=%v despite missing source value", v)
	}
	// "sub" must still be present — projector never drops it.
	if got, _ := body["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("/userinfo sub=%v want %q", body["sub"], scenariokit.DefaultSubject)
	}
}

// TestScenario_CL_35_SubClaimNotOverwritten checks that the projector
// guards the standard "sub" claim: even when the request asks for
// claims.id_token.sub with a value that disagrees with the session
// subject, the issued id_token carries the OP-internal subject
// untouched. The same protection applies to /userinfo (sub is the
// only claim Build always emits regardless of scope).
//
// Spec: OIDC Core 1.0 §5.5 ("Requesting the 'sub' (subject) Claim
// ... has no effect").
func TestScenario_CL_35_SubClaimNotOverwritten(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-35")
	clSeedAlice(t, tk)

	// Hostile request: ask the projector to overwrite "sub" with a
	// value the user never authenticated as.
	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"sub": map[string]any{"value": "attacker"},
		},
		"userinfo": map[string]any{
			"sub": map[string]any{"value": "attacker"},
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", extra)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got, _ := idClaims["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("id_token sub=%v want %q (sub must not be overwritten)",
			idClaims["sub"], scenariokit.DefaultSubject)
	}
	status, _, body := callUserinfo(t, tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status=%d body=%v", status, body)
	}
	if got, _ := body["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("/userinfo sub=%v want %q (sub must not be overwritten)",
			body["sub"], scenariokit.DefaultSubject)
	}
}

// TestScenario_CL_36_RefreshGrantInheritsClaims checks that the §5.5
// "claims" payload persisted on the originating grant is honoured by
// the refresh-token-derived id_token. The originating /authorize
// carries claims.id_token.email; the refresh exchange returns an
// id_token that still carries the projected claim (no per-refresh
// re-submission is required).
//
// Spec: OIDC Core 1.0 §5.5.2 / §12 (refresh-derived id_token must
// reflect the original authorization).
func TestScenario_CL_36_RefreshGrantInheritsClaims(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithStrictOfflineAccess()))
	rp, secret := clRegisterRP(t, tk, "rp-cl-36")
	// Re-register with offline_access support so the first /token
	// returns a refresh_token.
	updated := *rp
	updated.Scopes = []string{"openid", "email", "offline_access"}
	if err := tk.Store.UpdateClient(context.Background(), &updated); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	clSeedAlice(t, tk)

	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{"essential": true},
		},
	})
	_, first := clRunCodeFlow(t, tk, rp, secret, "openid email offline_access", extra)
	if first.RefreshToken == "" {
		t.Fatalf("first /token did not return refresh_token: raw=%v", first.Raw)
	}
	if got := decodeScenarioJWTClaims(t, first.IDToken)["email"]; got != "alice@example.com" {
		t.Fatalf("first id_token email=%v want alice@example.com", got)
	}

	refreshed := postRefreshToken(t, tk, first.RefreshToken, rp.ID, secret)
	if refreshed.StatusCode != http.StatusOK {
		t.Fatalf("/token refresh status=%d body=%v", refreshed.StatusCode, refreshed.Raw)
	}
	if refreshed.IDToken == "" {
		t.Fatal("refresh did not return id_token")
	}
	refreshedClaims := decodeScenarioJWTClaims(t, refreshed.IDToken)
	if got := refreshedClaims["email"]; got != "alice@example.com" {
		t.Errorf("refreshed id_token email=%v want alice@example.com (claims request not inherited)", got)
	}
}

// TestScenario_CL_37_AuthCodeGrantInheritsClaims checks that the §5.5
// "claims" payload persisted on the grant by /authorize is honoured by
// the authorization_code grant at /token. The id_token issued at
// /token reflects the projection — even though the /token request
// itself does not carry the claims parameter — because the grant
// carries it forward (Grant.Claims, decoded via DecodeClaimsFromGrant).
//
// CL-30 / CL-32 cover the same code path positively for specific
// locations; this row pins the broader contract that the carry-forward
// is unconditional and survives the /authorize → /token boundary.
//
// Spec: OIDC Core 1.0 §5.5 / §3.1.3.7.
func TestScenario_CL_37_AuthCodeGrantInheritsClaims(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-37")
	clSeedAlice(t, tk)

	// Request "name" in the id_token (a claim the granted "openid"
	// scope alone would not surface). The /token request body does
	// not re-send the claims parameter — the projector must read it
	// off the grant.
	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"name": map[string]any{"essential": true},
		},
	})
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid", extra)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got := idClaims["name"]; got != "Alice Example" {
		t.Errorf("id_token name=%v want Alice Example (grant must carry the claims request to /token)", got)
	}
}

// TestScenario_CL_40_EssentialACRSingleValueSatisfied is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_40_EssentialACRSingleValueSatisfied(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-40 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_41_EssentialACRValuesArraySatisfied is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_41_EssentialACRValuesArraySatisfied(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-41 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_42_EssentialACRUnsatisfiedPromptNone is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_42_EssentialACRUnsatisfiedPromptNone(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-42 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_43_InvalidACRValuesTypeRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_43_InvalidACRValuesTypeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-43 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_44_VoluntaryACRMissAllowed is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_44_VoluntaryACRMissAllowed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-44 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_45_DefaultACRValuesBackfilled checks that when an
// /authorize request omits acr_values and the registered client
// publishes default_acr_values (store.Client.DefaultACRValues), the
// authorize endpoint backfills the request's ACR list (see
// applyClientAuthorizeDefaults) and the resulting id_token carries
// an "acr" claim driven by the OP's ACR policy.
//
// The DefaultACRPolicy echoes the first satisfied entry from the
// backfilled list when the ceremony reached AAL1 or above (the
// testkit's SubjectAuthenticator provides exactly that). The wire
// shape proves the backfill: without DefaultACRValues this id_token
// would carry the AAL-derived InCommon URI rather than the client's
// configured value.
//
// Spec: OIDC Core 1.0 §5.5 / OIDC Registration §2 (default_acr_values).
func TestScenario_CL_45_DefaultACRValuesBackfilled(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-45")
	clSeedAlice(t, tk)

	// Apply default_acr_values to the registered client. The
	// authorize endpoint's applyClientAuthorizeDefaults will copy
	// this list onto req.ACRValues when the wire request omits the
	// parameter.
	updated := *rp
	updated.DefaultACRValues = []string{"urn:test:cl-45:loa1"}
	if err := tk.Store.UpdateClient(context.Background(), &updated); err != nil {
		t.Fatalf("UpdateClient(DefaultACRValues): %v", err)
	}

	// No acr_values on the wire — the backfill is the only path that
	// can populate the resulting id_token's acr claim.
	_, tok := clRunCodeFlow(t, tk, rp, secret, "openid email", nil)
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got, _ := idClaims["acr"].(string); got != "urn:test:cl-45:loa1" {
		t.Errorf("id_token acr=%v want %q (default_acr_values must backfill)",
			idClaims["acr"], "urn:test:cl-45:loa1")
	}
}

// TestScenario_CL_50_SubValueMatchesSessionSubject is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_50_SubValueMatchesSessionSubject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-50 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_51_PairwiseSubValueMatch is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_51_PairwiseSubValueMatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-51 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_52_SubValueMismatchPromptNone is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_52_SubValueMismatchPromptNone(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-52 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_53_PairwiseSubValueMismatchPromptNone is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_53_PairwiseSubValueMismatchPromptNone(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-53 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_54_NoSessionSubValueLogin is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_54_NoSessionSubValueLogin(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-54 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_60_HintSubMatchesSessionSubject is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_60_HintSubMatchesSessionSubject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-60 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_61_PairwiseHintSubMatch is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_61_PairwiseHintSubMatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-61 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_62_HintSubMismatchPromptNone is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_62_HintSubMismatchPromptNone(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-62 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_63_PairwiseHintSubMismatchPromptNone is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_63_PairwiseHintSubMismatchPromptNone(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-63 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_64_NoSessionWithHintRoutesToLogin is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_64_NoSessionWithHintRoutesToLogin(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-64 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_65_HintSignatureOrAudFailureRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_65_HintSignatureOrAudFailureRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-65 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_66_ExpiredHintAcceptedForSubMatch is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_66_ExpiredHintAcceptedForSubMatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-66 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_70_UngrantedClaimPromptNoneConsentRequired is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_70_UngrantedClaimPromptNoneConsentRequired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-70 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_71_RejectedClaimsExcludedFromProjection is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_71_RejectedClaimsExcludedFromProjection(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-71 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_80_ClaimsCarriedInJAR checks that a §5.5 claims
// payload nested inside a signed Request Object (RFC 9101 §6.1) reaches
// the projector identically to a wire-form claims parameter. The OP's
// JAR merge re-encodes JSON-shaped claims (claims, authorization_details)
// onto the merged form and the downstream parser handles them through
// the same authorize.ParseClaimsRequest path as plain-form rows.
//
// Spec: RFC 9101 §6.1 / OIDC Core 1.0 §5.5.
func TestScenario_CL_80_ClaimsCarriedInJAR(t *testing.T) {
	t.Parallel()

	const (
		callback = "https://rp.testkit.invalid/callback"
		clientID = "rp-cl-80"
	)
	const clientSecret = "rp-cl-80-secret" //nolint:gosec // test fixture, not a real credential.

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.JAR)))
	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	const kid = "rp-cl-80-kid"
	jwksRaw, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key:       &priv.PublicKey,
		KeyID:     kid,
		Algorithm: string(josev4.ES256),
		Use:       "sig",
	}}})
	if err != nil {
		t.Fatalf("Marshal JWKS: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		JWKs:                    jwksRaw,
	})
	clSeedAlice(t, tk)

	pkce := scenariokit.NewPKCEPair("")
	now := time.Now().UTC()
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	roClaims := map[string]any{
		"iss":                   rp.ID,
		"aud":                   tk.Issuer,
		"exp":                   now.Add(2 * time.Minute).Unix(),
		"iat":                   now.Unix(),
		"nbf":                   now.Unix(),
		"jti":                   "cl-80-jti-" + hex.EncodeToString(jtiBytes),
		"client_id":             rp.ID,
		"response_type":         "code",
		"redirect_uri":          callback,
		"scope":                 "openid",
		"state":                 scenariokit.DefaultState,
		"nonce":                 scenariokit.DefaultNonce,
		"code_challenge":        pkce.Challenge,
		"code_challenge_method": pkce.Method,
		// Nest the §5.5 payload as a structured object — the merge
		// step JSON-encodes it before the form-level parser sees it.
		"claims": map[string]any{
			"id_token": map[string]any{
				"email": map[string]any{"essential": true},
			},
		},
	}
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: josev4.ES256,
			Key: josev4.JSONWebKey{
				Key:       priv,
				KeyID:     kid,
				Algorithm: string(josev4.ES256),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType("oauth-authz-req+jwt"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	requestObject, err := jwt.Signed(signer).Claims(roClaims).Serialize()
	if err != nil {
		t.Fatalf("Serialize request object: %v", err)
	}

	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid",
		PKCE:        pkce,
		Extra:       url.Values{"request": {requestObject}},
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	idClaims := decodeScenarioJWTClaims(t, tok.IDToken)
	if got := idClaims["email"]; got != "alice@example.com" {
		t.Errorf("id_token email=%v want alice@example.com (JAR-carried claims must reach projector)", got)
	}
}

// TestScenario_CL_81_ClaimsReevaluatedAtPARPickup is OOS — see catalog out_of_scope_reason.
func TestScenario_CL_81_ClaimsReevaluatedAtPARPickup(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CL-81 (see catalog out_of_scope_reason)")
}

// TestScenario_CL_82_GETAndPOSTParseIdentically checks that an
// /authorize request carrying a §5.5 claims parameter via the URL
// query (GET) and via the form body (POST) yields the same projection.
// The OP's parser delegates to extractValues which reads URL.Query()
// for GET and r.PostForm for POST, then funnels both into the shared
// ParseValues path; the resulting id_token must surface the requested
// claim regardless of transport.
//
// Spec: OIDC Core 1.0 §3.1.2.1 (the wire form admits GET and POST).
func TestScenario_CL_82_GETAndPOSTParseIdentically(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := clRegisterRP(t, tk, "rp-cl-82")
	clSeedAlice(t, tk)

	// GET path — RunCodeFlow drives /authorize over GET by default.
	extra := claimsRequestExtra(t, map[string]any{
		"id_token": map[string]any{
			"email": map[string]any{"essential": true},
		},
	})
	_, getTok := clRunCodeFlow(t, tk, rp, secret, "openid", extra)
	getClaims := decodeScenarioJWTClaims(t, getTok.IDToken)
	if got := getClaims["email"]; got != "alice@example.com" {
		t.Fatalf("GET id_token email=%v want alice@example.com", got)
	}

	// POST path — drive /authorize manually with the same parameters
	// in the form body. The auto-consent driver still threads the
	// interaction once /authorize has 302'd onto /interaction.
	pkce := scenariokit.NewPKCEPair("scenariokit-default-verifier-scenariokit-cl-82-post-1234")
	form := url.Values{
		"client_id":             {rp.ID},
		"response_type":         {"code"},
		"redirect_uri":          {rp.RedirectURIs[0]},
		"scope":                 {"openid"},
		"state":                 {scenariokit.DefaultState},
		"nonce":                 {scenariokit.DefaultNonce},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
		"claims":                extra["claims"],
	}
	// Drive /authorize via POST body and confirm it 302s to the
	// interaction step (parsing succeeded). Once parsing is proven we
	// rely on the GET-path projector test above for the wire payload —
	// the parser feeds both transports into the same ParseValues.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/auth", io.NopCloser(strReader(form.Encode())))
	if err != nil {
		t.Fatalf("build POST /authorize: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /authorize status=%d want 302 body=%s", resp.StatusCode, string(body))
	}
	// A 302 to /oidc/interaction proves the POST parser accepted the
	// wire form; a parse failure would have surfaced as a 400 envelope.
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if !pathHasPrefix(loc.Path, "/oidc/interaction/") {
		t.Errorf("POST /authorize Location.Path=%q want /oidc/interaction/...", loc.Path)
	}
}

// strReader wraps a string as an io.Reader. The helper lets the CL-82
// POST hop avoid pulling in strings.NewReader at the top of the file
// when the rest of the suite reads its bodies as []byte.
func strReader(s string) *clStringReader {
	return &clStringReader{s: s}
}

type clStringReader struct {
	s string
	i int
}

func (r *clStringReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

// pathHasPrefix returns true when path starts with prefix. It avoids a
// strings import in this file; the suite-wide convention uses dedicated
// helpers per file.
func pathHasPrefix(path, prefix string) bool {
	if len(path) < len(prefix) {
		return false
	}
	return path[:len(prefix)] == prefix
}

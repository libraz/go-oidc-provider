package scenarios_test

// Catalog: test/scenarios/catalog/claims.yaml (CL-NN)
// Spec:
//   - OIDC Core 1.0 §5.5, §5.5.1, §5.5.1.1, §5.5.2
//   - OIDC Core 1.0 §3.1.2.1, §15
//   - RFC 9101 — JWT Secured Authorization Request (JAR)
//   - RFC 9126 — Pushed Authorization Requests (PAR)

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
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

func TestScenario_CL_04_MissingIDTokenAndUserinfoRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-04")
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

func TestScenario_CL_06_NullOrEmptySectionAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-06")
}

func TestScenario_CL_07_UnknownTopLevelKeysIgnored(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-07")
}

func TestScenario_CL_08_ClaimsWithResponseTypeNoneRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-08")
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

func TestScenario_CL_25_ValueComparisonUsesJSONEquality(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-25")
}

func TestScenario_CL_26_NonStandardEntryShapesIgnored(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-26")
}

func TestScenario_CL_27_LanguageTaggedKeysPreserved(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-27")
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

func TestScenario_CL_33_ClaimsBypassScopeRelease(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-33")
}

func TestScenario_CL_34_MissingSourceValueOmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-34")
}

func TestScenario_CL_35_SubClaimNotOverwritten(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-35")
}

func TestScenario_CL_36_RefreshGrantInheritsClaims(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-36")
}

func TestScenario_CL_37_AuthCodeGrantInheritsClaims(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-37")
}

func TestScenario_CL_40_EssentialACRSingleValueSatisfied(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-40")
}

func TestScenario_CL_41_EssentialACRValuesArraySatisfied(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-41")
}

func TestScenario_CL_42_EssentialACRUnsatisfiedPromptNone(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-42")
}

func TestScenario_CL_43_InvalidACRValuesTypeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-43")
}

func TestScenario_CL_44_VoluntaryACRMissAllowed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-44")
}

func TestScenario_CL_45_DefaultACRValuesBackfilled(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-45")
}

func TestScenario_CL_50_SubValueMatchesSessionSubject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-50")
}

func TestScenario_CL_51_PairwiseSubValueMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-51")
}

func TestScenario_CL_52_SubValueMismatchPromptNone(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-52")
}

func TestScenario_CL_53_PairwiseSubValueMismatchPromptNone(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-53")
}

func TestScenario_CL_54_NoSessionSubValueLogin(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-54")
}

func TestScenario_CL_60_HintSubMatchesSessionSubject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-60")
}

func TestScenario_CL_61_PairwiseHintSubMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-61")
}

func TestScenario_CL_62_HintSubMismatchPromptNone(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-62")
}

func TestScenario_CL_63_PairwiseHintSubMismatchPromptNone(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-63")
}

func TestScenario_CL_64_NoSessionWithHintRoutesToLogin(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-64")
}

func TestScenario_CL_65_HintSignatureOrAudFailureRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-65")
}

func TestScenario_CL_66_ExpiredHintAcceptedForSubMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-66")
}

func TestScenario_CL_70_UngrantedClaimPromptNoneConsentRequired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-70")
}

func TestScenario_CL_71_RejectedClaimsExcludedFromProjection(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-71")
}

func TestScenario_CL_80_ClaimsCarriedInJAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-80")
}

func TestScenario_CL_81_ClaimsReevaluatedAtPARPickup(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-81")
}

func TestScenario_CL_82_GETAndPOSTParseIdentically(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-82")
}

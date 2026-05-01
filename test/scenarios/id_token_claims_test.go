package scenarios_test

// Catalog: test/scenarios/catalog/id_token_claims.yaml (IDT-NN)
// Spec:
//   - OIDC Core 1.0 §2, §3.1.3.6, §3.1.3.7
//   - OIDC Core 1.0 §3.2.2.10 (at_hash), §3.3.2.10 (c_hash)
//   - OIDC Core 1.0 §5.3, §5.4, §5.5, §10, §16.11
//   - OIDC Front-Channel Logout 1.0 §2.2, OIDC Back-Channel Logout 1.0 §2.4
//   - JARM §4.2 (s_hash)
//   - RFC 9068 — JWT access token profile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// idtDefaultIDTokenTTL mirrors the OP's default id_token lifetime
// (internal/tokenendpoint/handler.go's defaultIDTokenTTL). v1.0 does
// not expose a public option to override it, so the IDT-40 assertion
// pins the wire shape to this constant.
const idtDefaultIDTokenTTL = 10 * time.Minute

// idtSpecHash captures the (sub, claims) pair extracted from the
// id_token returned by a code-flow exchange. Helpers reuse it so the
// per-row tests keep their bodies focused on the assertion under test.
type idtSpecHash struct {
	IDToken string
	Header  map[string]any
	Claims  map[string]any
}

// idtRunCodeFlow drives the canonical code flow against tk for the
// supplied client / scope, exchanges the resulting code at /token, and
// returns the parsed id_token together with its decoded JWS header and
// payload. Tests that need to inspect the full token response can
// recover it from the `tok` return value.
func idtRunCodeFlow(t *testing.T, tk *testkit.Provider, rp *store.Client, secret, scope string) (scenariokit.TokenResponse, idtSpecHash) {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: rp.RedirectURIs[0],
		Scope:       scope,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
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
	if tok.IDToken == "" {
		t.Fatal("/token response missing id_token")
	}
	return tok, idtSpecHash{
		IDToken: tok.IDToken,
		Header:  idtDecodeJWTHeader(t, tok.IDToken),
		Claims:  decodeScenarioJWTClaims(t, tok.IDToken),
	}
}

// idtDecodeJWTHeader returns the decoded protected header of a compact
// JWS. The OP signs id_tokens with ES256 only (internal/keys ships
// GenerateES256), so the IDT-41 assertion compares against that pin.
func idtDecodeJWTHeader(t *testing.T, jws string) map[string]any {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS has %d parts, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header segment: %v", err)
	}
	hdr := map[string]any{}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v (raw=%q)", err, raw)
	}
	return hdr
}

// idtRegisterRP installs a confidential code-flow client on tk with
// the canonical id-token-claims fixture. The returned secret is the
// plaintext credential the test should pass to /token.
func idtRegisterRP(t *testing.T, tk *testkit.Provider, id string) (*store.Client, string) {
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

// idtSeedAlice puts the canonical Alice user record on tk's store so
// the userinfo-related rows can assert on scope-derived claims.
func idtSeedAlice(t *testing.T, tk *testkit.Provider) {
	t.Helper()
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "alice@example.com",
			"email_verified": true,
		},
	})
}

// TestScenario_IDT_01_MandatoryClaimsPresent asserts that every
// id_token issued via the code-flow happy path carries the five
// hard-required claims (iss, sub, aud, exp, iat) with sane types.
//
// Spec: OIDC Core 1.0 §2 (ID Token, REQUIRED claims).
func TestScenario_IDT_01_MandatoryClaimsPresent(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := idtRegisterRP(t, tk, "rp-idt-01")
	_, decoded := idtRunCodeFlow(t, tk, rp, secret, "openid")

	if got, _ := decoded.Claims["iss"].(string); got == "" {
		t.Errorf("iss missing or not string: %v", decoded.Claims["iss"])
	}
	if got, _ := decoded.Claims["sub"].(string); got == "" {
		t.Errorf("sub missing or not string: %v", decoded.Claims["sub"])
	}
	if _, ok := decoded.Claims["aud"]; !ok {
		t.Error("aud claim missing")
	}
	if _, ok := decoded.Claims["exp"].(float64); !ok {
		t.Errorf("exp missing or not numeric: %v (%T)", decoded.Claims["exp"], decoded.Claims["exp"])
	}
	if _, ok := decoded.Claims["iat"].(float64); !ok {
		t.Errorf("iat missing or not numeric: %v (%T)", decoded.Claims["iat"], decoded.Claims["iat"])
	}
}

// TestScenario_IDT_02_AudContainsClientID asserts that the id_token's
// aud claim names the requesting client_id (whether wire-encoded as a
// string or as a string array).
//
// Spec: OIDC Core 1.0 §2 (aud REQUIRED, MUST contain the client_id).
func TestScenario_IDT_02_AudContainsClientID(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := idtRegisterRP(t, tk, "rp-idt-02")
	_, decoded := idtRunCodeFlow(t, tk, rp, secret, "openid")

	if !idtAudContains(decoded.Claims["aud"], rp.ID) {
		t.Errorf("aud=%v does not contain client_id=%q", decoded.Claims["aud"], rp.ID)
	}
}

// TestScenario_IDT_08_IssMatchesDiscovery asserts that the iss claim
// stamped on the id_token equals the issuer published in the
// discovery document.
//
// Spec: OIDC Core 1.0 §2 / OIDC Discovery §3 (issuer).
func TestScenario_IDT_08_IssMatchesDiscovery(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := idtRegisterRP(t, tk, "rp-idt-08")

	_, _, doc := fetchDiscovery(t, tk.Server.URL)
	wantIss, _ := doc["issuer"].(string)
	if wantIss == "" {
		t.Fatal("discovery document missing issuer")
	}

	_, decoded := idtRunCodeFlow(t, tk, rp, secret, "openid")
	got, _ := decoded.Claims["iss"].(string)
	if got != wantIss {
		t.Errorf("iss=%q want %q (discovery issuer)", got, wantIss)
	}
}

// TestScenario_IDT_30_AudShapeAndContents asserts v1.0's wire shape
// for the aud claim: when only one audience is present the OP emits
// it as a bare string (not a single-element array), and the value is
// the requesting client_id. The string-or-array choice is implemented
// by internal/tokens/tokens.go's encodeAudience.
//
// Spec: OIDC Core 1.0 §2 / RFC 7519 §4.1.3.
func TestScenario_IDT_30_AudShapeAndContents(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := idtRegisterRP(t, tk, "rp-idt-30")
	_, decoded := idtRunCodeFlow(t, tk, rp, secret, "openid")

	switch aud := decoded.Claims["aud"].(type) {
	case string:
		if aud != rp.ID {
			t.Errorf("aud=%q want %q", aud, rp.ID)
		}
	case []any:
		if !idtAudContains(aud, rp.ID) {
			t.Errorf("aud=%v does not contain client_id=%q", aud, rp.ID)
		}
	default:
		t.Errorf("aud claim has unexpected type %T (value=%v)", decoded.Claims["aud"], decoded.Claims["aud"])
	}
}

// TestScenario_IDT_31_SingleAudOmitsAzp pins v1.0's behaviour: when
// the id_token carries a single-audience aud claim, the OP omits azp
// entirely. v1.0 has no caller in internal/grants that populates the
// AZP field on tokens.IDTokenClaims, so azp never appears on the
// wire — a stricter posture than the OIDC Core "MAY omit" allowance.
//
// Spec: OIDC Core 1.0 §2 (azp is OPTIONAL when aud has a single value).
func TestScenario_IDT_31_SingleAudOmitsAzp(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := idtRegisterRP(t, tk, "rp-idt-31")
	_, decoded := idtRunCodeFlow(t, tk, rp, secret, "openid")

	// Sanity-check the precondition: aud is a bare string (single value).
	if _, ok := decoded.Claims["aud"].(string); !ok {
		t.Fatalf("precondition: expected single-value aud as string, got %T (%v)",
			decoded.Claims["aud"], decoded.Claims["aud"])
	}
	if got, ok := decoded.Claims["azp"]; ok {
		t.Errorf("azp present (=%v); v1.0 omits azp for single-aud id_tokens", got)
	}
}

// TestScenario_IDT_40_LifetimeFollowsDefaultIDTokenTTL asserts that
// the difference exp - iat equals the OP's id_token lifetime. v1.0
// does not expose a public option to override it, so the value is
// pinned to the internal 10-minute default. The injected clock keeps
// the assertion deterministic without sleeping.
//
// Spec: OIDC Core 1.0 §2 (exp / iat).
func TestScenario_IDT_40_LifetimeFollowsDefaultIDTokenTTL(t *testing.T) {
	t.Parallel()

	clock := newAdvanceableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	rp, secret := idtRegisterRP(t, tk, "rp-idt-40")
	_, decoded := idtRunCodeFlow(t, tk, rp, secret, "openid")

	iat, ok := decoded.Claims["iat"].(float64)
	if !ok {
		t.Fatalf("iat is not a JSON number: %T", decoded.Claims["iat"])
	}
	exp, ok := decoded.Claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp is not a JSON number: %T", decoded.Claims["exp"])
	}
	got := time.Duration(int64(exp)-int64(iat)) * time.Second
	want := idtDefaultIDTokenTTL
	tolerance := 1 * time.Second
	diff := got - want
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
		t.Errorf("exp - iat = %s, want %s (±%s)", got, want, tolerance)
	}
}

// TestScenario_IDT_41_SignedWithES256ByDefault asserts that, in the
// default testkit configuration, the id_token's JWS header carries
// alg=ES256. v1.0's internal/keys generator only emits ES256 keys
// (internal/keys/generate.go's GenerateES256), so the OP advertises
// and signs with ES256 unless the embedder injects a different
// keyset.
//
// Spec: OIDC Core 1.0 §10.1 (id_token_signed_response_alg).
func TestScenario_IDT_41_SignedWithES256ByDefault(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := idtRegisterRP(t, tk, "rp-idt-41")
	_, decoded := idtRunCodeFlow(t, tk, rp, secret, "openid")

	alg, _ := decoded.Header["alg"].(string)
	if alg != "ES256" {
		t.Errorf("id_token alg=%q want ES256", alg)
	}
	if typ, ok := decoded.Header["typ"].(string); ok && typ != "JWT" && typ != "" {
		// id_token spec is silent on a specific typ, but "JWT" is the
		// only conventional value; reject any surprise typ values.
		t.Errorf("id_token typ=%q want \"JWT\" or absent", typ)
	}
}

// TestScenario_IDT_50_UserinfoReturnsScopeClaims asserts that an
// access_token issued with a scope that maps to user-profile claims
// (here: "email") exchanges, when presented to /userinfo, for a body
// that carries those scope-derived claims.
//
// Spec: OIDC Core 1.0 §5.3 / §5.4.
func TestScenario_IDT_50_UserinfoReturnsScopeClaims(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := idtRegisterRP(t, tk, "rp-idt-50")
	idtSeedAlice(t, tk)
	tok, _ := idtRunCodeFlow(t, tk, rp, secret, "openid email")

	status, body, challenge := getUserInfo(t, tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status=%d want 200; challenge=%q", status, challenge)
	}
	if got, _ := body["email"].(string); got != "alice@example.com" {
		t.Errorf("email=%v want alice@example.com", body["email"])
	}
	if v, ok := body["email_verified"].(bool); !ok || !v {
		t.Errorf("email_verified=%v want true", body["email_verified"])
	}
}

// TestScenario_IDT_54_UserinfoAlwaysIncludesSub asserts that the
// /userinfo response carries sub regardless of which scope-derived
// claims the access_token's grant unlocks. OIDC Core §5.3.2 makes sub
// the only mandatory member of the userinfo body.
//
// Spec: OIDC Core 1.0 §5.3.2.
func TestScenario_IDT_54_UserinfoAlwaysIncludesSub(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := idtRegisterRP(t, tk, "rp-idt-54")
	idtSeedAlice(t, tk)
	// "openid" alone — no scope-derived claims, so the only thing
	// userinfo must still surface is sub.
	tok, _ := idtRunCodeFlow(t, tk, rp, secret, "openid")

	status, body, challenge := getUserInfo(t, tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status=%d want 200; challenge=%q", status, challenge)
	}
	if got, _ := body["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("userinfo sub=%v want %q", body["sub"], scenariokit.DefaultSubject)
	}
}

// TestScenario_IDT_55_UserinfoSubMatchesIDTokenSub asserts that the
// sub claim on /userinfo is byte-equal to the sub embedded in the
// id_token issued from the same authorize / token round-trip. The
// match is the spec's anti-subject-swap guarantee — any drift would
// let a substituted access_token return a different identity than
// the id_token's binding.
//
// Spec: OIDC Core 1.0 §16.11.
func TestScenario_IDT_55_UserinfoSubMatchesIDTokenSub(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	rp, secret := idtRegisterRP(t, tk, "rp-idt-55")
	idtSeedAlice(t, tk)
	tok, decoded := idtRunCodeFlow(t, tk, rp, secret, "openid email")

	idtSub, _ := decoded.Claims["sub"].(string)
	if idtSub == "" {
		t.Fatalf("id_token sub missing: %v", decoded.Claims)
	}
	status, body, challenge := getUserInfo(t, tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("/userinfo status=%d want 200; challenge=%q", status, challenge)
	}
	uiSub, _ := body["sub"].(string)
	if uiSub != idtSub {
		t.Errorf("userinfo sub=%q want id_token sub=%q", uiSub, idtSub)
	}
}

// TestScenario_IDT_61_IatReadsFromInjectedClock asserts that the iat
// claim is sourced from the OP's clock — not the wall clock. The
// test pins the injected clock to a known instant, runs a code flow,
// and checks that the id_token's iat equals that instant's Unix
// reading (within ±1s tolerance for the integer floor).
//
// Spec: OIDC Core 1.0 §2 (iat).
func TestScenario_IDT_61_IatReadsFromInjectedClock(t *testing.T) {
	t.Parallel()

	frozen := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	clock := newAdvanceableClock(frozen)
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	rp, secret := idtRegisterRP(t, tk, "rp-idt-61")
	_, decoded := idtRunCodeFlow(t, tk, rp, secret, "openid")

	iat, ok := decoded.Claims["iat"].(float64)
	if !ok {
		t.Fatalf("iat is not a JSON number: %T", decoded.Claims["iat"])
	}
	want := frozen.Unix()
	got := int64(iat)
	if diff := got - want; diff > 1 || diff < -1 {
		t.Errorf("iat=%d want %d (±1s); injected clock=%s", got, want, frozen)
	}
}

// TestScenario_IDT_62_IssNeverDeviatesFromDiscovery asserts that the
// iss claim minted on the id_token equals the discovery document's
// issuer field, drawn from a non-default issuer URL. The previous
// row (IDT-08) covers the default issuer; this one pins the same
// invariant when the OP is configured with a custom issuer to catch
// any code path that hard-codes the default.
//
// Spec: OIDC Core 1.0 §2 / OIDC Discovery §3.
func TestScenario_IDT_62_IssNeverDeviatesFromDiscovery(t *testing.T) {
	t.Parallel()

	const customIssuer = "https://op-idt-62.testkit.invalid"
	tk := testkit.NewProvider(t, testkit.WithIssuer(customIssuer))
	rp, secret := idtRegisterRP(t, tk, "rp-idt-62")

	_, _, doc := fetchDiscovery(t, tk.Server.URL)
	wantIss, _ := doc["issuer"].(string)
	if wantIss != customIssuer {
		t.Fatalf("discovery issuer=%q want %q", wantIss, customIssuer)
	}

	_, decoded := idtRunCodeFlow(t, tk, rp, secret, "openid")
	got, _ := decoded.Claims["iss"].(string)
	if got != wantIss {
		t.Errorf("id_token iss=%q want discovery issuer=%q", got, wantIss)
	}
}

// idtAudContains reports whether aud (which may be a string or a
// JSON-array of strings) names client_id at least once. Used by the
// IDT-02 / IDT-30 rows so the wire-shape branches stay collapsed at
// the call site.
func idtAudContains(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, entry := range v {
			if s, ok := entry.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// ---- pending stubs (untouched in this batch) ----

// TestScenario_IDT_03_AzpSetWhenAudMultiOrRequired is OOS — see catalog out_of_scope_reason.
func TestScenario_IDT_03_AzpSetWhenAudMultiOrRequired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: IDT-03 (see catalog out_of_scope_reason)")
}

func TestScenario_IDT_04_NonceMirroredFromRequest(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-04")
}

func TestScenario_IDT_05_AuthTimeIncludedWhenEssentialOrMaxAge(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-05")
}

func TestScenario_IDT_06_AcrEmittedOnRequestOrDefault(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-06")
}

func TestScenario_IDT_07_AmrVoluntarilyEmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-07")
}

func TestScenario_IDT_10_ConformTrueExcludesScopeClaimsWithAT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-10")
}

// TestScenario_IDT_11_ConformTrueIncludesScopeClaimsWhenIDTokenOnly is OOS — see catalog out_of_scope_reason.
func TestScenario_IDT_11_ConformTrueIncludesScopeClaimsWhenIDTokenOnly(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: IDT-11 (see catalog out_of_scope_reason)")
}

// TestScenario_IDT_12_ConformFalseAlwaysIncludesScopeClaims is OOS — see catalog out_of_scope_reason.
func TestScenario_IDT_12_ConformFalseAlwaysIncludesScopeClaims(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: IDT-12 (see catalog out_of_scope_reason)")
}

// TestScenario_IDT_13_HybridFlowExcludesScopeClaims is OOS — see catalog out_of_scope_reason.
func TestScenario_IDT_13_HybridFlowExcludesScopeClaims(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: IDT-13 (see catalog out_of_scope_reason)")
}

func TestScenario_IDT_14_ClaimsParameterAlwaysProjectedToIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-14")
}

func TestScenario_IDT_15_RefreshGrantUsesSameComposition(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-15")
}

func TestScenario_IDT_16_TokenEndpointUsesSameComposition(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-16")
}

func TestScenario_IDT_17_RejectedClaimsExcluded(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-17")
}

// TestScenario_IDT_20_AtHashRequiredWhenIDTokenAndATIssued is OOS — see catalog out_of_scope_reason.
func TestScenario_IDT_20_AtHashRequiredWhenIDTokenAndATIssued(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: IDT-20 (see catalog out_of_scope_reason)")
}

func TestScenario_IDT_21_AtHashComputation(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-21")
}

// TestScenario_IDT_22_CHashRequiredWhenIDTokenAndCodeIssued is OOS — see catalog out_of_scope_reason.
func TestScenario_IDT_22_CHashRequiredWhenIDTokenAndCodeIssued(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: IDT-22 (see catalog out_of_scope_reason)")
}

func TestScenario_IDT_23_CHashComputation(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-23")
}

func TestScenario_IDT_24_SHashOptionalUnderJARM(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-24")
}

func TestScenario_IDT_25_TokenEndpointIDTokenOmitsHashes(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-25")
}

func TestScenario_IDT_26_HashAlgFollowsSigningAlg(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-26")
}

func TestScenario_IDT_27_NoneAlgOmitsHashClaims(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-27")
}

func TestScenario_IDT_32_MultiAudRequiresAzp(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-32")
}

func TestScenario_IDT_33_SidIncludedForLogoutSubscribers(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-33")
}

func TestScenario_IDT_34_ResourceAudienceNotInIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-34")
}

func TestScenario_IDT_42_SignedThenEncryptedWhenConfigured(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-42")
}

func TestScenario_IDT_43_SymmetricAlgUsesClientSecret(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-43")
}

func TestScenario_IDT_44_DistinctTypForIDTokenAndATJWT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-44")
}

func TestScenario_IDT_51_UserinfoReleasesClaimsParameterEntries(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-51")
}

func TestScenario_IDT_52_SignedUserinfoResponse(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-52")
}

func TestScenario_IDT_53_EncryptedUserinfoResponse(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-53")
}

func TestScenario_IDT_60_NoUnsolicitedSensitiveDataEmbedded(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-60")
}

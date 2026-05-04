package scenarios_test

// Catalog: test/scenarios/catalog/pairwise.yaml (PW-NN)
// Spec:
//   - OIDC Core 1.0 §8, §8.1, §8.2, §3.1.2.1, §5.3, §5.5.1, §16
//   - OIDC Dynamic Client Registration 1.0 §2
//   - OIDC CIBA Core 1.0 §11
//   - OIDC Device Authorization 1.0 §6
//   - RFC 7662 — OAuth 2.0 Token Introspection

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// pwPairwiseSalt is the deterministic 32-byte salt the PW issuance
// rows wire through op.WithPairwiseSubject. The catalogue requires
// fixed fixtures so a failing trace replays identically across runs.
var pwPairwiseSalt = []byte("pw-pairwise-fixed-salt-32b!_v0.9")

// pwClientSecret is the deterministic confidential-client secret the
// PW issuance rows reuse. It mirrors the cgClientSecret pattern in
// custom_grants_test.go so the constant is local to the suite.
const pwClientSecret = "pw-client-secret"

// newPairwiseProvider constructs a testkit Provider that derives the
// "sub" claim through op.WithPairwiseSubject. Tests assemble their
// own clients via tk.RegisterClient because per-row sector setups
// vary (different redirect-host pairs, shared sector_identifier_uri,
// etc.).
func newPairwiseProvider(t *testing.T) *testkit.Provider {
	t.Helper()
	return testkit.NewProvider(t, testkit.WithOptions(
		op.WithPairwiseSubject(pwPairwiseSalt),
	))
}

// newPairwiseDCRProvider mirrors [newPairwiseProvider] but also enables
// Dynamic Client Registration so the registration-time validation rows
// (PW-10..PW-12, PW-20) can drive POST /oidc/register through the
// public wire. Static-client tests stay on [newPairwiseProvider].
func newPairwiseDCRProvider(t *testing.T) *testkit.Provider {
	t.Helper()
	return testkit.NewProvider(t, testkit.WithOptions(
		op.WithPairwiseSubject(pwPairwiseSalt),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	))
}

// pairwiseClient seeds a confidential client whose redirect_uri host
// will be picked up as the sector by the pairwise generator (sector
// resolution falls back to the single redirect host when
// SectorIdentifierURI is empty). Returns the registered store.Client
// and the plaintext secret so the test can drive HTTP Basic auth.
func pairwiseClient(t *testing.T, tk *testkit.Provider, id, redirectURI string) *store.Client {
	t.Helper()
	hash, err := op.HashClientSecret(pwClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	return tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      id,
		SecretHash:              hash,
		RedirectURIs:            []string{redirectURI},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SubjectType:             "pairwise",
	})
}

// runPairwiseFlow drives a complete /authorize → /interaction →
// /token round-trip for the given client and returns the id_token
// "sub" claim. The subject submitted to the testkit
// SubjectAuthenticator is fixed (DefaultSubject) so tests can compare
// "sub" output across clients without per-call subject jitter.
func runPairwiseFlow(t *testing.T, tk *testkit.Provider, c *store.Client, redirectURI string) string {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    c.ID,
		RedirectURI: redirectURI,
		Scope:       "openid",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  redirectURI,
		Verifier:     pkce.Verifier,
		ClientID:     c.ID,
		ClientSecret: pwClientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	if tok.IDToken == "" {
		t.Fatalf("/token did not return id_token (raw=%v)", tok.Raw)
	}
	claims := decodePWJWTClaims(t, tok.IDToken)
	sub, _ := claims["sub"].(string)
	if sub == "" {
		t.Fatalf("id_token claims missing sub: %v", claims)
	}
	return sub
}

// decodePWJWTClaims pulls the payload claims out of a JWS Compact
// Serialisation without verifying the signature. The PW issuance
// rows compare "sub" values across flows; verifying the signature
// would re-test JWS framing, which the IDT-suite already covers.
func decodePWJWTClaims(tb testing.TB, jws string) map[string]any {
	tb.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		tb.Fatalf("jwt parts=%d want 3 (value=%q)", len(parts), jws)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		tb.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		tb.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

// postPairwiseRegistration drives the public /oidc/register endpoint for
// the PW-02..PW-04 rows. The helper centralises the IAT issuance, JSON
// body marshalling, bearer header, and response decoding so the
// per-row tests can focus on the assertion that distinguishes them.
// Returns the HTTP status code and decoded response body (which may be
// either a successful client-information response or an error envelope
// per RFC 7591 §3.2).
func postPairwiseRegistration(tb testing.TB, tk *testkit.Provider, body map[string]any) (int, map[string]any) {
	tb.Helper()

	issued, err := tk.OP.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		tb.Fatalf("IssueInitialAccessToken: %v", err)
	}

	raw, err := json.Marshal(body)
	if err != nil {
		tb.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/register", bytes.NewReader(raw))
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+issued.Value)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("POST /oidc/register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}
	var decoded map[string]any
	if len(bytes.TrimSpace(respBytes)) > 0 {
		if err := json.Unmarshal(respBytes, &decoded); err != nil {
			tb.Fatalf("body is not JSON: %v (raw=%q)", err, string(respBytes))
		}
	}
	return resp.StatusCode, decoded
}

// TestScenario_PW_01_DiscoveryEnumeratesSupportedTypes asserts that the
// OP's discovery document advertises the exact set of subject identifier
// types it implements. With pairwise pinned OFF in v1.0
// (PairwiseEnabled=false; no public WithPairwiseSubject option ships)
// the published list MUST be exactly ["public"]. Advertising "pairwise"
// here without serving it would mislead RPs into requesting a
// subject_type the OP cannot honour.
//
// Spec: OIDC Core 1.0 §8 (subject_types_supported is REQUIRED metadata).
func TestScenario_PW_01_DiscoveryEnumeratesSupportedTypes(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, doc := fetchDiscovery(t, p.Server.URL)

	raw, ok := doc["subject_types_supported"].([]any)
	if !ok {
		t.Fatalf("subject_types_supported missing or wrong type: %T", doc["subject_types_supported"])
	}
	got := make([]string, 0, len(raw))
	for i, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("subject_types_supported[%d]=%v not a string", i, v)
		}
		got = append(got, s)
	}
	slices.Sort(got)
	want := []string{"public"}
	if !slices.Equal(got, want) {
		t.Errorf("subject_types_supported=%v want %v (pairwise is OFF in v1.0)", got, want)
	}
}

// TestScenario_PW_02_MissingSubjectTypeFallsBackToPublic drives the
// public /oidc/register endpoint with a metadata payload that omits
// subject_type and asserts the success response echoes
// "subject_type": "public" — the OP's documented default. Verified on
// the wire (registration response body) so the assertion covers the
// public surface rather than internal fields.
//
// Spec: OIDC Core 1.0 §8 / OIDC Dynamic Client Registration 1.0 §2
// (subject_type is OPTIONAL; omitted means the OP's default).
func TestScenario_PW_02_MissingSubjectTypeFallsBackToPublic(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)

	body := map[string]any{
		"redirect_uris": []string{"https://rp.example.com/cb"},
		// subject_type intentionally omitted.
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusCreated {
		t.Fatalf("status=%d want 201 body=%v", status, resp)
	}
	got, _ := resp["subject_type"].(string)
	if got != "public" {
		t.Errorf("subject_type=%q want %q (default when omitted)", got, "public")
	}
}

// TestScenario_PW_03_PairwiseRequestRejectedWhenFeatureOff drives the
// public /oidc/register endpoint with subject_type=pairwise against an
// OP whose pairwise feature is disabled (the v1.0 default; no public
// WithPairwiseSubject option ships). The OP MUST refuse the
// registration with 400 invalid_client_metadata so the RP cannot
// silently receive a public sub when it asked for a pairwise one. The
// internal validator (validateSubjectType) phrases this as
// "subject_type pairwise requires WithPairwiseSubject"; this test asserts
// only the wire-stable error code and that the description names the
// offending field.
//
// Spec: OIDC Core 1.0 §8 / RFC 7591 §3.2.2 (invalid_client_metadata).
func TestScenario_PW_03_PairwiseRequestRejectedWhenFeatureOff(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)

	body := map[string]any{
		"redirect_uris": []string{"https://rp.example.com/cb"},
		"subject_type":  "pairwise",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, resp)
	}
	if got, _ := resp["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata (body=%v)", got, resp)
	}
	desc, _ := resp["error_description"].(string)
	if !strings.Contains(desc, "subject_type") {
		t.Errorf("error_description=%q must name the subject_type field", desc)
	}
}

// TestScenario_PW_04_PairwiseUnimplementedRejectsRegistration captures
// the framing of OIDC Dynamic Client Registration 1.0 §2 from the
// perspective of an OP that does not implement pairwise at all (as
// opposed to PW-03's "feature is wired but disabled at this OP"
// framing). On v1.0 of this Go OP the two collapse to the same wire
// behaviour because no implementation path for pairwise ships, but
// keeping the row separate preserves the catalog's spec-level
// distinction so a future minor that implements pairwise still has a
// dedicated test for the "implementation absent" case.
//
// Spec: OIDC Dynamic Client Registration 1.0 §2 (subject_type values
// the OP does not support yield invalid_client_metadata).
func TestScenario_PW_04_PairwiseUnimplementedRejectsRegistration(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)

	body := map[string]any{
		"redirect_uris": []string{"https://rp.example.com/cb"},
		"subject_type":  "pairwise",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, resp)
	}
	if got, _ := resp["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata (body=%v)", got, resp)
	}
}

// TestScenario_PW_10_SingleHostRedirectURIsAdoptHostAsSector confirms
// a pairwise client may register without sector_identifier_uri when
// every redirect_uri shares one host. The OP accepts the registration
// (the host then serves as the sector at issuance time, see PW-43 /
// PW-44 for the issuance-side determinism); a 400 here would force
// every single-host pairwise RP to host a sector document needlessly.
//
// Spec: OIDC Core 1.0 §8.1 (single-host pairwise needs no sector
// document; the redirect host is sufficient).
func TestScenario_PW_10_SingleHostRedirectURIsAdoptHostAsSector(t *testing.T) {
	t.Parallel()

	tk := newPairwiseDCRProvider(t)
	body := map[string]any{
		"redirect_uris": []string{
			"https://rp.example.com/cb1",
			"https://rp.example.com/cb2",
		},
		"subject_type": "pairwise",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusCreated {
		t.Fatalf("status=%d want 201 body=%v", status, resp)
	}
	got, _ := resp["subject_type"].(string)
	if got != "pairwise" {
		t.Errorf("subject_type=%q want pairwise (body=%v)", got, resp)
	}
}

// TestScenario_PW_11_MultiHostRequiresSectorURI asserts a pairwise
// client whose redirect_uris span more than one host and omits
// sector_identifier_uri is rejected with invalid_client_metadata.
// Without an explicit sector document the OP cannot decide which
// host scopes the pairwise hash — admitting the registration would
// silently bind subs to whichever redirect arrived first.
//
// Spec: OIDC Core 1.0 §8.1 / RFC 7591 §3.2.2.
func TestScenario_PW_11_MultiHostRequiresSectorURI(t *testing.T) {
	t.Parallel()

	tk := newPairwiseDCRProvider(t)
	body := map[string]any{
		"redirect_uris": []string{
			"https://alpha.example/cb",
			"https://beta.example/cb",
		},
		"subject_type": "pairwise",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, resp)
	}
	if got, _ := resp["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata (body=%v)", got, resp)
	}
	desc, _ := resp["error_description"].(string)
	if !strings.Contains(desc, "sector_identifier_uri") {
		t.Errorf("error_description=%q must name the sector_identifier_uri requirement", desc)
	}
}

// TestScenario_PW_12_PathDifferenceOnSameHostAllowed pins that the
// single-host check looks only at the URL host: two redirect_uris
// that share a host but differ in path register without a sector
// document. The OAuth redirect_uri matching is byte-exact at runtime,
// but the §8.1 sector grouping is host-only by design.
//
// Spec: OIDC Core 1.0 §8.1.
func TestScenario_PW_12_PathDifferenceOnSameHostAllowed(t *testing.T) {
	t.Parallel()

	tk := newPairwiseDCRProvider(t)
	body := map[string]any{
		"redirect_uris": []string{
			"https://rp.example.com/app/cb",
			"https://rp.example.com/admin/cb",
		},
		"subject_type": "pairwise",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusCreated {
		t.Fatalf("status=%d want 201 body=%v", status, resp)
	}
	if got, _ := resp["subject_type"].(string); got != "pairwise" {
		t.Errorf("subject_type=%q want pairwise (body=%v)", got, resp)
	}
}

// TestScenario_PW_13_NoRedirectURIsRelyOnJwksHost is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_13_NoRedirectURIsRelyOnJwksHost(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-13 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_20_SectorURIMustBeHTTPS confirms the OP refuses a
// sector_identifier_uri whose scheme is not https. The check fires at
// URL parse time before any outbound I/O so an attacker cannot use
// the OP to probe an http upstream from a known network position.
// DCR-VAL-06 covers the same wire shape from the DCR catalog; this
// row pins the binding from the pairwise catalog.
//
// Spec: OIDC Core 1.0 §8.1 (sector_identifier_uri MUST be https).
func TestScenario_PW_20_SectorURIMustBeHTTPS(t *testing.T) {
	t.Parallel()

	tk := newPairwiseDCRProvider(t)
	body := map[string]any{
		"redirect_uris":         []string{"https://rp.example.com/cb"},
		"subject_type":          "pairwise",
		"sector_identifier_uri": "http://rp.example.com/sector.json",
	}
	status, resp := postPairwiseRegistration(t, tk, body)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, resp)
	}
	if got, _ := resp["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata (body=%v)", got, resp)
	}
}

// TestScenario_PW_21_SectorURIFetchedAtRegistration is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_21_SectorURIFetchedAtRegistration(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-21 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_22_SectorURINon200StatusFails is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_22_SectorURINon200StatusFails(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-22 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_23_SectorURIUnparseableJSONFails is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_23_SectorURIUnparseableJSONFails(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-23 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_24_SectorURINonArrayBodyFails is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_24_SectorURINonArrayBodyFails(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-24 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_25_SectorURIMustIncludeAllRedirectURIs is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_25_SectorURIMustIncludeAllRedirectURIs(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-25 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_26_PublicClientSectorURIHostRecorded is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_26_PublicClientSectorURIHostRecorded(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-26 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_27_SectorIdentifierIsLowercaseHost is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_27_SectorIdentifierIsLowercaseHost(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-27 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_30_CIBARequiresJwksURIInSectorList is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_30_CIBARequiresJwksURIInSectorList(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-30 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_31_DeviceFlowRequiresJwksURIInSectorList is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_31_DeviceFlowRequiresJwksURIInSectorList(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-31 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_32_NoRedirectClientsUseJwksAsSectorAnchor is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_32_NoRedirectClientsUseJwksAsSectorAnchor(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-32 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_40_PairwiseSubIsDeterministic confirms the
// pairwise transform is deterministic at issuance: two independent
// authorize → /token round-trips through the same client for the
// same internal subject MUST produce the same id_token "sub". The
// determinism contract is the basis of the (sector, subject)
// grouping every other PW-40 series row depends on.
//
// Spec: OIDC Core 1.0 §8.1.
func TestScenario_PW_40_PairwiseSubIsDeterministic(t *testing.T) {
	t.Parallel()
	tk := newPairwiseProvider(t)
	c := pairwiseClient(t, tk, "rp-pw-40", "https://rp.example.com/cb")

	sub1 := runPairwiseFlow(t, tk, c, "https://rp.example.com/cb")
	sub2 := runPairwiseFlow(t, tk, c, "https://rp.example.com/cb")
	if sub1 != sub2 {
		t.Errorf("pairwise sub drifted across two flows: %q vs %q", sub1, sub2)
	}
}

// TestScenario_PW_41_SaltIsSensitiveOPSecret is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_41_SaltIsSensitiveOPSecret(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-41 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_42_DefaultAlgorithmShape is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_42_DefaultAlgorithmShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-42 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_43_DifferentSectorsProduceDifferentSubs confirms
// that two clients whose sector_identifier hosts differ receive
// different "sub" values for the same internal subject. The two
// clients here register single redirect URIs on disjoint hosts
// (alpha.example vs beta.example); the OIDC Core §8.1 sector
// resolution falls back to the redirect host when
// sector_identifier_uri is absent, so the two flows derive the
// pairwise sub against different sectors.
//
// Spec: OIDC Core 1.0 §8.1 (sector grouping enforces disjoint
// pseudonyms across sector boundaries).
func TestScenario_PW_43_DifferentSectorsProduceDifferentSubs(t *testing.T) {
	t.Parallel()
	tk := newPairwiseProvider(t)
	alpha := pairwiseClient(t, tk, "rp-pw-43-alpha", "https://alpha.example/cb")
	beta := pairwiseClient(t, tk, "rp-pw-43-beta", "https://beta.example/cb")

	subAlpha := runPairwiseFlow(t, tk, alpha, "https://alpha.example/cb")
	subBeta := runPairwiseFlow(t, tk, beta, "https://beta.example/cb")
	if subAlpha == subBeta {
		t.Errorf("pairwise subs collided across sectors (%q == %q)", subAlpha, subBeta)
	}
}

// TestScenario_PW_44_SameSectorProducesSameSub confirms the
// converse of PW-43: two clients that resolve to the same sector
// (here, the same redirect host) receive the same pairwise "sub"
// for the same internal subject. The grouping is the whole point
// of the sector concept — applications a user owns under one
// brand share an identity even when the OAuth client_id differs.
//
// Spec: OIDC Core 1.0 §8.1.
func TestScenario_PW_44_SameSectorProducesSameSub(t *testing.T) {
	t.Parallel()
	tk := newPairwiseProvider(t)
	first := pairwiseClient(t, tk, "rp-pw-44-first", "https://shared.example/cb")
	second := pairwiseClient(t, tk, "rp-pw-44-second", "https://shared.example/cb")

	subFirst := runPairwiseFlow(t, tk, first, "https://shared.example/cb")
	subSecond := runPairwiseFlow(t, tk, second, "https://shared.example/cb")
	if subFirst != subSecond {
		t.Errorf("pairwise subs diverged within shared sector (%q != %q)", subFirst, subSecond)
	}
}

// TestScenario_PW_45_PublicClientUsesLocalAccountID is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_45_PublicClientUsesLocalAccountID(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-45 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_46_PairwiseSubLengthBounded is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_46_PairwiseSubLengthBounded(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-46 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_50_IDTokenSubFollowsSubjectType is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_50_IDTokenSubFollowsSubjectType(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-50 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_51_UserinfoSubFollowsSubjectType is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_51_UserinfoSubFollowsSubjectType(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-51 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_52_IntrospectionSubFollowsSubjectType is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_52_IntrospectionSubFollowsSubjectType(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-52 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_53_HintSubComparedAgainstSubjectType is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_53_HintSubComparedAgainstSubjectType(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-53 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_54_PairwiseClaimsSubValueMustMatch is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_54_PairwiseClaimsSubValueMustMatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-54 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_60_SaltRotationInvalidatesAllSubs is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_60_SaltRotationInvalidatesAllSubs(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-60 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_61_LocalIDNotLeakedInAuditPayload is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_61_LocalIDNotLeakedInAuditPayload(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-61 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_62_DiscoveryAdvertisesPairwiseWhenEnabled is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_62_DiscoveryAdvertisesPairwiseWhenEnabled(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-62 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_63_EmbedderHookForSaltAndHashFunction is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_63_EmbedderHookForSaltAndHashFunction(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-63 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_64_SectorURIFetchHasBoundedTimeout is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_64_SectorURIFetchHasBoundedTimeout(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-64 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_65_SectorURIResponseCacheablePolicyOPDefined is OOS — see catalog out_of_scope_reason.
func TestScenario_PW_65_SectorURIResponseCacheablePolicyOPDefined(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: PW-65 (see catalog out_of_scope_reason)")
}

// TestScenario_PW_70_RejectsSwitchOnUsedStoreWithWipedMarker pins the
// empty-store edge case for the subject-mode immutability gate. A
// re-used metadata store whose [store.SubjectModeKey] row was wiped
// (truncation, deliberate manipulation, or a tooling bug) but whose
// [store.OpInitKey] sentinel survives MUST refuse a non-public
// op.New construction. Without the sentinel probe the gate would
// fall through to the "fresh install" branch and silently re-key
// every future "sub" against the new strategy. The test seeds the
// op-init sentinel directly to simulate the post-wipe shape because
// no public API exposes a metadata-only truncation.
//
// Spec: OIDC Core 1.0 §8 (sub stability) / project v0.9.1 contract.
func TestScenario_PW_70_RejectsSwitchOnUsedStoreWithWipedMarker(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	if err := st.Metadata().Set(context.Background(), store.OpInitKey, store.OpInitMarker); err != nil {
		t.Fatalf("seed op-init sentinel: %v", err)
	}
	// MinimalOptions seeds its own inmem store; we override with WithStore
	// so the gate observes the sentinel we just stamped. The pairwise
	// option drives the gate into the "non-public on a previously-used
	// store" branch the row pins.
	opts := testkit.MinimalOptions(t,
		op.WithStore(st),
		op.WithPairwiseSubject(pwPairwiseSalt),
	)
	_, err := op.New(opts...)
	if !errors.Is(err, op.ErrSubjectModeMismatch) {
		t.Fatalf("op.New err=%v, want ErrSubjectModeMismatch (wiped marker on used store)", err)
	}
}

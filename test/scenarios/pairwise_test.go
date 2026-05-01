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
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

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

func TestScenario_PW_10_SingleHostRedirectURIsAdoptHostAsSector(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-10")
}

func TestScenario_PW_11_MultiHostRequiresSectorURI(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-11")
}

func TestScenario_PW_12_PathDifferenceOnSameHostAllowed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-12")
}

func TestScenario_PW_13_NoRedirectURIsRelyOnJwksHost(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-13")
}

func TestScenario_PW_20_SectorURIMustBeHTTPS(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-20")
}

func TestScenario_PW_21_SectorURIFetchedAtRegistration(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-21")
}

func TestScenario_PW_22_SectorURINon200StatusFails(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-22")
}

func TestScenario_PW_23_SectorURIUnparseableJSONFails(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-23")
}

func TestScenario_PW_24_SectorURINonArrayBodyFails(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-24")
}

func TestScenario_PW_25_SectorURIMustIncludeAllRedirectURIs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-25")
}

func TestScenario_PW_26_PublicClientSectorURIHostRecorded(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-26")
}

func TestScenario_PW_27_SectorIdentifierIsLowercaseHost(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-27")
}

func TestScenario_PW_30_CIBARequiresJwksURIInSectorList(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-30")
}

func TestScenario_PW_31_DeviceFlowRequiresJwksURIInSectorList(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-31")
}

func TestScenario_PW_32_NoRedirectClientsUseJwksAsSectorAnchor(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-32")
}

func TestScenario_PW_40_PairwiseSubIsDeterministic(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-40")
}

func TestScenario_PW_41_SaltIsSensitiveOPSecret(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-41")
}

func TestScenario_PW_42_DefaultAlgorithmShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-42")
}

func TestScenario_PW_43_DifferentSectorsProduceDifferentSubs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-43")
}

func TestScenario_PW_44_SameSectorProducesSameSub(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-44")
}

func TestScenario_PW_45_PublicClientUsesLocalAccountID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-45")
}

func TestScenario_PW_46_PairwiseSubLengthBounded(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-46")
}

func TestScenario_PW_50_IDTokenSubFollowsSubjectType(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-50")
}

func TestScenario_PW_51_UserinfoSubFollowsSubjectType(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-51")
}

func TestScenario_PW_52_IntrospectionSubFollowsSubjectType(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-52")
}

func TestScenario_PW_53_HintSubComparedAgainstSubjectType(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-53")
}

func TestScenario_PW_54_PairwiseClaimsSubValueMustMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-54")
}

func TestScenario_PW_60_SaltRotationInvalidatesAllSubs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-60")
}

func TestScenario_PW_61_LocalIDNotLeakedInAuditPayload(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-61")
}

func TestScenario_PW_62_DiscoveryAdvertisesPairwiseWhenEnabled(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-62")
}

func TestScenario_PW_63_EmbedderHookForSaltAndHashFunction(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-63")
}

func TestScenario_PW_64_SectorURIFetchHasBoundedTimeout(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-64")
}

func TestScenario_PW_65_SectorURIResponseCacheablePolicyOPDefined(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-65")
}

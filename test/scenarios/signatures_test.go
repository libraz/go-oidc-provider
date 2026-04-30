package scenarios_test

// Catalog: test/scenarios/catalog/signatures.yaml (SIG-NNN)
// Spec:
//   - RFC 7515 — JSON Web Signature
//   - RFC 7518 §3 — JSON Web Algorithms
//   - OIDC Core 1.0 §3.1.3.6 (`at_hash`, `c_hash`), §3.1.3.7 (id_token signing)
//   - RFC 9700 §2 / FAPI 1.0 / FAPI 2.0 (alg policy)

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestScenario_SIG_022_NoneAlgNotAdvertised verifies that the
// well-known discovery document never advertises `alg=none` for ID
// tokens. RFC 9700 §2 + FAPI 1/2 mandate at least RS256 baseline; none
// is forbidden. Also asserts at least one secure alg is advertised.
//
// Spec: OIDC Core §3.1.3.7, RFC 9700 §2.
func TestScenario_SIG_022_NoneAlgNotAdvertised(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	_, _, doc := fetchDiscovery(t, p.Server.URL)

	algs, _ := doc["id_token_signing_alg_values_supported"].([]any)
	if len(algs) == 0 {
		t.Fatalf("id_token_signing_alg_values_supported is empty; OIDC Core §3.1.3.7 requires advertising at least one alg")
	}
	for _, raw := range algs {
		alg, _ := raw.(string)
		if alg == "none" {
			t.Errorf("id_token_signing_alg_values_supported contains %q; RFC 9700 §2 forbids none for ID tokens", alg)
		}
	}
}

// --- Pending bindings --------------------------------------------------

func TestScenario_SIG_001_HS256IDTokenIssuance(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-001 — needs RP simulator + per-client alg pinning")
}

func TestScenario_SIG_002_HS256IDTokenAcceptedAsHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-002")
}

func TestScenario_SIG_010_AtHashLengthSHA256(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-010 — needs hybrid response_type wiring")
}

func TestScenario_SIG_011_AtHashLengthSHA384(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-011")
}

func TestScenario_SIG_012_AtHashLengthSHA512(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-012")
}

func TestScenario_SIG_013_EdDSAAtHashLength(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-013")
}

func TestScenario_SIG_014_Ed25519AtHashLength(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-014")
}

func TestScenario_SIG_020_AlgFromClientMetadataAndKidInHeader(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-020")
}

func TestScenario_SIG_021_AlgValuesAdvertisedInDiscovery(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SIG-021 — covered partially by SIG-022; expand once per-alg policy lands")
}

package scenarios_test

// Catalog: test/scenarios/catalog/issuer_identification.yaml (ISS-NNN)
// Spec:
//   - RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification
//   - RFC 8414 §2 — issuer metadata field
//   - OIDC Core 1.0 §3.1.2.5 / §3.1.2.6
//   - OIDC Core 1.0 §3.3 (hybrid)
//   - JARM §4.1

import "testing"

func TestScenario_ISS_001_DiscoveryAdvertisesIssParameterSupported(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-001")
}

func TestScenario_ISS_010_CodeFlowQueryCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-010")
}

func TestScenario_ISS_011_CodeTokenFragmentCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-011")
}

func TestScenario_ISS_012_CodeIDTokenFragmentEmbedsIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-012")
}

func TestScenario_ISS_013_CodeIDTokenTokenFragmentCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-013")
}

func TestScenario_ISS_014_IDTokenTokenFragmentCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-014")
}

func TestScenario_ISS_015_IDTokenFragmentCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-015")
}

func TestScenario_ISS_016_NoneResponseTypeQueryCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-016")
}

func TestScenario_ISS_017_JARMResponseEmbedsIssClaim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-017")
}

func TestScenario_ISS_020_RegularErrorRedirectCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-020")
}

func TestScenario_ISS_021_NoneResponseTypeErrorCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-021")
}

func TestScenario_ISS_022_JARMErrorQueryCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-022")
}

func TestScenario_ISS_023_JARMHybridErrorFragmentCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-023")
}

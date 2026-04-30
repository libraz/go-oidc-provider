package scenarios_test

// Catalog: test/scenarios/catalog/resource_indicators.yaml (RI-NNN)
// Spec:
//   - RFC 8707 — Resource Indicators for OAuth 2.0
//   - RFC 6749 §4.1, §4.4, §6
//   - RFC 8628 — OAuth 2.0 Device Authorization Grant
//   - RFC 9126 — OAuth 2.0 Pushed Authorization Requests
//   - OpenID Connect CIBA Core 1.0
//   - OIDC Core 1.0 §5.3 (UserInfo)

import "testing"

func TestScenario_RI_001_DefaultResourceHookExposed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-001")
}

func TestScenario_RI_002_GetResourceServerInfoFailsClosed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-002")
}

func TestScenario_RI_010_ResourceMustBeAbsoluteURI(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-010")
}

func TestScenario_RI_011_ResourceMustNotContainFragment(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-011")
}

func TestScenario_RI_012_EachResourceValueValidatedIndividually(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-012")
}

func TestScenario_RI_020_AuthorizeUnknownResourceFragmentRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-020")
}

func TestScenario_RI_021_AuthorizeAllowedResourceBindsAudience(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-021")
}

func TestScenario_RI_022_AuthorizeAppliesDefaultResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-022")
}

func TestScenario_RI_023_AuthorizeGetAndPostBehaveIdentically(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-023")
}

func TestScenario_RI_030_AuthorizeCodeUnknownResourceQueryRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-030")
}

func TestScenario_RI_031_AuthorizationCodePersistsResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-031")
}

func TestScenario_RI_032_TokenExchangePropagatesCodeResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-032")
}

func TestScenario_RI_033_RefreshPreservesResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-033")
}

func TestScenario_RI_034_DefaultResourceFlowsToCodeAndTokens(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-034")
}

func TestScenario_RI_035_UseGrantedResourceHookAtTokenExchange(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-035")
}

func TestScenario_RI_036_TokenExchangeAcceptsExplicitResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-036")
}

func TestScenario_RI_040_DeviceAuthRejectsUnknownResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-040")
}

func TestScenario_RI_041_DeviceTokenBindsAudienceAndResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-041")
}

func TestScenario_RI_042_DeviceFlowDefaultResourceAndRefresh(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-042")
}

func TestScenario_RI_043_DeviceFlowUseGrantedResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-043")
}

func TestScenario_RI_044_DeviceFlowExplicitResourceAtExchange(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-044")
}

func TestScenario_RI_050_BackchannelRejectsUnknownResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-050")
}

func TestScenario_RI_051_CIBATokenBindsAudienceAndResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-051")
}

func TestScenario_RI_052_CIBARefreshPreservesResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-052")
}

func TestScenario_RI_053_CIBADefaultResourceWithUseGrantedResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-053")
}

func TestScenario_RI_054_CIBAUseGrantedResourceFalseLeavesAudienceUnset(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-054")
}

func TestScenario_RI_060_ClientCredentialsBindsAudience(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-060")
}

func TestScenario_RI_061_ClientCredentialsDropsUnsupportedScopes(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-061")
}

func TestScenario_RI_062_ClientCredentialsRejectsUnknownResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-062")
}

func TestScenario_RI_063_ClientCredentialsRejectsMultipleResources(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-063")
}

func TestScenario_RI_064_ClientCredentialsValidatesEachResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-064")
}

func TestScenario_RI_065_ClientCredentialsAppliesDefaultResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-065")
}

func TestScenario_RI_066_ResourceTokenFormatPolicy(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-066")
}

func TestScenario_RI_070_UserInfoAcceptsAudienceLessTokens(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-070")
}

func TestScenario_RI_071_UserInfoRejectsResourceBoundTokens(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-071")
}

func TestScenario_RI_072_UserInfoRejectsNonStringAudience(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-072")
}

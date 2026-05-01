package scenarios_test

// Catalog: test/scenarios/catalog/client_id_metadata_document.yaml (CIMD-NNN)
// Spec:
//   - draft-ietf-oauth-client-id-metadata-document
//   - RFC 7591 §2 — Client Metadata Field Definitions
//   - OpenID Connect Core 1.0 §16.16, §16.17
//   - RFC 8414 — Authorization Server Metadata
//   - RFC 7517 — JWK / jwks_uri
//   - RFC 6749 §3.1.2 — redirect_uri matching

import "testing"

// TestScenario_CIMD_URL_01_HTTPSchemeRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_URL_01_HTTPSchemeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-URL-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_URL_02_PathRequired is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_URL_02_PathRequired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-URL-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_URL_03_DotSegmentsRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_URL_03_DotSegmentsRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-URL-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_URL_04_FragmentRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_URL_04_FragmentRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-URL-04 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_URL_05_UserinfoRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_URL_05_UserinfoRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-URL-05 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_URL_06_PortAndQueryAccepted is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_URL_06_PortAndQueryAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-URL-06 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_URL_07_NonURLTreatedAsRegularClientID is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_URL_07_NonURLTreatedAsRegularClientID(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-URL-07 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_01_RegisteredClientWinsOverCIMD is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_01_RegisteredClientWinsOverCIMD(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_02_RedirectsForbidden is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_02_RedirectsForbidden(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_03_ContentTypeMustBeJSON is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_03_ContentTypeMustBeJSON(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_04_NonOKStatusRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_04_NonOKStatusRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-04 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_05_InvalidJSONRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_05_InvalidJSONRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-05 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_06_BodySizeLimitEnforced is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_06_BodySizeLimitEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-06 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_07_NetworkFailureMappedToInvalidClient is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_07_NetworkFailureMappedToInvalidClient(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-07 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_08_CacheControlHonoured is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_08_CacheControlHonoured(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-08 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_09_AllowFetchHookGatesRequest is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_09_AllowFetchHookGatesRequest(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-09 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_10_AllowClientHookFiltersMetadata is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_10_AllowClientHookFiltersMetadata(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-10 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_11_DefaultAllowFetchBlocksPrivateRanges is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_11_DefaultAllowFetchBlocksPrivateRanges(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-11 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_12_FetchTimeoutsConfigurable is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_12_FetchTimeoutsConfigurable(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-12 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_META_01_ClientIDFieldMatchesURL is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_META_01_ClientIDFieldMatchesURL(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-META-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_META_02_AuthMethodLimitedToAsymmetric is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_META_02_AuthMethodLimitedToAsymmetric(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-META-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_META_03_ClientSecretFieldRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_META_03_ClientSecretFieldRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-META-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_META_04_URIFieldsRequireHTTPS is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_META_04_URIFieldsRequireHTTPS(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-META-04 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_META_05_RedirectURIsValidated is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_META_05_RedirectURIsValidated(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-META-05 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_META_06_UnsupportedGrantTypesFiltered is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_META_06_UnsupportedGrantTypesFiltered(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-META-06 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_META_07_UnsupportedResponseTypesFiltered is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_META_07_UnsupportedResponseTypesFiltered(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-META-07 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_META_08_UnsupportedResponseModesFiltered is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_META_08_UnsupportedResponseModesFiltered(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-META-08 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_META_09_GrantsAndResponseTypesAligned is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_META_09_GrantsAndResponseTypesAligned(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-META-09 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_META_10_JWKSAndJWKSURIExclusive is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_META_10_JWKSAndJWKSURIExclusive(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-META-10 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_META_11_NativeRedirectURIsLimited is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_META_11_NativeRedirectURIsLimited(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-META-11 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_DISC_01_FeatureFlagAdvertised is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_DISC_01_FeatureFlagAdvertised(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-DISC-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_DISC_02_FlagOmittedWhenDisabled is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_DISC_02_FlagOmittedWhenDisabled(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-DISC-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_CACHE_01_CacheKeyIsNormalizedURL is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_CACHE_01_CacheKeyIsNormalizedURL(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-CACHE-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_CACHE_02_SingleflightConcurrentFetches is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_CACHE_02_SingleflightConcurrentFetches(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-CACHE-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_CACHE_03_StrictMaxAgeExpiry is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_CACHE_03_StrictMaxAgeExpiry(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-CACHE-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_FLOW_01_AuthorizeStaticBeforeCIMD is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_FLOW_01_AuthorizeStaticBeforeCIMD(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-FLOW-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_FLOW_02_FetchedClientIsEphemeral is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_FLOW_02_FetchedClientIsEphemeral(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-FLOW-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_FLOW_03_RedirectURIMatchingStandard is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_FLOW_03_RedirectURIMatchingStandard(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-FLOW-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_FLOW_04_PARAcceptsCIMDClients is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_FLOW_04_PARAcceptsCIMDClients(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-FLOW-04 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_FLOW_05_TokenEndpointResolvesCIMD is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_FLOW_05_TokenEndpointResolvesCIMD(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-FLOW-05 (see catalog out_of_scope_reason)")
}

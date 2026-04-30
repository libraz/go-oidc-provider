package scenarios_test

// Catalog: test/scenarios/catalog/pairwise.yaml (PW-NN)
// Spec:
//   - OIDC Core 1.0 §8, §8.1, §8.2, §3.1.2.1, §5.3, §5.5.1, §16
//   - OIDC Dynamic Client Registration 1.0 §2
//   - OIDC CIBA Core 1.0 §11
//   - OIDC Device Authorization 1.0 §6
//   - RFC 7662 — OAuth 2.0 Token Introspection

import "testing"

func TestScenario_PW_01_DiscoveryEnumeratesSupportedTypes(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-01")
}

func TestScenario_PW_02_MissingSubjectTypeFallsBackToPublic(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-02")
}

func TestScenario_PW_03_PairwiseRequestRejectedWhenFeatureOff(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-03")
}

func TestScenario_PW_04_PairwiseUnimplementedRejectsRegistration(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PW-04")
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

package scenarios_test

// Catalog: test/scenarios/catalog/claims.yaml (CL-NN)
// Spec:
//   - OIDC Core 1.0 §5.5, §5.5.1, §5.5.1.1, §5.5.2
//   - OIDC Core 1.0 §3.1.2.1, §15
//   - RFC 9101 — JWT Secured Authorization Request (JAR)
//   - RFC 9126 — Pushed Authorization Requests (PAR)

import "testing"

func TestScenario_CL_01_AbsentClaimsParameter(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-01")
}

func TestScenario_CL_02_NonObjectTopLevelRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-02")
}

func TestScenario_CL_03_UnparsableClaimsRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-03")
}

func TestScenario_CL_04_MissingIDTokenAndUserinfoRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-04")
}

func TestScenario_CL_05_NonObjectSectionRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-05")
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

func TestScenario_CL_09_UserinfoRequestedWithoutEndpoint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-09")
}

func TestScenario_CL_10_UserinfoRequestedWithoutAccessToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-10")
}

func TestScenario_CL_20_NullClaimEntryAcceptedAsVoluntary(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-20")
}

func TestScenario_CL_21_EmptyObjectClaimEntryAcceptedAsVoluntary(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-21")
}

func TestScenario_CL_22_EssentialMissingClaimOmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-22")
}

func TestScenario_CL_23_ValueMismatchOmitsClaim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-23")
}

func TestScenario_CL_24_ValuesArrayMatchReleasesClaim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-24")
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

func TestScenario_CL_30_IDTokenClaimEmbeddedDirectly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-30")
}

func TestScenario_CL_31_UserinfoClaimDoesNotLeakToIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-31")
}

func TestScenario_CL_32_BothSectionsProjectedIndependently(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CL-32")
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

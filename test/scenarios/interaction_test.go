package scenarios_test

// Catalog: test/scenarios/catalog/interaction.yaml (ITX-NNN)
// Spec:
//   - OIDC Core 1.0 §3.1.2.1, §3.1.2.6, §3.2.1, §15
//   - OIDC RP-Initiated Logout 1.0
//   - RFC 6749 §4.1, §4.1.2.1
//   - RFC 9700 (BCP 240) §4

import "testing"

func TestScenario_ITX_001_MissingInteractionCookieReturnsSessionNotFound(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-001")
}

func TestScenario_ITX_002_MissingInteractionRecordReturnsSessionNotFound(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-002")
}

func TestScenario_ITX_010_UnauthenticatedAuthRedirectsToLoginInteraction(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-010")
}

func TestScenario_ITX_011_InteractionPageEscapesEchoedParams(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-011")
}

func TestScenario_ITX_012_LoginPostResumesAndRedirectsToClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-012")
}

func TestScenario_ITX_013_EmptyLoginAccountIDSurfacesServerError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-013")
}

func TestScenario_ITX_020_ConsentPromptRendersConsentForm(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-020")
}

func TestScenario_ITX_021_ConsentSessionDestroyedBeforePost(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-021")
}

func TestScenario_ITX_022_ConsentPrincipalChangedBeforePost(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-022")
}

func TestScenario_ITX_023_ConsentPostResumesAndRedirectsToClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-023")
}

func TestScenario_ITX_024_ConsentSessionDestroyedBeforeResume(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-024")
}

func TestScenario_ITX_025_ConsentNewLoginBeforeResume(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-025")
}

func TestScenario_ITX_030_UnknownPromptNameReturns501(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-030")
}

func TestScenario_ITX_040_AbortReturnsAccessDeniedToClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-040")
}

func TestScenario_ITX_050_ResumeWithoutCookieRendersExpired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-050")
}

func TestScenario_ITX_051_ResumeWithoutInteractionRecordRenders400(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-051")
}

func TestScenario_ITX_052_LoginWithoutRememberYieldsPermanentCookie(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-052")
}

func TestScenario_ITX_053_LoginRememberTrueYieldsPermanentCookie(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-053")
}

func TestScenario_ITX_054_LoginRememberFalseYieldsTransientCookie(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-054")
}

func TestScenario_ITX_055_AccountSwitchRendersLogoutForm(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-055")
}

func TestScenario_ITX_060_CustomFailWithPromptNoneRedirects(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-060")
}

func TestScenario_ITX_061_CustomInteractiveFailLoopsToNextPrompt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-061")
}

func TestScenario_ITX_062_ResumeAccessDeniedWithoutDescription(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-062")
}

func TestScenario_ITX_063_ResumeAccessDeniedWithDescription(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-063")
}

func TestScenario_ITX_064_ResumeWithCustomErrorCode(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-064")
}

func TestScenario_ITX_065_ErrorRedirectsRoundTripState(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-065")
}

func TestScenario_ITX_070_RequestedCustomPromptRedirectsToInteraction(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-070")
}

func TestScenario_ITX_071_UnrequestablePromptInjectedByOP(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-071")
}

func TestScenario_ITX_072_UnsatisfiedUnrequestablePromptLoops(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ITX-072")
}

package scenarios_test

// Catalog: test/scenarios/catalog/interaction.yaml (ITX-NNN)
// Spec:
//   - OIDC Core 1.0 §3.1.2.1, §3.1.2.6, §3.2.1, §15
//   - OIDC RP-Initiated Logout 1.0
//   - RFC 6749 §4.1, §4.1.2.1
//   - RFC 9700 (BCP 240) §4

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

func TestScenario_ITX_001_MissingInteractionCookieReturnsSessionNotFound(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-001 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_002_MissingInteractionRecordReturnsSessionNotFound(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-002 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_010_UnauthenticatedAuthRedirectsToLoginInteraction(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-010 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_011_InteractionPageEscapesEchoedParams(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-011 (see catalog out_of_scope_reason)")
}

// TestScenario_ITX_012_LoginPostResumesAndRedirectsToClient pins the
// interaction-completion observable: after the SPA submits the
// authentication factor (the v1.0 wire equivalent of panva's
// `prompt=login` POST), the next response MUST be the 302/303 redirect
// to the client's redirect_uri carrying a fresh authorization code and
// the original state. v1.0 collapses panva's two-hop /interaction →
// /auth/{uid} → callback into a single redirect; the wire-observable
// end state is identical.
func TestScenario_ITX_012_LoginPostResumesAndRedirectsToClient(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "rp-itx-012"
		callback    = "https://rp.testkit.invalid/callback"
		clientState = "itx-012-state"
	)
	tk := testkit.NewProvider(t)
	hash, err := op.HashClientSecret("rp-itx-012-secret")
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	flow := scenariokit.RunCodeFlow(t, tk, "alice-itx-012", scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		State:       clientState,
	})
	if flow.Code == "" {
		t.Fatalf("interaction completion did not produce code: %+v", flow)
	}
	if flow.State != clientState {
		t.Errorf("state=%q want %q", flow.State, clientState)
	}
	if flow.Location == nil || flow.Location.Path != "/callback" {
		t.Errorf("redirect target=%v want host/callback", flow.Location)
	}
}

func TestScenario_ITX_013_EmptyLoginAccountIDSurfacesServerError(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-013 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_020_ConsentPromptRendersConsentForm(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-020 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_021_ConsentSessionDestroyedBeforePost(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-021 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_022_ConsentPrincipalChangedBeforePost(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-022 (see catalog out_of_scope_reason)")
}

// TestScenario_ITX_023_ConsentPostResumesAndRedirectsToClient pins the
// post-consent completion observable. RunCodeFlow drives the consent
// prompt to approval (the v1.0 wire-equivalent of panva's "successful
// consent POST") and the helper asserts the end state is a redirect
// back to the RP carrying the authorization code and state. v1.0
// collapses panva's POST → /auth → callback into a single 302; the
// observable end state is identical.
func TestScenario_ITX_023_ConsentPostResumesAndRedirectsToClient(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "rp-itx-023"
		callback    = "https://rp.testkit.invalid/callback"
		clientState = "itx-023-state"
	)
	tk := testkit.NewProvider(t)
	hash, err := op.HashClientSecret("rp-itx-023-secret")
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	flow := scenariokit.RunCodeFlow(t, tk, "alice-itx-023", scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid profile email",
		State:       clientState,
	})
	if flow.Code == "" {
		t.Fatalf("post-consent completion did not produce code: %+v", flow)
	}
	if flow.State != clientState {
		t.Errorf("state=%q want %q", flow.State, clientState)
	}
}

func TestScenario_ITX_024_ConsentSessionDestroyedBeforeResume(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-024 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_025_ConsentNewLoginBeforeResume(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-025 (see catalog out_of_scope_reason)")
}

// TestScenario_ITX_030_UnknownPromptNameReturns501 is OOS — see catalog out_of_scope_reason.
func TestScenario_ITX_030_UnknownPromptNameReturns501(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-030 (see catalog out_of_scope_reason)")
}

// TestScenario_ITX_040_AbortReturnsAccessDeniedToClient pins the
// user-cancellation observable required by RFC 6749 §4.1.2.1: when the
// end-user aborts the in-progress interaction, the OP MUST redirect to
// the RP carrying error=access_denied and the original state. v1.0
// exposes the cancel surface as DELETE on /oidc/interaction/{uid}
// rather than panva's GET on {interaction_url}/abort; the wire verb /
// route differ but the §4.1.2.1-mandated end state is identical.
func TestScenario_ITX_040_AbortReturnsAccessDeniedToClient(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "rp-itx-040"
		callback    = "https://rp.testkit.invalid/callback"
		clientState = "itx-040-state"
	)
	tk := testkit.NewProvider(t)
	hash, err := op.HashClientSecret("rp-itx-040-secret")
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := tk.HTTPClient(jar)

	pkce := scenariokit.NewPKCEPair("")
	authorizeURL := tk.Server.URL + "/oidc/auth?" + (scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		State:       clientState,
		PKCE:        pkce,
	}).Values().Encode()

	authReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authorizeURL, http.NoBody)
	if err != nil {
		t.Fatalf("build /authorize: %v", err)
	}
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	_ = authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("/authorize status=%d want 302", authResp.StatusCode)
	}
	loc, err := authResp.Location()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("/authorize redirected to %q, want /oidc/interaction/...", loc.Path)
	}
	interactionURL := tk.Server.URL + loc.Path

	delReq, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, interactionURL, http.NoBody)
	if err != nil {
		t.Fatalf("build DELETE: %v", err)
	}
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE /interaction: %v", err)
	}
	defer func() { _ = delResp.Body.Close() }()
	if delResp.StatusCode != http.StatusFound {
		t.Fatalf("DELETE /interaction status=%d want 302", delResp.StatusCode)
	}
	cancelLoc, err := delResp.Location()
	if err != nil {
		t.Fatalf("DELETE Location: %v", err)
	}
	want, _ := url.Parse(callback)
	if cancelLoc.Scheme != want.Scheme || cancelLoc.Host != want.Host || cancelLoc.Path != want.Path {
		t.Fatalf("cancel redirect=%s want %s", cancelLoc.String(), callback)
	}
	q := cancelLoc.Query()
	if q.Get("error") != "access_denied" {
		t.Errorf("error=%q want access_denied", q.Get("error"))
	}
	if got := q.Get("state"); got != clientState {
		t.Errorf("state=%q want %q", got, clientState)
	}
	if q.Get("error_description") == "" {
		t.Error("error_description missing on access_denied redirect")
	}
}

func TestScenario_ITX_050_ResumeWithoutCookieRendersExpired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-050 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_051_ResumeWithoutInteractionRecordRenders400(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-051 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_052_LoginWithoutRememberYieldsPermanentCookie(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-052 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_053_LoginRememberTrueYieldsPermanentCookie(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-053 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_054_LoginRememberFalseYieldsTransientCookie(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-054 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_055_AccountSwitchRendersLogoutForm(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-055 (see catalog out_of_scope_reason)")
}

// TestScenario_ITX_060_CustomFailWithPromptNoneRedirects is OOS — see catalog out_of_scope_reason.
func TestScenario_ITX_060_CustomFailWithPromptNoneRedirects(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-060 (see catalog out_of_scope_reason)")
}

// TestScenario_ITX_061_CustomInteractiveFailLoopsToNextPrompt is OOS — see catalog out_of_scope_reason.
func TestScenario_ITX_061_CustomInteractiveFailLoopsToNextPrompt(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-061 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_062_ResumeAccessDeniedWithoutDescription(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-062 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_063_ResumeAccessDeniedWithDescription(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-063 (see catalog out_of_scope_reason)")
}

// TestScenario_ITX_064_ResumeWithCustomErrorCode is OOS — see catalog out_of_scope_reason.
func TestScenario_ITX_064_ResumeWithCustomErrorCode(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-064 (see catalog out_of_scope_reason)")
}

// TestScenario_ITX_065_ErrorRedirectsRoundTripState pins the
// state-on-error round-trip required by OIDC Core 1.0 §3.1.2.6 and
// RFC 6749 §4.1.2.1: every error redirect MUST echo the original
// `state` verbatim. The test drives the user-cancel path (DELETE on
// /oidc/interaction/{uid}) because it produces an error redirect
// without depending on RP misuse, and asserts the state survives the
// hop unchanged.
func TestScenario_ITX_065_ErrorRedirectsRoundTripState(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "rp-itx-065"
		callback    = "https://rp.testkit.invalid/callback"
		clientState = "ITX-065;weird=value/with#special?chars"
	)
	tk := testkit.NewProvider(t)
	hash, err := op.HashClientSecret("rp-itx-065-secret")
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := tk.HTTPClient(jar)

	pkce := scenariokit.NewPKCEPair("")
	authorizeURL := tk.Server.URL + "/oidc/auth?" + (scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		State:       clientState,
		PKCE:        pkce,
	}).Values().Encode()

	authReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authorizeURL, http.NoBody)
	if err != nil {
		t.Fatalf("build /authorize: %v", err)
	}
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	_ = authResp.Body.Close()
	loc, err := authResp.Location()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	interactionURL := tk.Server.URL + loc.Path

	delReq, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, interactionURL, http.NoBody)
	if err != nil {
		t.Fatalf("build DELETE: %v", err)
	}
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer func() { _ = delResp.Body.Close() }()
	cancelLoc, err := delResp.Location()
	if err != nil {
		t.Fatalf("DELETE Location: %v", err)
	}
	if got := cancelLoc.Query().Get("state"); got != clientState {
		t.Errorf("state on error redirect=%q want %q", got, clientState)
	}
	if cancelLoc.Query().Get("error") == "" {
		t.Error("error code missing — test relies on the error-redirect path")
	}
}

// TestScenario_ITX_070_RequestedCustomPromptRedirectsToInteraction is OOS — see catalog out_of_scope_reason.
func TestScenario_ITX_070_RequestedCustomPromptRedirectsToInteraction(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-070 (see catalog out_of_scope_reason)")
}

// TestScenario_ITX_071_UnrequestablePromptInjectedByOP is OOS — see catalog out_of_scope_reason.
func TestScenario_ITX_071_UnrequestablePromptInjectedByOP(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-071 (see catalog out_of_scope_reason)")
}

func TestScenario_ITX_072_UnsatisfiedUnrequestablePromptLoops(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ITX-072 (see catalog out_of_scope_reason)")
}

package authorizeendpoint_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_PromptConsent_RunsConsentDespiteCoveringGrant pins the
// re-consent contract: prompt=consent MUST reach the consent screen even
// when the cached grant already covers every requested scope. The
// dispatcher routes such a request to an interaction, so the only way it
// can still skip the ceremony is by pre-marking the built-in consent
// interaction as already run — which would hand the RP an authorization
// code for an authorization the user was never asked to re-confirm.
func TestEndToEnd_PromptConsent_RunsConsentDespiteCoveringGrant(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)}
	f := newE2EFlow(t, "rp-reconsent", testkit.WithClock(clock))
	const subject = "user-reconsent"

	// Pass 1 establishes the session and a grant covering the whole
	// requested scope set.
	loc1 := f.authorize(t, f.values())
	if got := loc1.Query().Get("code"); got != "" {
		t.Fatalf("first pass minted a code without an interaction: %s", loc1.String())
	}
	if code := f.completeLogin(t, loc1, subject); code == "" {
		t.Fatal("first pass produced no authorization code")
	}
	grant, err := f.tk.Store.Grants().FindBySubjectClient(context.Background(), subject, f.rp.ID)
	if err != nil {
		t.Fatalf("FindBySubjectClient: %v", err)
	}
	for _, want := range []string{"openid", "profile", "email"} {
		if !containsScope(grant.Scope, want) {
			t.Fatalf("grant scope=%v does not cover %q; the test premise no longer holds", grant.Scope, want)
		}
	}

	// Pass 2 asks for re-consent against that covering grant.
	v := f.values()
	v.Set("prompt", "consent")
	loc2 := f.authorize(t, v)
	if got := loc2.Query().Get("code"); got != "" {
		t.Fatalf("prompt=consent silently minted a code: %s", loc2.String())
	}
	if !strings.HasPrefix(loc2.Path, "/oidc/interaction") {
		t.Fatalf("prompt=consent redirect=%s want an interaction", loc2.String())
	}

	interactionURL := f.interactionURL(loc2)
	postResp, _ := f.submitSubject(t, interactionURL, subject)
	defer postResp.Body.Close()
	isConsent, envelope, err := testkit.IsConsentPrompt(postResp)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	if !isConsent {
		t.Fatalf("prompt=consent never reached the consent screen: status=%d envelope=%v",
			postResp.StatusCode, envelope)
	}

	// Approving finishes the flow, confirming the extra ceremony is a
	// real step rather than a dead end.
	stateRef, _ := envelope["state_ref"].(string)
	if stateRef == "" {
		t.Fatalf("consent prompt missing state_ref: %v", envelope)
	}
	rotated := findCookie(postResp.Cookies(), cookie.CSRFProfile.Name)
	if rotated == nil {
		t.Fatal("consent prompt did not rotate the csrf cookie")
	}
	finalResp := testkit.PostConsentApproval(t, f.client, interactionURL, f.tk.Issuer,
		rotated.Value, stateRef, approvedScopesFromPrompt(envelope))
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		t.Fatalf("consent approval status=%d want 302", finalResp.StatusCode)
	}
	rpRedirect, err := finalResp.Location()
	if err != nil {
		t.Fatalf("Location after consent: %v", err)
	}
	if rpRedirect.Query().Get("code") == "" {
		t.Fatalf("consent approval produced no code: %s", rpRedirect.String())
	}
}

// TestEndToEnd_NewAuthorizationDetails_RunsConsentDespiteCoveringGrant is
// the RFC 9396 half of the same contract. A returning user whose grant
// covers the requested scope but NOT the newly presented
// authorization_details element must see the consent screen: the element
// carries the consent-bearing terms (a payment amount here), so granting
// it silently would authorize a transaction the user never saw.
func TestEndToEnd_NewAuthorizationDetails_RunsConsentDespiteCoveringGrant(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)}
	f := newE2EFlow(t, "rp-rar-reconsent",
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithAuthorizationDetailTypes(op.AuthorizationDetailType{
			Type:     "payment_initiation",
			Validate: func(context.Context, map[string]any, *store.Client) error { return nil },
		})),
	)
	const subject = "user-rar-reconsent"

	first := f.values()
	first.Set("authorization_details", `[{"type":"payment_initiation","amount":"100"}]`)
	loc1 := f.authorize(t, first)
	if code := f.completeLogin(t, loc1, subject); code == "" {
		t.Fatal("first pass produced no authorization code")
	}
	grant, err := f.tk.Store.Grants().FindBySubjectClient(context.Background(), subject, f.rp.ID)
	if err != nil {
		t.Fatalf("FindBySubjectClient: %v", err)
	}
	if len(grant.AuthorizationDetails) == 0 {
		t.Fatalf("grant recorded no authorization_details: %+v", grant)
	}

	// The second pass keeps the scope but changes the payment amount, so
	// the grant no longer covers what is being asked for.
	second := f.values()
	second.Set("authorization_details", `[{"type":"payment_initiation","amount":"999"}]`)
	loc2 := f.authorize(t, second)
	if got := loc2.Query().Get("code"); got != "" {
		t.Fatalf("a new authorization_details element silently minted a code: %s", loc2.String())
	}
	if !strings.HasPrefix(loc2.Path, "/oidc/interaction") {
		t.Fatalf("redirect=%s want an interaction", loc2.String())
	}

	postResp, _ := f.submitSubject(t, f.interactionURL(loc2), subject)
	defer postResp.Body.Close()
	isConsent, envelope, err := testkit.IsConsentPrompt(postResp)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	if !isConsent {
		t.Fatalf("a new authorization_details element never reached the consent screen: status=%d envelope=%v",
			postResp.StatusCode, envelope)
	}
}

// TestEndToEnd_PromptLogin_RunsAuthnDespiteActiveSession is the login
// counterpart: prompt=login must re-run the factor chain even when the
// session is fresh and the grant covers the request. The interaction
// state is always built at the pre-authentication phase with no factor
// pre-marked, and this test pins that a cached grant cannot short-
// circuit it.
func TestEndToEnd_PromptLogin_RunsAuthnDespiteActiveSession(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)}
	f := newE2EFlow(t, "rp-relogin", testkit.WithClock(clock))
	const subject = "user-relogin"

	if code := f.completeLogin(t, f.authorize(t, f.values()), subject); code == "" {
		t.Fatal("first pass produced no authorization code")
	}

	v := f.values()
	v.Set("prompt", "login")
	loc := f.authorize(t, v)
	if got := loc.Query().Get("code"); got != "" {
		t.Fatalf("prompt=login silently minted a code: %s", loc.String())
	}

	stepResp, err := newGet(f.interactionURL(loc)).Do(f.client)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		t.Fatalf("interaction GET status=%d want 200", stepResp.StatusCode)
	}
	step := decodeMap(t, stepResp)
	if got, _ := step["type"].(string); got != testkit.SubjectPromptType {
		t.Fatalf("prompt=login first step type=%q want %q (the factor chain was skipped)",
			got, testkit.SubjectPromptType)
	}
}

// containsScope reports whether the scope slice holds want.
func containsScope(scope []string, want string) bool {
	for _, s := range scope {
		if s == want {
			return true
		}
	}
	return false
}

package authorizeendpoint_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_ReconsentWithdrawal_RemovesScopeFromGrant pins the
// withdrawal half of the consent contract. Re-consent that unticks a
// scope has to leave the grant, not just the code: a grant that keeps
// the declined name reports it as already consented on the next
// request, so the very next prompt-less authorization re-grants it
// without a ceremony and the user's refusal is undone silently.
//
// The script is the one a user performs: approve everything, come back
// through prompt=consent and drop one scope, then let the RP ask for
// the full set again.
func TestEndToEnd_ReconsentWithdrawal_RemovesScopeFromGrant(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)}
	f := newE2EFlow(t, "rp-withdraw", testkit.WithClock(clock))
	const subject = "user-withdraw"
	ctx := context.Background()

	// Pass 1: approve openid + profile + email.
	if code := f.completeLogin(t, f.authorize(t, f.values()), subject); code == "" {
		t.Fatal("first pass produced no authorization code")
	}
	grant, err := f.tk.Store.Grants().FindBySubjectClient(ctx, subject, f.rp.ID)
	if err != nil {
		t.Fatalf("FindBySubjectClient after pass 1: %v", err)
	}
	if !containsScope(grant.Scope, "email") {
		t.Fatalf("grant scope=%v lacks email; the test premise no longer holds", grant.Scope)
	}

	// Pass 2: prompt=consent, and this time email is unticked.
	v := f.values()
	v.Set("prompt", "consent")
	loc2 := f.authorize(t, v)
	interactionURL := f.interactionURL(loc2)
	postResp, _ := f.submitSubject(t, interactionURL, subject)
	defer postResp.Body.Close()
	isConsent, envelope, err := testkit.IsConsentPrompt(postResp)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	if !isConsent {
		t.Fatalf("prompt=consent did not reach the consent screen: status=%d envelope=%v",
			postResp.StatusCode, envelope)
	}
	stateRef, _ := envelope["state_ref"].(string)
	rotated := findCookie(postResp.Cookies(), cookie.CSRFProfile.Name)
	if stateRef == "" || rotated == nil {
		t.Fatalf("consent prompt missing state_ref / rotated csrf cookie: %v", envelope)
	}
	finalResp := testkit.PostConsentApproval(t, f.client, interactionURL, f.tk.Issuer,
		rotated.Value, stateRef, "openid profile")
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		t.Fatalf("partial consent status=%d want 302", finalResp.StatusCode)
	}
	rpRedirect, err := finalResp.Location()
	if err != nil {
		t.Fatalf("Location after partial consent: %v", err)
	}
	narrowCode := rpRedirect.Query().Get("code")
	if narrowCode == "" {
		t.Fatalf("partial consent produced no code: %s", rpRedirect)
	}

	// The code carries only what was approved.
	stored, err := f.tk.Store.AuthorizationCodes().Find(ctx, narrowCode)
	if err != nil {
		t.Fatalf("find authorization code: %v", err)
	}
	if containsScope(stored.Scope, "email") {
		t.Errorf("authorization code scope=%v carries the declined scope", stored.Scope)
	}

	// And so does the grant: the declined scope is gone, the approved
	// ones survive.
	grant, err = f.tk.Store.Grants().FindBySubjectClient(ctx, subject, f.rp.ID)
	if err != nil {
		t.Fatalf("FindBySubjectClient after withdrawal: %v", err)
	}
	if containsScope(grant.Scope, "email") {
		t.Errorf("grant scope=%v still holds the declined scope; the withdrawal did not stick", grant.Scope)
	}
	for _, want := range []string{"openid", "profile"} {
		if !containsScope(grant.Scope, want) {
			t.Errorf("grant scope=%v dropped the approved scope %q", grant.Scope, want)
		}
	}

	// Pass 3: the RP asks for the full set again with no prompt. The
	// withdrawn scope is no longer covered, so a ceremony is owed and
	// no code may be minted silently.
	loc3 := f.authorize(t, f.values())
	if code := loc3.Query().Get("code"); code != "" {
		t.Fatalf("the declined scope was silently re-granted: %s", loc3)
	}
	if !strings.HasPrefix(loc3.Path, "/oidc/interaction") {
		t.Fatalf("redirect=%s want an interaction (consent is owed for the withdrawn scope)", loc3)
	}
}

// TestEndToEnd_EmptyConsentApproval_IsNotTotalApproval pins the other
// end of the same rule: approving nothing is a decision, not a missing
// ceremony. Treating an empty approval as "no consent ran" makes the
// fallback — the full requested scope set — apply, so a ceremony in
// which the user ticked no box would mint a code for everything.
func TestEndToEnd_EmptyConsentApproval_IsNotTotalApproval(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)}
	f := newE2EFlow(t, "rp-empty-consent", testkit.WithClock(clock))
	const subject = "user-empty-consent"
	ctx := context.Background()

	loc := f.authorize(t, f.values())
	interactionURL := f.interactionURL(loc)
	postResp, _ := f.submitSubject(t, interactionURL, subject)
	defer postResp.Body.Close()
	isConsent, envelope, err := testkit.IsConsentPrompt(postResp)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	if !isConsent {
		t.Fatalf("first login did not reach the consent screen: status=%d envelope=%v",
			postResp.StatusCode, envelope)
	}
	stateRef, _ := envelope["state_ref"].(string)
	rotated := findCookie(postResp.Cookies(), cookie.CSRFProfile.Name)
	if stateRef == "" || rotated == nil {
		t.Fatalf("consent prompt missing state_ref / rotated csrf cookie: %v", envelope)
	}
	finalResp := testkit.PostConsentApproval(t, f.client, interactionURL, f.tk.Issuer,
		rotated.Value, stateRef, "")
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		t.Fatalf("empty consent status=%d want 302", finalResp.StatusCode)
	}
	rpRedirect, err := finalResp.Location()
	if err != nil {
		t.Fatalf("Location after empty consent: %v", err)
	}
	code := rpRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("empty consent produced no code: %s", rpRedirect)
	}
	stored, err := f.tk.Store.AuthorizationCodes().Find(ctx, code)
	if err != nil {
		t.Fatalf("find authorization code: %v", err)
	}
	if len(stored.Scope) != 0 {
		t.Errorf("authorization code scope=%v; an approval of nothing must not grant the requested set", stored.Scope)
	}
	grant, err := f.tk.Store.Grants().FindBySubjectClient(ctx, subject, f.rp.ID)
	if err != nil {
		t.Fatalf("FindBySubjectClient: %v", err)
	}
	if len(grant.Scope) != 0 {
		t.Errorf("grant scope=%v; an approval of nothing must not grant the requested set", grant.Scope)
	}
}

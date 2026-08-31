package authorizeendpoint_test

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_AuthorizationDetails_RideTheRequestNotTheConsentAnswer pins
// the boundary of what the consent ceremony decides. The scope set comes
// from the user's answer; the RFC 9396 authorization_details elements come
// from the authorization request and are persisted verbatim, because the
// built-in consent step has no element-level row for the user to answer
// with.
//
// The script drives the sharpest case: a ceremony in which the user
// approves no scope at all. The grant is left with an empty scope set and
// the requested element still attached. This is what the coverage
// predicate's doc describes, and a deployment that needs the element's
// terms shown and gated has to render them in its own interaction.Driver.
func TestEndToEnd_AuthorizationDetails_RideTheRequestNotTheConsentAnswer(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)}
	f := newE2EFlow(t, "rp-rar-consent-boundary",
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithAuthorizationDetailTypes(op.AuthorizationDetailType{
			Type:     "payment_initiation",
			Validate: func(context.Context, map[string]any, *store.Client) error { return nil },
		})),
	)
	const subject = "user-rar-consent-boundary"
	ctx := context.Background()

	v := f.values()
	v.Set("authorization_details", `[{"type":"payment_initiation","amount":"100"}]`)
	loc := f.authorize(t, v)

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

	// The prompt is scope-only: the payload carries the client
	// projection and the scope rows and nothing else, so a driver has
	// no element to render and the submission has no field to answer
	// with. A driver cannot gate what it is never given.
	data, _ := envelope["data"].(map[string]any)
	if data == nil {
		t.Fatalf("consent prompt carries no data: %v", envelope)
	}
	got := slices.Sorted(maps.Keys(data))
	if want := []string{"Client", "Scopes"}; !slices.Equal(got, want) {
		t.Errorf("consent prompt data keys=%v want %v; the payload changed and the coverage docs must follow", got, want)
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
	if rpRedirect.Query().Get("code") == "" {
		t.Fatalf("empty consent produced no code: %s", rpRedirect)
	}

	grant, err := f.tk.Store.Grants().FindBySubjectClient(ctx, subject, f.rp.ID)
	if err != nil {
		t.Fatalf("FindBySubjectClient: %v", err)
	}
	if len(grant.Scope) != 0 {
		t.Errorf("grant scope=%v; the ceremony approved nothing", grant.Scope)
	}
	if len(grant.AuthorizationDetails) != 1 {
		t.Fatalf("grant authorization_details=%v want the one requested element", grant.AuthorizationDetails)
	}
	if got := grant.AuthorizationDetails[0]["amount"]; got != "100" {
		t.Errorf("grant element amount=%v want %q (persisted verbatim from the request)", got, "100")
	}
}

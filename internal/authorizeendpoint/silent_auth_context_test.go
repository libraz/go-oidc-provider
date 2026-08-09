package authorizeendpoint_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_SilentMint_IDTokenCarriesSessionAuthContext pins the
// authentication context a silently minted code reports. The dispatcher
// validates max_age against the SESSION's auth_time and acr_values
// against the SESSION's acr, so the id_token it leads to must describe
// that same authentication. Reusing whatever the grant happens to carry
// contradicts the check that just passed: an RP enforcing max_age would
// reject a days-old auth_time and loop the user through login, and a
// strong acr recorded by an earlier ceremony would be reported for a
// weaker current session.
//
// The test forces the divergence by rewriting the grant's context after
// the interactive pass, then serves a silent pass against it.
func TestEndToEnd_SilentMint_IDTokenCarriesSessionAuthContext(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	f := newE2EFlow(t, "rp-silent-authctx", testkit.WithClock(fakeClock{now: now}))
	const subject = "user-silent-authctx"
	ctx := context.Background()

	// Pass 1: interactive login binds the session at acr "1", auth_time now.
	first := f.values()
	first.Set("acr_values", "1")
	claims1 := f.exchange(t, f.completeLogin(t, f.authorize(t, first), subject))
	if got, _ := claims1["acr"].(string); got != "1" {
		t.Fatalf("first pass id_token acr=%q want 1", got)
	}
	if got := idTokenAuthTime(t, claims1); got != now.Unix() {
		t.Fatalf("first pass id_token auth_time=%d want %d", got, now.Unix())
	}

	// Rewrite the grant so it looks like it was recorded by an older and
	// stronger ceremony than the session now serving the request.
	grant, err := f.tk.Store.Grants().FindBySubjectClient(ctx, subject, f.rp.ID)
	if err != nil {
		t.Fatalf("FindBySubjectClient: %v", err)
	}
	grant.AuthTime = now.Add(-72 * time.Hour)
	grant.ACR = "urn:test:acr:stale"
	grant.AMR = []string{"stale"}
	if err := f.tk.Store.Grants().Save(ctx, grant); err != nil {
		t.Fatalf("Save stale grant: %v", err)
	}

	// Pass 2: max_age=3600 is satisfied by the session (authenticated at
	// now) but not by the rewritten grant, and the scope is covered, so
	// the request is served silently.
	second := f.values()
	second.Set("acr_values", "1")
	second.Set("max_age", "3600")
	loc := f.authorize(t, second)
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("second pass expected a silent code redirect, got: %s", loc.String())
	}

	claims2 := f.exchange(t, code)
	if got := idTokenAuthTime(t, claims2); got != now.Unix() {
		t.Errorf("silent mint id_token auth_time=%d want %d (the session's authentication, not the grant's)",
			got, now.Unix())
	}
	if got, _ := claims2["acr"].(string); got != "1" {
		t.Errorf("silent mint id_token acr=%q want 1 (the session's context, not the grant's)", got)
	}
	if raw, ok := claims2["amr"]; ok {
		values, _ := raw.([]any)
		for _, v := range values {
			if s, _ := v.(string); s == "stale" {
				t.Errorf("silent mint id_token amr=%v carries the grant's stale value", raw)
			}
		}
	}

	// The persisted grant is re-stamped too, so a refresh-token-derived
	// id_token reports the same context (OIDC Core 1.0 §12).
	reloaded, err := f.tk.Store.Grants().FindBySubjectClient(ctx, subject, f.rp.ID)
	if err != nil {
		t.Fatalf("reload grant: %v", err)
	}
	if !reloaded.AuthTime.Equal(now) {
		t.Errorf("grant AuthTime=%v want %v", reloaded.AuthTime, now)
	}
	if reloaded.ACR != "1" {
		t.Errorf("grant ACR=%q want 1", reloaded.ACR)
	}
	if len(reloaded.AMR) != 0 {
		t.Errorf("grant AMR=%v want empty (the session records none)", reloaded.AMR)
	}
}

// idTokenAuthTime reads the auth_time claim as Unix seconds, failing the
// test when it is absent or not numeric.
func idTokenAuthTime(t *testing.T, claims map[string]any) int64 {
	t.Helper()
	raw, ok := claims["auth_time"]
	if !ok {
		t.Fatalf("id_token carries no auth_time claim: %v", claims)
	}
	seconds, ok := raw.(float64)
	if !ok {
		t.Fatalf("id_token auth_time=%v is not numeric", raw)
	}
	return int64(seconds)
}

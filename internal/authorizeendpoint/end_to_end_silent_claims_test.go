package authorizeendpoint_test

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// silentClaimsSubject is the account whose grant both passes of the test
// below reuse.
const silentClaimsSubject = "user-silent-claims"

// TestEndToEnd_SilentMintHonoursTheRequestsClaimsParameter drives the
// exit that serves a returning subject without any ceremony, and adds an
// OIDC Core 1.0 §5.5 claims parameter on the second pass.
//
// The claims payload is carried on the grant, which is where /token and
// /userinfo read the projection from. An exit that reuses the grant
// without re-recording the payload answers the new request with the old
// projection and says nothing about it: the RP sees a code, a successful
// exchange, and none of the claims it asked for.
//
// The id_token is the discriminating surface. Scope-derived claims are
// released at /userinfo regardless of the parameter (Core §5.4), so a
// claim appearing there proves nothing; a claim appearing in the
// id_token can only have come from the §5.5 projection.
func TestEndToEnd_SilentMintHonoursTheRequestsClaimsParameter(t *testing.T) {
	t.Parallel()

	f := newE2EFlow(t, "rp-silent-claims")
	f.tk.Store.PutUser(context.Background(), &store.User{
		Subject: silentClaimsSubject,
		Claims:  map[string]any{"email": "silent@example.com"},
	})

	// Pass 1 records the grant, with no claims parameter in play.
	first := f.exchange(t, f.completeLogin(t, f.authorize(t, f.values()), silentClaimsSubject))
	if v, ok := first["email"]; ok {
		t.Fatalf("pass 1 id_token carries email=%v with no claims parameter", v)
	}

	// Pass 2 is covered by that grant, so prompt=none is served silently
	// — and carries a claims parameter the grant has never seen.
	values := f.values()
	values.Set("prompt", "none")
	values.Set("claims", `{"id_token":{"email":{"essential":true}}}`)
	loc := f.authorize(t, values)
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("prompt=none was not served from the existing grant: %s", loc)
	}

	second := f.exchange(t, code)
	if got := second["email"]; got != "silent@example.com" {
		t.Errorf("id_token email=%v want silent@example.com; the silent exit dropped the claims parameter",
			second["email"])
	}
}

// TestEndToEnd_SilentMintDoesNotEraseAPreviouslyRecordedProjection is
// the complement: a request that names no claims leaves the payload the
// subject already agreed to in place, matching the rule the interactive
// upsert follows.
func TestEndToEnd_SilentMintDoesNotEraseAPreviouslyRecordedProjection(t *testing.T) {
	t.Parallel()

	f := newE2EFlow(t, "rp-silent-claims-keep")
	f.tk.Store.PutUser(context.Background(), &store.User{
		Subject: silentClaimsSubject,
		Claims:  map[string]any{"email": "silent@example.com"},
	})

	first := f.values()
	first.Set("claims", `{"id_token":{"email":{"essential":true}}}`)
	f.completeLogin(t, f.authorize(t, first), silentClaimsSubject)

	values := f.values()
	values.Set("prompt", "none")
	loc := f.authorize(t, values)
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("prompt=none was not served from the existing grant: %s", loc)
	}
	if got := f.exchange(t, code)["email"]; got != "silent@example.com" {
		t.Errorf("id_token email=%v want silent@example.com; an absent claims parameter erased the projection", got)
	}
}

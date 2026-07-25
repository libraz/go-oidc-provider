package authorizeendpoint_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestInteraction_ResolvesOnlyForTheBrowserThatStartedIt pins that an
// in-flight interaction is reachable by exactly one user agent: the one
// the OP handed the cookie to when the flow began.
//
// The interaction identifier travels in the URL, which means it is
// linkable, forwardable, and visible to anyone who can see a browser's
// history or a referrer. Treating it as sufficient to resolve the
// interaction makes it a capability, and a capability an attacker can
// mint on demand: start a flow, take the identifier, get a signed-in
// victim to open it. The victim then authenticates — genuinely, with
// their own credentials — into a flow the attacker set up, and whatever
// the flow concludes with settles on the attacker's side. That is the
// account-linking takeover shape, and it needs no credential theft at
// all, only one click.
//
// The identifier is therefore half of a pair. The other half is the
// cookie, which the OP issued to a specific user agent and which no
// amount of link-sharing transfers.
//
// Tracks: CVE-2025-68158 (Authlib) — in-flight authorization state was
// stored in a shared cache keyed only by the state value, so the
// callback handler resolved it without checking that the browser
// presenting it was the one that started the flow, enabling a one-click
// account-linking takeover.
func TestInteraction_ResolvesOnlyForTheBrowserThatStartedIt(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	// Two independent browsers, each with a flow of its own. Either
	// one may be cast as the attacker; the property is symmetric.
	first := startInteractionFlow(t, h)
	second := startInteractionFlow(t, h)

	if first.uid == second.uid {
		t.Fatal("two independent flows share an interaction identifier; the identifier is not per-flow")
	}
	if first.interactionCk.Value == second.interactionCk.Value {
		t.Fatal("two independent flows share an interaction cookie; the cookie cannot distinguish browsers")
	}

	get := func(t *testing.T, uid string, ck *http.Cookie) int {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.interactionPth+"/"+uid, nil)
		if ck != nil {
			req.AddCookie(ck)
		}
		rr := httptest.NewRecorder()
		h.handler.ServeHTTP(rr, req)
		return rr.Code
	}

	// The controls: each browser reaches its own interaction. Without
	// these the crossed cases below would pass against a handler that
	// resolved nothing at all.
	if code := get(t, first.uid, first.interactionCk); code == http.StatusNotFound {
		t.Fatalf("the browser that started the first flow cannot reach it: status=%d", code)
	}
	if code := get(t, second.uid, second.interactionCk); code == http.StatusNotFound {
		t.Fatalf("the browser that started the second flow cannot reach it: status=%d", code)
	}

	crossed := []struct {
		name string
		uid  string
		ck   *http.Cookie
	}{
		{"the second browser's cookie against the first identifier", first.uid, second.interactionCk},
		{"the first browser's cookie against the second identifier", second.uid, first.interactionCk},
		{"the first identifier with no cookie at all", first.uid, nil},
	}
	for _, tc := range crossed {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if code := get(t, tc.uid, tc.ck); code != http.StatusNotFound {
				t.Fatalf("status=%d want 404; an interaction resolved for a browser that did not start it, "+
					"so the URL identifier alone is a capability", code)
			}
		})
	}
}

// White-box test for the [respondUseDPoPNonce] helper. RFC 9449 §9
// defines the resource-server challenge as a 401 with
// WWW-Authenticate: DPoP error="use_dpop_nonce" plus a fresh
// DPoP-Nonce response header. The cases here lock the wire shape
// without standing up the full /userinfo fixture (the public
// op.WithDPoPNonceSource option that exercises this end-to-end
// lands in a follow-up).
//
//nolint:testpackage // intentional white-box test for unexported helper.
package userinfo

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type staticIssuer string

func (s staticIssuer) IssueNonce() string { return string(s) }

type emptyIssuer struct{}

func (emptyIssuer) IssueNonce() string { return "" }

func TestRespondUseDPoPNonce_EmitsRSChallenge(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	deps := HandlerDeps{DPoPNonces: staticIssuer("fresh-nonce-99")}
	respondUseDPoPNonce(rec, deps)

	if got := rec.Code; got != 401 {
		t.Errorf("status = %d, want 401 (RFC 9449 §9 RS challenge)", got)
	}
	if got := rec.Header().Get("DPoP-Nonce"); got != "fresh-nonce-99" {
		t.Errorf("DPoP-Nonce = %q, want %q", got, "fresh-nonce-99")
	}
	auth := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(auth, "DPoP ") {
		t.Errorf("WWW-Authenticate = %q, want a DPoP-scheme challenge", auth)
	}
	if !strings.Contains(auth, `error="use_dpop_nonce"`) {
		t.Errorf("WWW-Authenticate = %q, expected use_dpop_nonce error code", auth)
	}
}

func TestRespondUseDPoPNonce_NoIssuer_OmitsHeader(t *testing.T) {
	t.Parallel()
	// Misconfiguration path: HandlerDeps.DPoPNonces is nil. The
	// challenge still fires (so a debugger can see the gate
	// triggered) but no DPoP-Nonce header is emitted — there is
	// no value to give the client.
	rec := httptest.NewRecorder()
	respondUseDPoPNonce(rec, HandlerDeps{})

	if got := rec.Code; got != 401 {
		t.Errorf("status = %d, want 401", got)
	}
	if got := rec.Header().Get("DPoP-Nonce"); got != "" {
		t.Errorf("DPoP-Nonce = %q, want empty (no issuer wired)", got)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `error="use_dpop_nonce"`) {
		t.Errorf("WWW-Authenticate = %q, expected use_dpop_nonce error code", got)
	}
}

// rotatingIssuer returns a different nonce on each [IssueNonce] call,
// modelling the production posture where the OP rotates its accepted
// nonce window over time. Tests use it to assert that the challenge
// path emits a FRESH value rather than echoing whatever the client
// just presented.
type rotatingIssuer struct {
	mu       sync.Mutex
	counter  int
	template string
}

func (r *rotatingIssuer) IssueNonce() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counter++
	return fmt.Sprintf("%s-%d", r.template, r.counter)
}

// TestRespondUseDPoPNonce_DoesNotEchoStaleNonce pins the freshness
// invariant on the use_dpop_nonce challenge path: when the OP rejects
// a proof because its nonce is stale, the DPoP-Nonce header in the
// 401 response MUST carry a NEWLY issued value rather than echoing
// the one the client just presented. Echoing the stale nonce would
// be useless (the next retry would fail the same way) and would also
// hand a confused client a perpetual loop.
//
// Tracks:
//   - RFC 9449 §9 "Nonce Mechanism" — the server-generated nonce is
//     a one-time-use freshness token; rotation is the whole point.
//   - upstream JS reference OP commit 1b073c0 ("issue dpop-nonce on
//     proof iat skew failure") and 4d635e2 ("avoid emitting stale
//     dpop-nonce on freshness failure") which fixed exactly the
//     "echo the value the client showed" failure mode in another
//     ecosystem.
//
// Defence in this codebase: [respondUseDPoPNonce] calls
// [HandlerDeps.DPoPNonces.IssueNonce] every time it fires; the value
// the client presented is never plumbed into this helper, so an
// echo regression would require a refactor that broke the boundary.
// The test confirms the boundary is still honoured: every challenge
// receives a fresh value from the issuer, distinct from any other.
func TestRespondUseDPoPNonce_DoesNotEchoStaleNonce(t *testing.T) {
	t.Parallel()

	iss := &rotatingIssuer{template: "server-nonce"}
	deps := HandlerDeps{DPoPNonces: iss}

	// Drive the challenge twice; assert each emission is distinct
	// from every prior emission — the rotation contract.
	seen := make(map[string]struct{})
	for i := range 4 {
		rec := httptest.NewRecorder()
		respondUseDPoPNonce(rec, deps)
		got := rec.Header().Get("DPoP-Nonce")
		if got == "" {
			t.Fatalf("call %d: DPoP-Nonce header empty", i)
		}
		if _, dup := seen[got]; dup {
			t.Fatalf("call %d: DPoP-Nonce=%q already emitted on a prior challenge; rotation contract broken", i, got)
		}
		seen[got] = struct{}{}
		if rec.Code != 401 {
			t.Errorf("call %d: status=%d want 401", i, rec.Code)
		}
		if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="use_dpop_nonce"`) {
			t.Errorf("call %d: WWW-Authenticate missing use_dpop_nonce code", i)
		}
	}
}

func TestRespondUseDPoPNonce_IssuerReturnsEmpty_OmitsHeader(t *testing.T) {
	t.Parallel()
	// Issuer wired but offline. The helper omits the DPoP-Nonce
	// header rather than emitting an empty value (the same posture
	// as the token-endpoint helper); the WWW-Authenticate code
	// still surfaces so the client can reason about the failure.
	rec := httptest.NewRecorder()
	deps := HandlerDeps{DPoPNonces: emptyIssuer{}}
	respondUseDPoPNonce(rec, deps)

	if got := rec.Header().Get("DPoP-Nonce"); got != "" {
		t.Errorf("DPoP-Nonce = %q, want empty (issuer returned empty string)", got)
	}
}

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
	"net/http/httptest"
	"strings"
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

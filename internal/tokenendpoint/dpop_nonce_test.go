// White-box test for the nonce dispatch the token endpoint inherits
// from the shared [dpop.Gate]. RFC 9449 §8 defines a distinct wire
// shape for the use_dpop_nonce challenge — it is not just another
// invalid_request — so the endpoint MUST route the two nonce
// dpop.Err* sentinels off the standard ladder. The cases here lock
// the routing as [dpopGate] wires it, without spinning up the full
// token-endpoint fixture.
//
//nolint:testpackage // intentional white-box test for unexported helpers.
package tokenendpoint

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// staticIssuer satisfies [dpop.NonceIssuer] with a fixed value so
// the test asserts the exact byte sequence that lands in the
// DPoP-Nonce response header.
type staticIssuer string

func (s staticIssuer) IssueNonce() string { return string(s) }

func TestDPoPGateWriteError_NonceMissing_EmitsUseDPoPNonceChallenge(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	deps := Deps{DPoPNonces: staticIssuer("fresh-nonce-42")}
	dpopGate(deps).WriteError(context.Background(), rec, dpop.ErrProofNonceMissing)

	if got := rec.Code; got != 400 {
		t.Errorf("status = %d, want 400 (RFC 9449 §8.2 token-endpoint error envelope)", got)
	}
	if got := rec.Header().Get("DPoP-Nonce"); got != "fresh-nonce-42" {
		t.Errorf("DPoP-Nonce = %q, want %q", got, "fresh-nonce-42")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v (raw=%q)", err, rec.Body.String())
	}
	if got := body["error"]; got != "use_dpop_nonce" {
		t.Errorf(`body.error = %v, want "use_dpop_nonce"`, got)
	}
	if desc, _ := body["error_description"].(string); !strings.Contains(desc, "DPoP-Nonce") {
		t.Errorf("body.error_description = %q, expected mention of the DPoP-Nonce header", desc)
	}
}

func TestDPoPGateWriteError_NonceInvalid_AlsoEmitsChallenge(t *testing.T) {
	t.Parallel()
	// ErrProofNonceInvalid (stale value) shares the wire response
	// with ErrProofNonceMissing per RFC 9449 §8 — the client
	// retries with the fresh nonce regardless of which sub-cause
	// fired. Distinct sentinel discrimination is for audit logs.
	rec := httptest.NewRecorder()
	deps := Deps{DPoPNonces: staticIssuer("rotated")}
	dpopGate(deps).WriteError(context.Background(), rec, dpop.ErrProofNonceInvalid)

	if got := rec.Code; got != 400 {
		t.Errorf("status = %d, want 400", got)
	}
	if got := rec.Header().Get("DPoP-Nonce"); got != "rotated" {
		t.Errorf("DPoP-Nonce = %q, want %q", got, "rotated")
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if got := body["error"]; got != "use_dpop_nonce" {
		t.Errorf(`body.error = %v, want "use_dpop_nonce"`, got)
	}
}

func TestDPoPGateWriteError_NoIssuer_OmitsHeaderButKeepsErrorCode(t *testing.T) {
	t.Parallel()
	// Misconfiguration path: the verifier was wired with a
	// NonceVerifier (so the proof is rejected for missing nonce)
	// but no NonceIssuer was wired on the endpoint. The response
	// still carries error="use_dpop_nonce" so a debugger can see
	// the gate fired; the missing DPoP-Nonce header truthfully
	// signals "the server has no nonce to give you".
	rec := httptest.NewRecorder()
	dpopGate(Deps{}).WriteError(context.Background(), rec, dpop.ErrProofNonceMissing)

	if got := rec.Code; got != 400 {
		t.Errorf("status = %d, want 400", got)
	}
	if got := rec.Header().Get("DPoP-Nonce"); got != "" {
		t.Errorf("DPoP-Nonce = %q, want empty (no issuer wired)", got)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if got := body["error"]; got != "use_dpop_nonce" {
		t.Errorf(`body.error = %v, want "use_dpop_nonce"`, got)
	}
}

// emptyIssuer is the third NonceIssuer state: present but offline.
// The helper omits the DPoP-Nonce header rather than emitting an
// empty value so the wire shape is unambiguous (RFC 7230 §3.2.4
// permits empty header values, but a value-less DPoP-Nonce on the
// challenge is a worse signal than no header at all).
type emptyIssuer struct{}

func (emptyIssuer) IssueNonce() string { return "" }

func TestDPoPGateWriteError_IssuerReturnsEmpty_OmitsHeader(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	deps := Deps{DPoPNonces: emptyIssuer{}}
	dpopGate(deps).WriteError(context.Background(), rec, dpop.ErrProofNonceMissing)

	if got := rec.Header().Get("DPoP-Nonce"); got != "" {
		t.Errorf("DPoP-Nonce = %q, want empty (issuer returned empty string)", got)
	}
}

func TestDPoPGateWriteError_NonNonceErrorBypassesNonceBranch(t *testing.T) {
	t.Parallel()
	// A non-nonce sentinel must NOT trigger the use_dpop_nonce
	// challenge — even when an issuer is wired. Otherwise a
	// signature failure would leak a fresh nonce to an attacker
	// probing the endpoint.
	rec := httptest.NewRecorder()
	deps := Deps{DPoPNonces: staticIssuer("should-not-leak")}
	dpopGate(deps).WriteError(context.Background(), rec, dpop.ErrProofSignature)

	if got := rec.Header().Get("DPoP-Nonce"); got != "" {
		t.Errorf("DPoP-Nonce = %q, want empty (signature errors must not leak a nonce)", got)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if got := body["error"]; got != errInvalidRequest {
		t.Errorf("body.error = %v, want %q", got, errInvalidRequest)
	}
}

// White-box tests for the sender-constraint enforcement helper. The
// helper is package-private because it composes with the rest of the
// grant orchestration; tests live in-package so they can drive it
// directly without standing up a full HTTP fixture.
//
//nolint:testpackage // intentional white-box test for unexported helpers.
package tokenendpoint

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// TestEnforceSenderConstraint_DisabledNoOp confirms the helper is a
// no-op when the flag is off, regardless of the binding shape.
func TestEnforceSenderConstraint_DisabledNoOp(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if !enforceSenderConstraint(rec, Deps{}, tokenBinding{}) {
		t.Fatal("returned false with feature disabled")
	}
	if rec.Code != 200 { // recorder default
		t.Errorf("status=%d, want untouched (200)", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body written when disabled: %q", rec.Body.String())
	}
}

// TestEnforceSenderConstraint_DPoPBoundOK confirms a DPoP thumbprint
// satisfies the constraint.
func TestEnforceSenderConstraint_DPoPBoundOK(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	deps := Deps{RequireSenderConstrainedTokens: true}
	if !enforceSenderConstraint(rec, deps, tokenBinding{DPoPJKT: "jkt-abc"}) {
		t.Fatal("returned false despite DPoP binding")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("error body written for ok path: %q", rec.Body.String())
	}
}

// TestEnforceSenderConstraint_MTLSBoundOK confirms an mTLS thumbprint
// satisfies the constraint independently of DPoP.
func TestEnforceSenderConstraint_MTLSBoundOK(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	deps := Deps{RequireSenderConstrainedTokens: true}
	if !enforceSenderConstraint(rec, deps, tokenBinding{MTLSThumbprint: "x5t-abc"}) {
		t.Fatal("returned false despite mTLS binding")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("error body written for ok path: %q", rec.Body.String())
	}
}

// TestEnforceSenderConstraint_UnboundFails confirms an unbound binding
// produces a 400 invalid_request with a description that names both
// proof options so RP libraries can fix the request without grovelling
// through the spec.
func TestEnforceSenderConstraint_UnboundFails(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	deps := Deps{RequireSenderConstrainedTokens: true}
	if enforceSenderConstraint(rec, deps, tokenBinding{}) {
		t.Fatal("returned true when binding is empty")
	}
	if rec.Code != 400 {
		t.Errorf("status=%d, want 400", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", got)
	}
	var body httpx.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rec.Body.String())
	}
	if body.Error != errInvalidRequest {
		t.Errorf("error=%q want %q", body.Error, errInvalidRequest)
	}
	if body.ErrorDescription == "" {
		t.Error("error_description is empty; it must name DPoP / client cert as remedies")
	}
}

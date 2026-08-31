package ciba_test

import (
	"errors"
	"testing"

	cgrant "github.com/libraz/go-oidc-provider/internal/grants/ciba"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// makeClient is a small fixture builder for the Authorize tests.
// Callers tweak the returned record in-place to express the case
// under test.
func makeClient() *store.Client {
	return &store.Client{
		ID:         "client-1",
		GrantTypes: []string{"urn:openid:params:grant-type:ciba"},
		Scopes:     []string{"openid", "profile", "email"},
	}
}

func makeRecord(status store.CIBARequestStatus) *store.CIBARequest {
	return &store.CIBARequest{
		ID:        "ciba-001",
		ClientID:  "client-1",
		Scope:     []string{"openid", "profile"},
		Resource:  []string{"https://api.example.com"},
		ACRValues: []string{"urn:mace:incommon:iap:silver"},
		ACR:       "urn:mace:incommon:iap:bronze",
		Subject:   "user-42",
		Status:    status,
	}
}

func TestAuthorize_Approved(t *testing.T) {
	t.Parallel()
	got, err := cgrant.Authorize(cgrant.AuthorizeInput{
		Client: makeClient(),
		Record: makeRecord(store.CIBARequestStatusApproved),
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.Subject != "user-42" {
		t.Errorf("Subject = %q, want user-42", got.Subject)
	}
	if got.SenderConstraint != "bearer" {
		t.Errorf("SenderConstraint = %q, want bearer", got.SenderConstraint)
	}
	if len(got.Scope) != 2 {
		t.Errorf("Scope = %v, want [openid profile]", got.Scope)
	}
	if got.ACR != "urn:mace:incommon:iap:bronze" {
		t.Errorf("ACR = %q, want urn:mace:incommon:iap:bronze", got.ACR)
	}
}

func TestAuthorize_GrantTypeMissing(t *testing.T) {
	t.Parallel()
	c := makeClient()
	c.GrantTypes = []string{"authorization_code"}
	_, err := cgrant.Authorize(cgrant.AuthorizeInput{
		Client: c,
		Record: makeRecord(store.CIBARequestStatusApproved),
	})
	if !errors.Is(err, cgrant.ErrGrantNotPermitted) {
		t.Errorf("got %v, want ErrGrantNotPermitted", err)
	}
}

func TestAuthorize_StatusGates(t *testing.T) {
	t.Parallel()
	cases := map[store.CIBARequestStatus]error{
		store.CIBARequestStatusPending:  cgrant.ErrPendingApproval,
		store.CIBARequestStatusDenied:   cgrant.ErrDenied,
		store.CIBARequestStatusConsumed: cgrant.ErrAlreadyRedeemed,
	}
	for status, want := range cases {
		_, err := cgrant.Authorize(cgrant.AuthorizeInput{
			Client: makeClient(),
			Record: makeRecord(status),
		})
		if !errors.Is(err, want) {
			t.Errorf("status=%v: got %v, want %v", status, err, want)
		}
	}
}

func TestAuthorize_DPoPBindingMatch(t *testing.T) {
	t.Parallel()
	rec := makeRecord(store.CIBARequestStatusApproved)
	rec.DPoPJKT = "abc123"
	got, err := cgrant.Authorize(cgrant.AuthorizeInput{
		Client:           makeClient(),
		Record:           rec,
		PresentedDPoPJKT: "abc123",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.SenderConstraint != "dpop" {
		t.Errorf("SenderConstraint = %q, want dpop", got.SenderConstraint)
	}
}

func TestAuthorize_DPoPBindingMissing(t *testing.T) {
	t.Parallel()
	rec := makeRecord(store.CIBARequestStatusApproved)
	rec.DPoPJKT = "abc123"
	_, err := cgrant.Authorize(cgrant.AuthorizeInput{
		Client: makeClient(),
		Record: rec,
	})
	if !errors.Is(err, cgrant.ErrCnfBindingMissing) {
		t.Errorf("got %v, want ErrCnfBindingMissing", err)
	}
}

func TestAuthorize_DPoPBindingMismatch(t *testing.T) {
	t.Parallel()
	rec := makeRecord(store.CIBARequestStatusApproved)
	rec.DPoPJKT = "abc123"
	_, err := cgrant.Authorize(cgrant.AuthorizeInput{
		Client:           makeClient(),
		Record:           rec,
		PresentedDPoPJKT: "different",
	})
	if !errors.Is(err, cgrant.ErrCnfBindingMismatch) {
		t.Errorf("got %v, want ErrCnfBindingMismatch", err)
	}
}

func TestAuthorize_MTLSBindingMatch(t *testing.T) {
	t.Parallel()
	rec := makeRecord(store.CIBARequestStatusApproved)
	rec.MTLSCertS256 = "thumb"
	got, err := cgrant.Authorize(cgrant.AuthorizeInput{
		Client:                makeClient(),
		Record:                rec,
		PresentedMTLSCertS256: "thumb",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.SenderConstraint != "mtls" {
		t.Errorf("SenderConstraint = %q, want mtls", got.SenderConstraint)
	}
}

// TestAuthorize_DualBindingANDEvaluated pins the AND evaluation across
// every confirmation method a record committed to. A record carrying
// both a DPoP thumbprint and an mTLS thumbprint must not redeem on a
// poll that satisfies only one of them: otherwise a holder of the
// auth_req_id plus the DPoP key would receive a token stamped with a
// cnf.x5t#S256 the OP never re-verified.
func TestAuthorize_DualBindingANDEvaluated(t *testing.T) {
	t.Parallel()

	newDualRecord := func() *store.CIBARequest {
		rec := makeRecord(store.CIBARequestStatusApproved)
		rec.DPoPJKT = "jkt-device"
		rec.MTLSCertS256 = "x5t-device"
		return rec
	}

	t.Run("cert mismatch is refused", func(t *testing.T) {
		t.Parallel()
		_, err := cgrant.Authorize(cgrant.AuthorizeInput{
			Client:                makeClient(),
			Record:                newDualRecord(),
			PresentedDPoPJKT:      "jkt-device",
			PresentedMTLSCertS256: "x5t-attacker",
		})
		if !errors.Is(err, cgrant.ErrCnfBindingMismatch) {
			t.Errorf("got %v, want ErrCnfBindingMismatch", err)
		}
	})

	t.Run("cert absent is refused", func(t *testing.T) {
		t.Parallel()
		_, err := cgrant.Authorize(cgrant.AuthorizeInput{
			Client:           makeClient(),
			Record:           newDualRecord(),
			PresentedDPoPJKT: "jkt-device",
		})
		if !errors.Is(err, cgrant.ErrCnfBindingMissing) {
			t.Errorf("got %v, want ErrCnfBindingMissing", err)
		}
	})

	t.Run("dpop mismatch is refused", func(t *testing.T) {
		t.Parallel()
		_, err := cgrant.Authorize(cgrant.AuthorizeInput{
			Client:                makeClient(),
			Record:                newDualRecord(),
			PresentedDPoPJKT:      "jkt-attacker",
			PresentedMTLSCertS256: "x5t-device",
		})
		if !errors.Is(err, cgrant.ErrCnfBindingMismatch) {
			t.Errorf("got %v, want ErrCnfBindingMismatch", err)
		}
	})

	t.Run("both matching succeeds", func(t *testing.T) {
		t.Parallel()
		got, err := cgrant.Authorize(cgrant.AuthorizeInput{
			Client:                makeClient(),
			Record:                newDualRecord(),
			PresentedDPoPJKT:      "jkt-device",
			PresentedMTLSCertS256: "x5t-device",
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if got.SenderConstraint != "dpop+mtls" {
			t.Errorf("SenderConstraint = %q, want dpop+mtls", got.SenderConstraint)
		}
	})
}

func TestAuthorize_ScopeSubset(t *testing.T) {
	t.Parallel()
	rec := makeRecord(store.CIBARequestStatusApproved)
	rec.Scope = []string{"openid", "admin"} // admin not in client.Scopes
	_, err := cgrant.Authorize(cgrant.AuthorizeInput{
		Client: makeClient(),
		Record: rec,
	})
	if !errors.Is(err, cgrant.ErrScopeForbidden) {
		t.Errorf("got %v, want ErrScopeForbidden", err)
	}
}

// TestGrantTypeMatchesPublicConstant pins the duplicated wire string
// in this package to op/grant.CIBA.String() so a future rename in
// either place fails to compile rather than drifting silently.
func TestGrantTypeMatchesPublicConstant(t *testing.T) {
	t.Parallel()
	want := grant.CIBA.String()
	c := makeClient()
	c.GrantTypes = []string{want}
	if _, err := cgrant.Authorize(cgrant.AuthorizeInput{
		Client: c,
		Record: makeRecord(store.CIBARequestStatusApproved),
	}); err != nil {
		t.Fatalf("Authorize with public-constant grant_type: %v", err)
	}
}

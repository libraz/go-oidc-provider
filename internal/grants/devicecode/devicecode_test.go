package devicecode_test

import (
	"errors"
	"testing"

	dcgrant "github.com/libraz/go-oidc-provider/internal/grants/devicecode"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// makeClient is a small fixture builder for the Authorize tests.
// Callers tweak the returned record in-place to express the case
// under test.
func makeClient() *store.Client {
	return &store.Client{
		ID:         "client-1",
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
		Scopes:     []string{"openid", "profile", "email"},
	}
}

func makeRecord(status store.DeviceCodeStatus) *store.DeviceCode {
	return &store.DeviceCode{
		ID:       "dev-001",
		ClientID: "client-1",
		Scope:    []string{"openid", "profile"},
		Resource: []string{"https://api.example.com"},
		Status:   status,
		Subject:  "user-42",
	}
}

func TestAuthorize_Approved(t *testing.T) {
	t.Parallel()
	got, err := dcgrant.Authorize(dcgrant.AuthorizeInput{
		Client: makeClient(),
		Record: makeRecord(store.DeviceCodeStatusApproved),
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
}

func TestAuthorize_GrantTypeMissing(t *testing.T) {
	t.Parallel()
	c := makeClient()
	c.GrantTypes = []string{"authorization_code"}
	_, err := dcgrant.Authorize(dcgrant.AuthorizeInput{
		Client: c,
		Record: makeRecord(store.DeviceCodeStatusApproved),
	})
	if !errors.Is(err, dcgrant.ErrGrantNotPermitted) {
		t.Errorf("got %v, want ErrGrantNotPermitted", err)
	}
}

func TestAuthorize_StatusGates(t *testing.T) {
	t.Parallel()
	cases := map[store.DeviceCodeStatus]error{
		store.DeviceCodeStatusPending:  dcgrant.ErrPendingApproval,
		store.DeviceCodeStatusDenied:   dcgrant.ErrDenied,
		store.DeviceCodeStatusConsumed: dcgrant.ErrExpiredOrConsumed,
	}
	for status, want := range cases {
		_, err := dcgrant.Authorize(dcgrant.AuthorizeInput{
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
	rec := makeRecord(store.DeviceCodeStatusApproved)
	rec.DPoPJKT = "abc123"
	got, err := dcgrant.Authorize(dcgrant.AuthorizeInput{
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
	rec := makeRecord(store.DeviceCodeStatusApproved)
	rec.DPoPJKT = "abc123"
	_, err := dcgrant.Authorize(dcgrant.AuthorizeInput{
		Client: makeClient(),
		Record: rec,
	})
	if !errors.Is(err, dcgrant.ErrCnfBindingMissing) {
		t.Errorf("got %v, want ErrCnfBindingMissing", err)
	}
}

func TestAuthorize_DPoPBindingMismatch(t *testing.T) {
	t.Parallel()
	rec := makeRecord(store.DeviceCodeStatusApproved)
	rec.DPoPJKT = "abc123"
	_, err := dcgrant.Authorize(dcgrant.AuthorizeInput{
		Client:           makeClient(),
		Record:           rec,
		PresentedDPoPJKT: "different",
	})
	if !errors.Is(err, dcgrant.ErrCnfBindingMismatch) {
		t.Errorf("got %v, want ErrCnfBindingMismatch", err)
	}
}

func TestAuthorize_ScopeSubset(t *testing.T) {
	t.Parallel()
	rec := makeRecord(store.DeviceCodeStatusApproved)
	rec.Scope = []string{"openid", "admin"} // admin not in client.Scopes
	_, err := dcgrant.Authorize(dcgrant.AuthorizeInput{
		Client: makeClient(),
		Record: rec,
	})
	if !errors.Is(err, dcgrant.ErrScopeForbidden) {
		t.Errorf("got %v, want ErrScopeForbidden", err)
	}
}

// TestGrantTypeMatchesPublicConstant pins the duplicated wire string
// in this package to op/grant.DeviceCode.String() so a future rename
// in either place fails to compile rather than drifting silently.
func TestGrantTypeMatchesPublicConstant(t *testing.T) {
	t.Parallel()
	want := grant.DeviceCode.String()
	c := makeClient()
	c.GrantTypes = []string{want}
	if _, err := dcgrant.Authorize(dcgrant.AuthorizeInput{
		Client: c,
		Record: makeRecord(store.DeviceCodeStatusApproved),
	}); err != nil {
		t.Fatalf("Authorize with public-constant grant_type: %v", err)
	}
}

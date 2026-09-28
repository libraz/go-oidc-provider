package op_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

type revokeSubjectClock struct{ now time.Time }

func (c revokeSubjectClock) Now() time.Time { return c.now }

func seedSubjectGrant(t *testing.T, tk *testkit.Provider, now time.Time, grantID, subject, clientID string) {
	t.Helper()
	ctx := context.Background()
	if err := tk.Store.Grants().Save(ctx, &store.Grant{
		ID: grantID, Subject: subject, ClientID: clientID, Scope: []string{"openid"},
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	if err := tk.Store.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID: "rt-" + grantID, ClientID: clientID, Subject: subject, GrantID: grantID,
		Scope: []string{"openid"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RefreshTokens.Save: %v", err)
	}
}

// assertGrantRevoked reports whether grantID's record, refresh token and
// access tokens were all retired.
func assertGrantRevoked(t *testing.T, tk *testkit.Provider, issuedAt time.Time, grantID string, want bool) {
	t.Helper()
	ctx := context.Background()
	_, err := tk.Store.Grants().Find(ctx, grantID)
	if gone := errors.Is(err, store.ErrNotFound); gone != want {
		t.Errorf("grant %s record gone=%v (err=%v), want %v", grantID, gone, err, want)
	}
	rt, err := tk.Store.RefreshTokens().Find(ctx, "rt-"+grantID)
	if dead := errors.Is(err, store.ErrNotFound) || (err == nil && rt.Revoked); dead != want {
		t.Errorf("grant %s refresh token revoked=%v (err=%v), want %v", grantID, dead, err, want)
	}
	tombstoned, err := tk.Store.GrantRevocations().IsRevoked(ctx, grantID, "", issuedAt)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if tombstoned != want {
		t.Errorf("grant %s access tokens revoked=%v, want %v", grantID, tombstoned, want)
	}
}

func TestProvider_RevokeSubject_RevokesOnlyThatSubjectsGrants(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tk := testkit.NewProvider(t, testkit.WithClock(revokeSubjectClock{now: now}))
	seedSubjectGrant(t, tk, now, "grant-alice-1", "alice", "client-a")
	seedSubjectGrant(t, tk, now, "grant-alice-2", "alice", "client-b")
	seedSubjectGrant(t, tk, now, "grant-bob", "bob", "client-a")

	if err := tk.OP.RevokeSubject(context.Background(), "alice"); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	issuedAt := now.Add(-time.Second)
	assertGrantRevoked(t, tk, issuedAt, "grant-alice-1", true)
	assertGrantRevoked(t, tk, issuedAt, "grant-alice-2", true)
	assertGrantRevoked(t, tk, issuedAt, "grant-bob", false)

	// Idempotent: the subject now holds no grants.
	if err := tk.OP.RevokeSubject(context.Background(), "alice"); err != nil {
		t.Fatalf("second RevokeSubject: %v", err)
	}
	if err := tk.OP.RevokeSubject(context.Background(), "nobody"); err != nil {
		t.Fatalf("RevokeSubject on a subject with no grants: %v", err)
	}
}

func TestProvider_RevokeSubject_EmptySubjectIsConfigurationError(t *testing.T) {
	t.Parallel()
	tk := testkit.NewProvider(t)
	err := tk.OP.RevokeSubject(context.Background(), "")
	var opErr *op.Error
	if !errors.As(err, &opErr) || opErr.Code != "configuration_error" {
		t.Fatalf("RevokeSubject(\"\") = %v, want a configuration_error *op.Error", err)
	}
}

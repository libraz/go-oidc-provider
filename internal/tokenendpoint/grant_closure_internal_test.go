package tokenendpoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// confirm is the settle step both refresh paths run once a rotation is
// durable. A closure that landed after the pre-mint check must replace the
// staged success with invalid_grant, retire what the rotation persisted, and
// suppress the token.refreshed record — under any JWT revocation strategy.
func TestRotationOutcomeConfirm_RefusesUnderGrantClosedDuringRotation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	backing := inmem.New(inmem.WithClock(fixedClock{now: now}))
	const grantID = "grant-closed-mid-rotation"
	const successor = "rt-successor"
	if err := backing.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID: successor, ClientID: "client-1", Subject: "user-1", GrantID: grantID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	deps := Deps{
		Clock:              fixedClock{now: now},
		RefreshTokens:      backing.RefreshTokens(),
		GrantRevocations:   backing.GrantRevocations(),
		RevocationStrategy: store.RevocationStrategyJTIRegistry,
	}
	issued := issuedUnderGrant{GrantID: grantID, IssuedAt: now.Add(-time.Minute), RefreshToken: successor}

	var open rotationOutcome
	open.record(audit.Event{Name: auditTokenRefreshed})
	open.recordIssued(issued)
	staged := httpx.NewBufferedWriter(http.StatusOK)
	if got := open.confirm(ctx, deps, staged); got != staged || open.event == nil {
		t.Fatal("an open grant must forward the staged response and keep the rotation record")
	}

	if err := backing.GrantRevocations().RevokeGrant(ctx, store.GrantTombstone{
		GrantID: grantID, RevokedAt: now, ExpiresAt: now.Add(time.Hour), Reason: "operator",
	}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	var closed rotationOutcome
	closed.record(audit.Event{Name: auditTokenRefreshed})
	closed.recordIssued(issued)
	got := closed.confirm(ctx, deps, staged)
	if got == staged || got.Status() != http.StatusBadRequest {
		t.Fatalf("closed grant: status=%d, want the staged success replaced by 400", got.Status())
	}
	rec := httptest.NewRecorder()
	_ = got.Commit(rec)
	if !strings.Contains(rec.Body.String(), errInvalidGrant) {
		t.Errorf("closed grant: body=%s, want invalid_grant", rec.Body.String())
	}
	if closed.event != nil {
		t.Error("a refused rotation must not raise token.refreshed")
	}
	stored, err := backing.RefreshTokens().Find(ctx, successor)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if !stored.Revoked {
		t.Error("the successor persisted under the closed grant is still redeemable")
	}
}

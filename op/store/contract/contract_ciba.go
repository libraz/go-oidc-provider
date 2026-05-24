package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// This file holds the CIBARequestStore contract sub-tests (OpenID
// Connect CIBA Core 1.0). They pin the backchannel-authentication
// state machine — Save → approve / deny → poll → consume, plus the
// slow_down poll-violation counter — identically across every backend
// that hosts the substore.

// requireCIBA skips the current test when the backend does not provide
// a [store.CIBARequestStore]. Partial-coverage backends return nil
// here, and the harness treats the substore as out of scope rather
// than panicking.
func requireCIBA(t *testing.T, s store.Store) store.CIBARequestStore {
	t.Helper()
	cr := s.CIBARequests()
	if cr == nil {
		t.Skipf("backend %T does not provide a CIBARequestStore", s)
	}
	return cr
}

func newCIBARequest(now time.Time, id string) *store.CIBARequest {
	return &store.CIBARequest{
		ID:             id,
		ClientID:       "client",
		Subject:        "sub",
		Scope:          []string{"openid"},
		ACRValues:      []string{"urn:mace:incommon:iap:silver"},
		BindingMessage: "W4SCT",
		Interval:       5 * time.Second,
		Status:         store.CIBARequestStatusPending,
		IssuedAt:       now,
		ExpiresAt:      now.Add(time.Hour),
	}
}

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var cibaRequestCases = []subtest{
	{"SaveFind", cibaSaveFind},
	{"ApproveConsumeOnce", cibaApproveConsumeOnce},
	{"ApproveConflictAfterDeny", cibaApproveConflictAfterDeny},
	{"ConsumeConflictWhenDenied", cibaConsumeConflictWhenDenied},
	{"RecordPollStampsTimestamp", cibaRecordPollStamps},
	{"PollViolationsIncrement", cibaPollViolationsIncrement},
	{"Expired", cibaExpired},
	{"TransitionMissing", cibaTransitionMissing},
}

func cibaSaveFind(t *testing.T, f Factory) {
	b := f(t)
	cr := requireCIBA(t, b.Store)
	ctx := context.Background()
	if err := cr.Save(ctx, newCIBARequest(b.Now(), "ar-1")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := cr.FindByAuthReqID(ctx, "ar-1")
	if err != nil {
		t.Fatalf("FindByAuthReqID: %v", err)
	}
	if got.ID != "ar-1" || got.BindingMessage != "W4SCT" || got.Status != store.CIBARequestStatusPending {
		t.Fatalf("unexpected record: %+v", got)
	}
	if len(got.ACRValues) != 1 || got.ACRValues[0] != "urn:mace:incommon:iap:silver" {
		t.Fatalf("acr_values did not round-trip: %+v", got.ACRValues)
	}
	if _, err := cr.FindByAuthReqID(ctx, "absent"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByAuthReqID missing: want ErrNotFound, got %v", err)
	}
}

func cibaApproveConsumeOnce(t *testing.T, f Factory) {
	b := f(t)
	cr := requireCIBA(t, b.Store)
	ctx := context.Background()
	if err := cr.Save(ctx, newCIBARequest(b.Now(), "ar-ac")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := cr.Approve(ctx, "ar-ac", "sub-1", b.Now()); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	got, err := cr.FindByAuthReqID(ctx, "ar-ac")
	if err != nil {
		t.Fatalf("FindByAuthReqID after approve: %v", err)
	}
	if got.Status != store.CIBARequestStatusApproved || got.Subject != "sub-1" {
		t.Fatalf("approve did not stamp record: %+v", got)
	}
	first, err := cr.Consume(ctx, "ar-ac")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if first.Status != store.CIBARequestStatusConsumed || first.ID != "ar-ac" {
		t.Fatalf("Consume returned unexpected record: %+v", first)
	}
	if _, err := cr.Consume(ctx, "ar-ac"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
}

func cibaApproveConflictAfterDeny(t *testing.T, f Factory) {
	b := f(t)
	cr := requireCIBA(t, b.Store)
	ctx := context.Background()
	if err := cr.Save(ctx, newCIBARequest(b.Now(), "ar-cf")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := cr.Deny(ctx, "ar-cf", "user_denied"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if err := cr.Approve(ctx, "ar-cf", "sub-1", b.Now()); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Approve after Deny: want ErrConflict, got %v", err)
	}
}

func cibaConsumeConflictWhenDenied(t *testing.T, f Factory) {
	b := f(t)
	cr := requireCIBA(t, b.Store)
	ctx := context.Background()
	if err := cr.Save(ctx, newCIBARequest(b.Now(), "ar-dn")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := cr.Deny(ctx, "ar-dn", "auth_device_timeout"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if _, err := cr.Consume(ctx, "ar-dn"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Consume denied: want ErrConflict, got %v", err)
	}
}

func cibaRecordPollStamps(t *testing.T, f Factory) {
	b := f(t)
	cr := requireCIBA(t, b.Store)
	ctx := context.Background()
	if err := cr.Save(ctx, newCIBARequest(b.Now(), "ar-poll")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := cr.RecordPoll(ctx, "ar-poll", b.Now()); err != nil {
		t.Fatalf("RecordPoll: %v", err)
	}
	got, err := cr.FindByAuthReqID(ctx, "ar-poll")
	if err != nil {
		t.Fatalf("FindByAuthReqID: %v", err)
	}
	if got.LastPolledAt == nil {
		t.Fatal("RecordPoll did not stamp LastPolledAt")
	}
	if err := cr.RecordPoll(ctx, "absent", b.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RecordPoll missing: want ErrNotFound, got %v", err)
	}
}

func cibaPollViolationsIncrement(t *testing.T, f Factory) {
	b := f(t)
	cr := requireCIBA(t, b.Store)
	ctx := context.Background()
	if err := cr.Save(ctx, newCIBARequest(b.Now(), "ar-viol")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for want := uint8(1); want <= 2; want++ {
		got, err := cr.IncrementPollViolation(ctx, "ar-viol")
		if err != nil {
			t.Fatalf("IncrementPollViolation: %v", err)
		}
		if got != want {
			t.Fatalf("violation count: want %d, got %d", want, got)
		}
	}
	if _, err := cr.IncrementPollViolation(ctx, "absent"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("IncrementPollViolation missing: want ErrNotFound, got %v", err)
	}
}

func cibaExpired(t *testing.T, f Factory) {
	b := f(t)
	cr := requireCIBA(t, b.Store)
	ctx := context.Background()
	rec := newCIBARequest(b.Now(), "ar-exp")
	rec.ExpiresAt = b.Now().Add(-time.Hour)
	if err := cr.Save(ctx, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := cr.FindByAuthReqID(ctx, "ar-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByAuthReqID expired: want ErrNotFound, got %v", err)
	}
	if err := cr.Approve(ctx, "ar-exp", "sub-1", b.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Approve expired: want ErrNotFound, got %v", err)
	}
	if _, err := cr.Consume(ctx, "ar-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume expired: want ErrNotFound, got %v", err)
	}
	if err := cr.RecordPoll(ctx, "ar-exp", b.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RecordPoll expired: want ErrNotFound, got %v", err)
	}
	if _, err := cr.IncrementPollViolation(ctx, "ar-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("IncrementPollViolation expired: want ErrNotFound, got %v", err)
	}
}

func cibaTransitionMissing(t *testing.T, f Factory) {
	b := f(t)
	cr := requireCIBA(t, b.Store)
	ctx := context.Background()
	if err := cr.Approve(ctx, "absent", "sub-1", b.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Approve missing: want ErrNotFound, got %v", err)
	}
	if err := cr.Deny(ctx, "absent", "user_denied"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Deny missing: want ErrNotFound, got %v", err)
	}
	if _, err := cr.Consume(ctx, "absent"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume missing: want ErrNotFound, got %v", err)
	}
}

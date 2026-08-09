package contract

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// This file groups the contract sub-tests for the substores that come after
// GrantStore: SessionStore, PushedAuthRequestStore, InteractionStore, and
// ConsumedJTIStore. They are split off from contract.go to keep the per-file
// size budget below 800 lines; the Transactional extension has its own file
// for the same reason.

// --- SessionStore ------------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var sessionCases = []subtest{
	{"SaveFind", sessionSaveFind},
	{"Touch", sessionTouch},
	{"TouchMissing", sessionTouchMissing},
	{"TouchAfterDelete", sessionTouchAfterDelete},
	{"Delete", sessionDelete},
	{"DeleteExpired", sessionDeleteExpired},
	{"Expired", sessionExpired},
	{"ListByChooserGroup", sessionListByChooserGroup},
	{"ListByChooserGroupSkipsExpired", sessionListByChooserGroupSkipsExpired},
	{"ConcurrentRotate", sessionConcurrentRotate},
}

// sessionConcurrentRotate is a thin adapter that funnels the harness's
// [Factory] / [Backend] pair into the free-standing
// [AssertConcurrentRotate] helper so the contract suite drives the
// rotation post-condition automatically. Adapter authors may also call
// AssertConcurrentRotate directly when they want to exercise the
// SessionStore in isolation (e.g. a Redis-only deployment).
func sessionConcurrentRotate(t *testing.T, f Factory) {
	b := f(t)
	AssertConcurrentRotate(t, b.Store.Sessions(), b.Now())
}

func sessionSaveFind(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	s := newSession(b.Now(), "s-1")
	if err := b.Store.Sessions().Save(ctx, s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.Sessions().Find(ctx, "s-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != "s-1" {
		t.Fatalf("unexpected session: %+v", got)
	}
}

func sessionTouch(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	s := newSession(b.Now(), "s-touch")
	if err := b.Store.Sessions().Save(ctx, s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	newExp := b.Now().Add(2 * time.Hour)
	newUpd := b.Now().Add(time.Minute)
	if err := b.Store.Sessions().Touch(ctx, "s-touch", newExp, newUpd); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, err := b.Store.Sessions().Find(ctx, "s-touch")
	if err != nil {
		t.Fatalf("Find after Touch: %v", err)
	}
	if !got.ExpiresAt.Equal(newExp) {
		t.Fatalf("Touch did not update ExpiresAt: got %v want %v", got.ExpiresAt, newExp)
	}
	if !got.UpdatedAt.Equal(newUpd) {
		t.Fatalf("Touch did not update UpdatedAt: got %v want %v", got.UpdatedAt, newUpd)
	}
}

func sessionTouchMissing(t *testing.T, f Factory) {
	b := f(t)
	err := b.Store.Sessions().Touch(context.Background(), "absent", b.Now(), b.Now())
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Touch missing: want ErrNotFound, got %v", err)
	}
}

func sessionTouchAfterDelete(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	s := newSession(b.Now(), "s-touch-delete")
	if err := b.Store.Sessions().Save(ctx, s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := b.Store.Sessions().Delete(ctx, s.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	err := b.Store.Sessions().Touch(ctx, s.ID, b.Now().Add(2*time.Hour), b.Now().Add(time.Minute))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Touch after Delete: want ErrNotFound, got %v", err)
	}
	if _, err := b.Store.Sessions().Find(ctx, s.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after Touch-after-Delete: want ErrNotFound, got %v", err)
	}
}

func sessionDelete(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	s := newSession(b.Now(), "s-del")
	if err := b.Store.Sessions().Save(ctx, s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := b.Store.Sessions().Delete(ctx, "s-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	err := b.Store.Sessions().Delete(ctx, "s-del")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("repeat Delete: want ErrNotFound, got %v", err)
	}
}

// sessionDeleteExpired pins the absent-or-expired rule declared on
// [store.SessionStore.Delete]. [sessionDelete] only covers live-then-repeat,
// which every backend answers correctly from physical presence alone; the
// case that discriminates is a record still resident but past its ExpiresAt.
// A presence-based backend returns nil for it and [store.ErrNotFound] for
// the same record once a sweep or a TTL eviction reclaimed the row, so the
// caller's observation would turn on collection timing rather than on the
// session's state.
//
// Two shapes are exercised because backends differ in where the expired
// record can come from: a write that was already past-dated (some backends
// legitimately drop it, which satisfies the post-condition) and a record
// stored live and then expired in place by moving the backend clock. Only
// the second guarantees the row is physically there, so it runs wherever
// [Backend.Advance] exists.
func sessionDeleteExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()

	dead := newSession(b.Now(), "s-del-past-dated")
	dead.ExpiresAt = b.Now().Add(-time.Hour)
	if err := b.Store.Sessions().Save(ctx, dead); err != nil {
		t.Fatalf("Save past-dated: %v", err)
	}
	if err := b.Store.Sessions().Delete(ctx, dead.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete past-dated session: want ErrNotFound, got %v", err)
	}

	if b.Advance == nil {
		return
	}
	const ttl = time.Minute
	resident := newSession(b.Now(), "s-del-expired-in-place")
	resident.ExpiresAt = b.Now().Add(ttl)
	if err := b.Store.Sessions().Save(ctx, resident); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Overshoot the expiry rather than landing on it: backends differ on
	// whether the boundary instant itself counts as expired.
	b.Advance(2 * ttl)
	if err := b.Store.Sessions().Delete(ctx, resident.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete expired-but-resident session: want ErrNotFound, got %v", err)
	}
	if _, err := b.Store.Sessions().Find(ctx, resident.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after Delete of an expired session: want ErrNotFound, got %v", err)
	}
}

func sessionExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	s := newSession(b.Now(), "s-exp")
	s.ExpiresAt = b.Now().Add(-time.Hour)
	if err := b.Store.Sessions().Save(ctx, s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := b.Store.Sessions().Find(ctx, "s-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find expired: want ErrNotFound, got %v", err)
	}
}

func sessionListByChooserGroup(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	a := newSession(b.Now(), "s-a")
	a.ChooserGroupID = "cg-list"
	a.Subject = "user-a"
	bb := newSession(b.Now(), "s-b")
	bb.ChooserGroupID = "cg-list"
	bb.Subject = "user-b"
	other := newSession(b.Now(), "s-other")
	other.ChooserGroupID = "cg-other"
	for _, s := range []*store.Session{a, bb, other} {
		if err := b.Store.Sessions().Save(ctx, s); err != nil {
			t.Fatalf("Save %s: %v", s.ID, err)
		}
	}
	got, err := b.Store.Sessions().ListByChooserGroup(ctx, "cg-list")
	if err != nil {
		t.Fatalf("ListByChooserGroup: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d want 2; got %+v", len(got), got)
	}
	for _, s := range got {
		if s.ChooserGroupID != "cg-list" {
			t.Errorf("returned session with ChooserGroupID=%q", s.ChooserGroupID)
		}
	}
}

func sessionListByChooserGroupSkipsExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	live := newSession(b.Now(), "s-live")
	live.ChooserGroupID = "cg-mixed"
	dead := newSession(b.Now(), "s-dead")
	dead.ChooserGroupID = "cg-mixed"
	dead.ExpiresAt = b.Now().Add(-time.Hour)
	for _, s := range []*store.Session{live, dead} {
		if err := b.Store.Sessions().Save(ctx, s); err != nil {
			t.Fatalf("Save %s: %v", s.ID, err)
		}
	}
	got, err := b.Store.Sessions().ListByChooserGroup(ctx, "cg-mixed")
	if err != nil {
		t.Fatalf("ListByChooserGroup: %v", err)
	}
	if len(got) != 1 || got[0].ID != "s-live" {
		t.Fatalf("got %+v want exactly s-live", got)
	}
}

// --- PushedAuthRequestStore --------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var parCases = []subtest{
	{"SaveFind", parSaveFind},
	{"ConsumeOnce", parConsumeOnce},
	{"Expired", parExpired},
	{"ConsumeExpiredStillRedeems", parConsumeExpiredStillRedeems},
}

func parSaveFind(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	par := newPAR(b.Now(), "urn:par:1")
	if err := b.Store.PushedAuthRequests().Save(ctx, par); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.PushedAuthRequests().Find(ctx, "urn:par:1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.URI != "urn:par:1" {
		t.Fatalf("unexpected par: %+v", got)
	}
}

func parConsumeOnce(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	par := newPAR(b.Now(), "urn:par:2")
	if err := b.Store.PushedAuthRequests().Save(ctx, par); err != nil {
		t.Fatalf("Save: %v", err)
	}
	first, err := b.Store.PushedAuthRequests().Consume(ctx, "urn:par:2")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if first.ConsumedAt == nil {
		t.Fatal("Consume returned ConsumedAt=nil")
	}
	_, err = b.Store.PushedAuthRequests().Consume(ctx, "urn:par:2")
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
}

func parExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	par := newPAR(b.Now(), "urn:par:exp")
	par.ExpiresAt = b.Now().Add(-time.Hour)
	if err := b.Store.PushedAuthRequests().Save(ctx, par); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := b.Store.PushedAuthRequests().Find(ctx, "urn:par:exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find expired: want ErrNotFound, got %v", err)
	}
}

// parConsumeExpiredStillRedeems pins the single-use-only Consume contract:
// expiry is gated at presentation by Find, so a request_uri whose lifetime
// elapsed during an interactive login still redeems exactly once at code
// emission. Consuming a second time is the replay that MUST fail.
func parConsumeExpiredStillRedeems(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	par := newPAR(b.Now(), "urn:par:exp-consume")
	par.ExpiresAt = b.Now().Add(-time.Hour)
	if err := b.Store.PushedAuthRequests().Save(ctx, par); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.PushedAuthRequests().Consume(ctx, "urn:par:exp-consume")
	if err != nil {
		t.Fatalf("Consume expired-but-unconsumed: want success, got %v", err)
	}
	if got.ConsumedAt == nil {
		t.Fatal("Consume returned ConsumedAt=nil")
	}
	if _, err := b.Store.PushedAuthRequests().Consume(ctx, "urn:par:exp-consume"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
}

// --- InteractionStore --------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var interactionCases = []subtest{
	{"SaveFind", interactionSaveFind},
	{"CompareAndSwap", interactionCompareAndSwap},
	{"Delete", interactionDelete},
	{"DeleteExpired", interactionDeleteExpired},
	{"Expired", interactionExpired},
}

func interactionSaveFind(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	i := newInteraction(b.Now(), "i-1")
	if err := b.Store.Interactions().Save(ctx, i); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.Interactions().Find(ctx, "i-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != "i-1" {
		t.Fatalf("unexpected interaction: %+v", got)
	}
}

func interactionCompareAndSwap(t *testing.T, f Factory) { //nolint:gocognit,cyclop // one linear contract scenario asserts every CAS post-condition.
	b := f(t)
	ctx := context.Background()
	cas, ok := b.Store.Interactions().(store.InteractionStoreCAS)
	if !ok {
		t.Fatal("InteractionStore must implement InteractionStoreCAS")
	}
	original := newInteraction(b.Now(), "i-cas")
	original.RawState = []byte("v1")
	if err := cas.Save(ctx, original); err != nil {
		t.Fatalf("Save: %v", err)
	}
	snapshot, err := cas.Find(ctx, original.ID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	next := *snapshot
	next.RawState = []byte("v2")
	next.UpdatedAt = b.Now().Add(time.Second)
	nonVersionSnapshot := *snapshot
	nonVersionSnapshot.Step = "locally-different-step"
	nonVersionSnapshot.UpdatedAt = b.Now().Add(30 * time.Second)
	if err := cas.CompareAndSwap(ctx, &nonVersionSnapshot, &next); err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	stale := next
	stale.RawState = []byte("v3")
	if err := cas.CompareAndSwap(ctx, snapshot, &stale); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale CompareAndSwap: want ErrConflict, got %v", err)
	}
	got, err := cas.Find(ctx, original.ID)
	if err != nil {
		t.Fatalf("Find replacement: %v", err)
	}
	if string(got.RawState) != "v2" {
		t.Fatalf("RawState=%q want v2", got.RawState)
	}
	contenders := []store.Interaction{*got, *got}
	contenders[0].RawState = []byte("v3-a")
	contenders[1].RawState = []byte("v3-b")
	errs := make([]error, len(contenders))
	var wg sync.WaitGroup
	wg.Add(len(contenders))
	for i := range contenders {
		go func(index int) {
			defer wg.Done()
			errs[index] = cas.CompareAndSwap(ctx, got, &contenders[index])
		}(i)
	}
	wg.Wait()
	var successes, conflicts int
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, store.ErrConflict):
			conflicts++
		default:
			t.Fatalf("concurrent CompareAndSwap: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent CompareAndSwap successes=%d conflicts=%d want 1/1",
			successes, conflicts)
	}
	if err := cas.DeleteIfUnchanged(ctx, snapshot); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale DeleteIfUnchanged: want ErrConflict, got %v", err)
	}
	got, err = cas.Find(ctx, original.ID)
	if err != nil {
		t.Fatalf("Find concurrent winner: %v", err)
	}
	if err := cas.DeleteIfUnchanged(ctx, got); err != nil {
		t.Fatalf("DeleteIfUnchanged: %v", err)
	}
	if _, err := cas.Find(ctx, original.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find conditionally deleted interaction: want ErrNotFound, got %v", err)
	}
	missing := *snapshot
	missing.ID = "i-cas-missing"
	missingNext := missing
	missingNext.RawState = []byte("new")
	if err := cas.CompareAndSwap(ctx, &missing, &missingNext); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing CompareAndSwap: want ErrNotFound, got %v", err)
	}
	if err := cas.DeleteIfUnchanged(ctx, &missing); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing DeleteIfUnchanged: want ErrNotFound, got %v", err)
	}
	if b.Advance != nil {
		expiring := newInteraction(b.Now(), "i-cas-expiring")
		expiring.ExpiresAt = b.Now().Add(time.Minute)
		if err := cas.Save(ctx, expiring); err != nil {
			t.Fatalf("Save expiring: %v", err)
		}
		b.Advance(2 * time.Minute)
		expiringNext := *expiring
		expiringNext.RawState = []byte("after-expiry")
		if err := cas.CompareAndSwap(ctx, expiring, &expiringNext); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired-current CompareAndSwap: want ErrNotFound, got %v", err)
		}
		if err := cas.DeleteIfUnchanged(ctx, expiring); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired-current DeleteIfUnchanged: want ErrNotFound, got %v", err)
		}
	}
}

func interactionDelete(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	i := newInteraction(b.Now(), "i-del")
	if err := b.Store.Interactions().Save(ctx, i); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := b.Store.Interactions().Delete(ctx, "i-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	err := b.Store.Interactions().Delete(ctx, "i-del")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("repeat Delete: want ErrNotFound, got %v", err)
	}
}

// interactionDeleteExpired is [sessionDeleteExpired] for
// [store.InteractionStore.Delete], which carries the identical
// absent-or-expired rule. The two substores are the volatile pair most
// likely to be routed to a backend with its own reclamation schedule, so
// each needs its own case: an adapter can easily fix one Delete and leave
// the other answering from presence.
func interactionDeleteExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()

	dead := newInteraction(b.Now(), "i-del-past-dated")
	dead.ExpiresAt = b.Now().Add(-time.Hour)
	if err := b.Store.Interactions().Save(ctx, dead); err != nil {
		t.Fatalf("Save past-dated: %v", err)
	}
	if err := b.Store.Interactions().Delete(ctx, dead.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete past-dated interaction: want ErrNotFound, got %v", err)
	}

	if b.Advance == nil {
		return
	}
	const ttl = time.Minute
	resident := newInteraction(b.Now(), "i-del-expired-in-place")
	resident.ExpiresAt = b.Now().Add(ttl)
	if err := b.Store.Interactions().Save(ctx, resident); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Overshoot the expiry rather than landing on it: backends differ on
	// whether the boundary instant itself counts as expired.
	b.Advance(2 * ttl)
	if err := b.Store.Interactions().Delete(ctx, resident.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete expired-but-resident interaction: want ErrNotFound, got %v", err)
	}
	if _, err := b.Store.Interactions().Find(ctx, resident.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after Delete of an expired interaction: want ErrNotFound, got %v", err)
	}
}

func interactionExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	i := newInteraction(b.Now(), "i-exp")
	i.ExpiresAt = b.Now().Add(-time.Hour)
	if err := b.Store.Interactions().Save(ctx, i); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := b.Store.Interactions().Find(ctx, "i-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find expired: want ErrNotFound, got %v", err)
	}
}

// --- ConsumedJTIStore --------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var jtiCases = []subtest{
	{"MarkHas", jtiMarkHas},
	{"HasMissing", jtiHasMissing},
	{"Replay", jtiReplay},
	{"ExpiredMarkerCanBeReplaced", jtiExpiredMarkerCanBeReplaced},
	{"ExpiryBoundIsInclusive", jtiExpiryBoundIsInclusive},
	{"ZeroExpiryPersists", jtiZeroExpiryPersists},
}

// jtiExpiryBoundIsInclusive pins the single expiry boundary declared on
// [store.ConsumedJTIStore]: a marker is expired from its expiresAt onwards,
// and Mark and Has apply that bound identically. A backend that expires the
// marker for one method but not the other lets a caller read a jti as
// consumed and then successfully consume it again — or, in the other
// direction, read it as free and be rejected as a replay.
//
// The case advances the backend clock to the marker's own expiry instant, so
// it discriminates only on backends that expose [Backend.Advance]; without
// one there is no way to land exactly on the boundary.
func jtiExpiryBoundIsInclusive(t *testing.T, f Factory) {
	b := f(t)
	if b.Advance == nil {
		t.Skip("backend has no mutable clock; cannot land on the expiry boundary")
	}
	ctx := context.Background()
	const ttl = time.Hour
	expiresAt := b.Now().Add(ttl)
	if err := b.Store.ConsumedJTIs().Mark(ctx, "jti-boundary", expiresAt); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	b.Advance(ttl)

	got, err := b.Store.ConsumedJTIs().Has(ctx, "jti-boundary")
	if err != nil {
		t.Fatalf("Has at the expiry instant: %v", err)
	}
	if got {
		t.Fatal("Has reported a marker live at its own expiresAt; the bound is inclusive")
	}
	if err := b.Store.ConsumedJTIs().Mark(ctx, "jti-boundary", b.Now().Add(ttl)); err != nil {
		t.Fatalf("Mark at the expiry instant: want the stale marker replaced, got %v", err)
	}
}

func jtiMarkHas(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	expiresAt := b.Now().Add(time.Hour)
	if err := b.Store.ConsumedJTIs().Mark(ctx, "jti-1", expiresAt); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	got, err := b.Store.ConsumedJTIs().Has(ctx, "jti-1")
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if !got {
		t.Fatal("Has returned false for marked jti")
	}
}

func jtiHasMissing(t *testing.T, f Factory) {
	b := f(t)
	got, err := b.Store.ConsumedJTIs().Has(context.Background(), "absent")
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if got {
		t.Fatal("Has returned true for unknown jti")
	}
}

func jtiReplay(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	expiresAt := b.Now().Add(time.Hour)
	if err := b.Store.ConsumedJTIs().Mark(ctx, "jti-replay", expiresAt); err != nil {
		t.Fatalf("first Mark: %v", err)
	}
	err := b.Store.ConsumedJTIs().Mark(ctx, "jti-replay", expiresAt)
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("replay Mark: want ErrAlreadyConsumed, got %v", err)
	}
}

func jtiExpiredMarkerCanBeReplaced(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	if err := b.Store.ConsumedJTIs().Mark(ctx, "jti-expired", b.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("expired Mark: %v", err)
	}
	got, err := b.Store.ConsumedJTIs().Has(ctx, "jti-expired")
	if err != nil {
		t.Fatalf("Has expired: %v", err)
	}
	if got {
		t.Fatal("Has returned true for expired jti marker")
	}
	if err := b.Store.ConsumedJTIs().Mark(ctx, "jti-expired", b.Now().Add(time.Hour)); err != nil {
		t.Fatalf("fresh Mark after expired marker: %v", err)
	}
}

// jtiZeroExpiryPersists pins the project-wide "zero time means no expiry"
// convention for replay markers: a jti marked with a zero expiresAt must
// be retained permanently (Has stays true) and must reject a later Mark
// as a replay. A backend that dropped the zero-expiry marker would
// silently lose replay protection for any caller passing a zero expiry.
func jtiZeroExpiryPersists(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	if err := b.Store.ConsumedJTIs().Mark(ctx, "jti-zero", time.Time{}); err != nil {
		t.Fatalf("Mark zero-expiry: %v", err)
	}
	got, err := b.Store.ConsumedJTIs().Has(ctx, "jti-zero")
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if !got {
		t.Fatal("Has returned false for a zero-expiry (permanent) marker")
	}
	if err := b.Store.ConsumedJTIs().Mark(ctx, "jti-zero", time.Time{}); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("replay of zero-expiry marker: want ErrAlreadyConsumed, got %v", err)
	}
}

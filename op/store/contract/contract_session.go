package contract

import (
	"bytes"
	"context"
	"errors"
	"strconv"
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
	{"SaveReplacesPastDatedRecord", sessionSaveReplacesWithPastDated},
	{"Touch", sessionTouch},
	{"TouchWithUnchangedValues", sessionTouchUnchanged},
	{"TouchLeavesEveryOtherField", sessionTouchLeavesOtherFields},
	{"TouchMissing", sessionTouchMissing},
	{"TouchAfterDelete", sessionTouchAfterDelete},
	{"Delete", sessionDelete},
	{"DeleteExpired", sessionDeleteExpired},
	{"Expired", sessionExpired},
	{"ListByChooserGroup", sessionListByChooserGroup},
	{"ListByChooserGroupSkipsExpired", sessionListByChooserGroupSkipsExpired},
	{"ListByChooserGroupFollowsTheRecord", sessionListByChooserGroupFollowsTheRecord},
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

// sessionTouchUnchanged pins that a Touch which writes the values the
// record already carries still reports success.
//
// The repeat is ordinary traffic, not a contrived input: an OP whose
// clock has second granularity computes the same ExpiresAt for two
// requests that arrive inside the same second, and the sliding-expiry
// update on the second one changes no column at all. A backend that
// reads its verdict off an affected-row count sees zero changed rows for
// it — MySQL counts changed rows rather than matched ones — and answers
// ErrNotFound, which the OP maps onto "the current session expired". The
// user is signed out mid-flow, on one storage engine only, by a request
// that found their session perfectly alive.
func sessionTouchUnchanged(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	s := newSession(b.Now(), "s-touch-noop")
	if err := b.Store.Sessions().Save(ctx, s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	exp := b.Now().Add(2 * time.Hour)
	upd := b.Now().Add(time.Minute)
	for attempt := 1; attempt <= 2; attempt++ {
		if err := b.Store.Sessions().Touch(ctx, s.ID, exp, upd); err != nil {
			t.Fatalf("Touch with unchanged values (attempt %d): want success, got %v", attempt, err)
		}
	}
	got, err := b.Store.Sessions().Find(ctx, s.ID)
	if err != nil {
		t.Fatalf("Find after the repeated Touch: %v", err)
	}
	if !got.ExpiresAt.Equal(exp) || !got.UpdatedAt.Equal(upd) {
		t.Fatalf("repeated Touch left ExpiresAt=%v UpdatedAt=%v, want %v / %v",
			got.ExpiresAt, got.UpdatedAt, exp, upd)
	}
}

// touchRaceRounds is how many times [sessionTouchLeavesOtherFields]
// runs its two writers at each other. One round is enough to catch a
// backend that always loses the field, but the interleaving that exposes
// a read-decide-write extension is a window of one round trip, so the
// case repeats to make hitting it reliable rather than lucky.
const touchRaceRounds = 16

// sessionTouchLeavesOtherFields pins the scope of the write
// [store.SessionStore.Touch] declares: it sets ExpiresAt and UpdatedAt,
// and it is not a replacement of the record.
//
// The distinction is invisible until something else writes the record
// between the extension's read and its write. A backend that implements
// the idle timer by reading the session, patching two fields and putting
// the whole thing back rewinds everything the other writer stored — the
// ACR a step-up just raised, the chooser group an account switch just
// moved the session into — and rebuilds whatever secondary index it
// derives from them. Nothing reports an error: the session simply goes
// back to what it was a moment ago, carrying the authentication context
// of the login it was supposed to have left behind.
//
// The two writers run against each other because that is the only shape
// the defect has. Whichever order they land in, the post-condition is the
// same and does not depend on the timing: the record-level write is the
// Save, so the fields it set are what the record holds afterwards, and
// the Touch may have moved the two timestamps and nothing else. A
// backend that cannot narrow the write that far is required to refuse
// rather than store what it read, so a Touch that reports
// [store.ErrConflict] satisfies the contract too — what it may not do is
// report success and take the step-up with it.
func sessionTouchLeavesOtherFields(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	sessions := b.Store.Sessions()

	for round := range touchRaceRounds {
		id := "s-touch-fields-" + strconv.Itoa(round)
		original := newSession(b.Now(), id)
		original.ChooserGroupID = "cg-before-" + strconv.Itoa(round)
		original.ACR = "urn:acr:pwd"
		if err := sessions.Save(ctx, original); err != nil {
			t.Fatalf("Save round %d: %v", round, err)
		}

		// The step-up: a second factor raised the ACR and the account
		// moved into another chooser group.
		stepped := newSession(b.Now(), id)
		stepped.ChooserGroupID = "cg-after-" + strconv.Itoa(round)
		stepped.ACR = "urn:acr:mfa"
		stepped.AMR = []string{"pwd", "otp"}

		exp := b.Now().Add(2 * time.Hour)
		upd := b.Now().Add(time.Minute)
		saveErr, touchErr := raceSaveAndTouch(sessions, stepped, exp, upd)
		if saveErr != nil {
			t.Fatalf("concurrent Save round %d: %v", round, saveErr)
		}
		if touchErr != nil && !errors.Is(touchErr, store.ErrConflict) {
			t.Fatalf("concurrent Touch round %d: %v", round, touchErr)
		}

		got, err := sessions.Find(ctx, id)
		if err != nil {
			t.Fatalf("Find round %d: %v", round, err)
		}
		if got.ACR != stepped.ACR {
			t.Fatalf("round %d: ACR = %q after a Touch racing a step-up, want %q — the extension wrote "+
				"back the snapshot it read and undid the step-up", round, got.ACR, stepped.ACR)
		}
		if got.ChooserGroupID != stepped.ChooserGroupID {
			t.Fatalf("round %d: ChooserGroupID = %q after Touch, want %q — Touch is not a replacement "+
				"of the record", round, got.ChooserGroupID, stepped.ChooserGroupID)
		}
		assertChooserGroupHolds(t, sessions, stepped.ChooserGroupID, id)
		assertChooserGroupOmits(t, sessions, original.ChooserGroupID, id)
	}
}

// raceSaveAndTouch runs one record-level Save and one idle-timer
// extension at the same session, holding both goroutines at a barrier so
// they enter the store together.
func raceSaveAndTouch(
	sessions store.SessionStore,
	sess *store.Session,
	expiresAt, updatedAt time.Time,
) (saveErr, touchErr error) {
	ctx := context.Background()
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(2)
	done.Add(2)
	go func() {
		defer done.Done()
		ready.Done()
		<-start
		saveErr = sessions.Save(ctx, sess)
	}()
	go func() {
		defer done.Done()
		ready.Done()
		<-start
		touchErr = sessions.Touch(ctx, sess.ID, expiresAt, updatedAt)
	}()
	ready.Wait()
	close(start)
	done.Wait()
	return saveErr, touchErr
}

// assertChooserGroupHolds asserts that the chooser-group index lists id.
func assertChooserGroupHolds(t *testing.T, sessions store.SessionStore, groupID, id string) {
	t.Helper()
	listed, err := sessions.ListByChooserGroup(context.Background(), groupID)
	if err != nil {
		t.Fatalf("ListByChooserGroup(%q): %v", groupID, err)
	}
	for _, sess := range listed {
		if sess.ID == id {
			return
		}
	}
	t.Fatalf("session %q is missing from chooser group %q: the index no longer follows the record", id, groupID)
}

// assertChooserGroupOmits asserts that the chooser-group index does not
// list id. A stale entry is what a whole-record write leaves behind: the
// group the session was moved out of keeps offering it in the account
// chooser.
func assertChooserGroupOmits(t *testing.T, sessions store.SessionStore, groupID, id string) {
	t.Helper()
	listed, err := sessions.ListByChooserGroup(context.Background(), groupID)
	if err != nil {
		t.Fatalf("ListByChooserGroup(%q): %v", groupID, err)
	}
	for _, sess := range listed {
		if sess.ID == id {
			t.Fatalf("session %q is still listed under the chooser group %q it was moved out of", id, groupID)
		}
	}
}

// sessionSaveReplacesWithPastDated pins what [store.SessionStore.Save]
// owes the caller when the record it is handed is already past its
// ExpiresAt: whatever the id held before must not survive it.
//
// Ending a session out of band is the reason this matters. An embedder
// that terminates one by storing it with an expiry in the past reads a
// nil error, and on a backend that quietly drops the write the earlier,
// still-authenticated record stays exactly where it was. The next
// prompt=none authorization succeeds silently for a subject the operator
// believes was signed out.
//
// Dropping the write is only equivalent to replacing it when the id held
// nothing live to begin with, which is why the case seeds one first.
func sessionSaveReplacesWithPastDated(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	sessions := b.Store.Sessions()

	live := newSession(b.Now(), "s-save-past-dated")
	if err := sessions.Save(ctx, live); err != nil {
		t.Fatalf("Save live: %v", err)
	}
	ended := newSession(b.Now(), live.ID)
	ended.ExpiresAt = b.Now().Add(-time.Hour)
	if err := sessions.Save(ctx, ended); err != nil {
		t.Fatalf("Save past-dated over a live record: %v", err)
	}
	if _, err := sessions.Find(ctx, live.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after a past-dated Save: want ErrNotFound, got %v — the earlier record survived "+
			"the write that was meant to replace it, and the subject is still signed in", err)
	}
	assertChooserGroupOmits(t, sessions, live.ChooserGroupID, live.ID)
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

// sessionListByChooserGroupFollowsTheRecord pins which of the two
// possible sources of truth answers ListByChooserGroup: a session that
// moved to another group MUST NOT come back under the group it left,
// however the backend maintains whatever secondary index it keeps. A
// backend that lists from the index alone returns the session under
// both groups the moment one index write is lost, and what the caller
// does with that list is offer the accounts in a browser's chooser and
// sign them all out together — so the failure hands one browser another
// account's subject, and lets a sign-out-everywhere reach a session
// that is not part of that group.
func sessionListByChooserGroupFollowsTheRecord(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	s := newSession(b.Now(), "s-moved")
	s.ChooserGroupID = "cg-left"
	if err := b.Store.Sessions().Save(ctx, s); err != nil {
		t.Fatalf("Save into the original group: %v", err)
	}
	moved := *s
	moved.ChooserGroupID = "cg-joined"
	moved.UpdatedAt = b.Now().Add(time.Minute)
	if err := b.Store.Sessions().Save(ctx, &moved); err != nil {
		t.Fatalf("Save into the new group: %v", err)
	}

	left, err := b.Store.Sessions().ListByChooserGroup(ctx, "cg-left")
	if err != nil {
		t.Fatalf("ListByChooserGroup(left group): %v", err)
	}
	for _, got := range left {
		if got.ID == s.ID {
			t.Errorf("session %q still listed under the group it left (ChooserGroupID=%q)",
				got.ID, got.ChooserGroupID)
		}
	}
	joined, err := b.Store.Sessions().ListByChooserGroup(ctx, "cg-joined")
	if err != nil {
		t.Fatalf("ListByChooserGroup(new group): %v", err)
	}
	if len(joined) != 1 || joined[0].ID != s.ID {
		t.Fatalf("ListByChooserGroup(new group) = %+v, want exactly %q", joined, s.ID)
	}
}

// --- PushedAuthRequestStore --------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var parCases = []subtest{
	{"SaveFind", parSaveFind},
	{"ConsumeOnce", parConsumeOnce},
	{"Expired", parExpired},
	{"ConsumeExpiredStillRedeems", parConsumeExpiredStillRedeems},
	{"ConsumeSurvivesUnrelatedPushes", parConsumeSurvivesUnrelatedPushes},
}

// parUnrelatedPushes is how many unrelated records the churn case
// writes while one login is in progress. Backends that reclaim rows on
// an amortised sweep run it once a fixed number of writes has
// accumulated, so the count is set well above any such interval: a
// smaller number could stop short of a reclamation boundary and report
// a pass without ever having crossed one.
const parUnrelatedPushes = 256

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
	replay, err := b.Store.PushedAuthRequests().Consume(ctx, "urn:par:2")
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
	// The record carries the pushed authorization request. Returning it
	// alongside the replay error would leave a caller that mishandles
	// the error holding a usable request, so the contract withholds it.
	if replay != nil {
		t.Errorf("second Consume returned a record alongside ErrAlreadyConsumed: %+v", replay)
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

// parConsumeSurvivesUnrelatedPushes pins the reclamation half of the
// single-use-only Consume contract: whatever a backend does to bound
// its storage, it may only retire records its own Consume already
// rejects. An unconsumed record therefore stays redeemable however far
// its short lifetime is behind and however many unrelated pushes have
// arrived since. A backend that reclaims on expiry alone answers the
// authorization endpoint with ErrNotFound at code emission, turning a
// login the user completed into access_denied — intermittently, and
// only under push load.
func parConsumeSurvivesUnrelatedPushes(t *testing.T, f Factory) {
	b := f(t)
	if b.Advance == nil {
		t.Skip("backend supplies no Advance hook")
	}
	ctx := context.Background()
	par := newPAR(b.Now(), "urn:par:slow-login")
	if err := b.Store.PushedAuthRequests().Save(ctx, par); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The user takes longer over password, second factor and consent
	// than the request_uri lifetime, while other clients keep pushing.
	b.Advance(5 * time.Minute)
	for i := range parUnrelatedPushes {
		unrelated := newPAR(b.Now(), "urn:par:unrelated-"+strconv.Itoa(i))
		if err := b.Store.PushedAuthRequests().Save(ctx, unrelated); err != nil {
			t.Fatalf("Save unrelated push #%d: %v", i, err)
		}
	}

	got, err := b.Store.PushedAuthRequests().Consume(ctx, "urn:par:slow-login")
	if err != nil {
		t.Fatalf("Consume after %d unrelated pushes: want success, got %v", parUnrelatedPushes, err)
	}
	if got.ConsumedAt == nil {
		t.Fatal("Consume returned ConsumedAt=nil")
	}
	if _, err := b.Store.PushedAuthRequests().Consume(ctx, "urn:par:slow-login"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
}

// --- InteractionStore --------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var interactionCases = []subtest{
	{"SaveFind", interactionSaveFind},
	{"SaveReplacesPastDatedRecord", interactionSaveReplacesWithPastDated},
	{"CompareAndSwap", interactionCompareAndSwap},
	{"CompareAndSwapToIdenticalState", interactionCompareAndSwapIdentical},
	{"ConcurrentCompareAndSwapHasOneWinner", interactionConcurrentCAS},
	{"ConcurrentDeleteIfUnchangedHasOneWinner", interactionConcurrentDeleteIfUnchanged},
	{"Delete", interactionDelete},
	{"DeleteExpired", interactionDeleteExpired},
	{"Expired", interactionExpired},
}

// interactionConcurrentCAS and interactionConcurrentDeleteIfUnchanged
// funnel the harness's [Factory] into the free-standing helpers so the
// suite drives them automatically. The helpers are exported because a
// volatile backend that hosts interactions and nothing else reaches the
// contract through [RunInteractions] or through them directly.
func interactionConcurrentCAS(t *testing.T, f Factory) {
	b := f(t)
	AssertConcurrentInteractionCAS(t, b.Store.Interactions(), b.Now())
}

func interactionConcurrentDeleteIfUnchanged(t *testing.T, f Factory) {
	b := f(t)
	AssertConcurrentInteractionDelete(t, b.Store.Interactions(), b.Now())
}

// interactionCompareAndSwapIdentical pins that a swap whose replacement
// equals what is stored still reports success.
//
// The idempotent write is what a retried interaction step looks like: a
// browser resubmits the form, the driver recomputes the same state, and
// the swap it issues changes no column. A backend that reads its verdict
// off an affected-row count sees zero changed rows for it — MySQL counts
// changed rows rather than matched ones — and reports ErrConflict, which
// the driver reads as another tab having taken the interaction over. The
// user is bounced out of a flow nothing else was touching.
func interactionCompareAndSwapIdentical(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	cas, ok := b.Store.Interactions().(store.InteractionStoreCAS)
	if !ok {
		t.Fatal("InteractionStore must implement InteractionStoreCAS")
	}
	original := newInteraction(b.Now(), "i-cas-identical")
	if err := cas.Save(ctx, original); err != nil {
		t.Fatalf("Save: %v", err)
	}
	stored, err := cas.Find(ctx, original.ID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	next := *stored
	for attempt := 1; attempt <= 2; attempt++ {
		if err := cas.CompareAndSwap(ctx, stored, &next); err != nil {
			t.Fatalf("CompareAndSwap onto an identical replacement (attempt %d): want success, got %v", attempt, err)
		}
	}
	got, err := cas.Find(ctx, original.ID)
	if err != nil {
		t.Fatalf("Find after the identical swap: %v", err)
	}
	if !bytes.Equal(got.RawState, stored.RawState) {
		t.Fatalf("RawState = %q after an identical swap, want %q", got.RawState, stored.RawState)
	}
}

// interactionSaveReplacesWithPastDated is
// [sessionSaveReplacesWithPastDated] for the interaction record: an
// interaction stored with an expiry already behind the clock replaces
// whatever the id held, and a backend that drops the write leaves the
// earlier state resolvable for the rest of its lifetime.
func interactionSaveReplacesWithPastDated(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	interactions := b.Store.Interactions()

	live := newInteraction(b.Now(), "i-save-past-dated")
	if err := interactions.Save(ctx, live); err != nil {
		t.Fatalf("Save live: %v", err)
	}
	ended := newInteraction(b.Now(), live.ID)
	ended.RawState = []byte(`{"step":"done"}`)
	ended.ExpiresAt = b.Now().Add(-time.Hour)
	if err := interactions.Save(ctx, ended); err != nil {
		t.Fatalf("Save past-dated over a live record: %v", err)
	}
	if _, err := interactions.Find(ctx, live.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after a past-dated Save: want ErrNotFound, got %v — the earlier state survived "+
			"the write that was meant to replace it", err)
	}
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
	{"ConcurrentMarkHasOneWinner", jtiConcurrentMark},
	{"ExpiredMarkerCanBeReplaced", jtiExpiredMarkerCanBeReplaced},
	{"ExpiryBoundIsInclusive", jtiExpiryBoundIsInclusive},
	{"ZeroExpiryPersists", jtiZeroExpiryPersists},
}

// jtiConcurrentMark funnels the harness's [Factory] into the
// free-standing [AssertConcurrentJTIMark] helper so the suite drives the
// replay marker's atomicity automatically. The helper is exported for
// the volatile backends that host consumed JTIs and little else.
func jtiConcurrentMark(t *testing.T, f Factory) {
	b := f(t)
	AssertConcurrentJTIMark(t, b.Store.ConsumedJTIs(), b.Now())
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

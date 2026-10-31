package contract

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- RefreshTokenStore -------------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var refreshCases = []subtest{
	{"SaveFindConsume", refreshSaveFindConsume},
	{"ParentIDRoundTrip", refreshParentIDRoundTrip},
	{"RevokeChain", refreshRevokeChain},
	{"RevokeChainMissing", refreshRevokeChainMissing},
	{"RevokeByGrant", refreshRevokeByGrant},
	{"RetryResponse", refreshRetryResponse},
	{"RetryResponseDiesWithPredecessor", refreshRetryResponseDiesWithPredecessor},
	{"RetryRotationOntoAbsentParent", refreshRetryRotationOntoAbsentParent},
	{"Expired", refreshExpired},
	{"SaveOntoRevokedParent", refreshSaveOntoRevokedParent},
}

// refreshSaveOntoRevokedParent pins the rule declared on
// [store.RefreshTokenStore.Save]: a rotation whose parent has already been
// tombstoned by a replay cascade MUST be refused with
// [store.ErrAlreadyConsumed], and the descendant MUST NOT be redeemable
// afterwards. A backend that answered nil here would hand the client a
// refresh token belonging to a chain RFC 9700 §2.2.2 requires to be dead,
// and the caller has no way to notice.
func refreshSaveOntoRevokedParent(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	root := newRefresh(b.Now(), "revoked-parent-root", nil)
	if err := b.Store.RefreshTokens().Save(ctx, root); err != nil {
		t.Fatalf("Save root: %v", err)
	}
	if err := b.Store.RefreshTokens().RevokeChain(ctx, root.ID); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	child := newRefresh(b.Now(), "revoked-parent-child", &root.ID)
	err := b.Store.RefreshTokens().Save(ctx, child)
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Save onto revoked parent: want ErrAlreadyConsumed, got %v", err)
	}
	assertRevoked(t, b.Store, child.ID)
}

func refreshSaveFindConsume(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	rt := newRefresh(b.Now(), "rt-1", nil)
	rt.Claims = recordedClaimsRequest()
	rt.AuthorizationRecorded = true
	rt.ChainID = "chain-1"
	if err := b.Store.RefreshTokens().Save(ctx, rt); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := b.Store.RefreshTokens().Find(ctx, "rt-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != "rt-1" {
		t.Fatalf("unexpected token: %+v", got)
	}
	assertRefreshContext(t, got, rt)
	// A backend whose opaque substore retires by chain relies on the
	// refresh row carrying its chain; one that does not falls back to the
	// grant and may drop the field.
	if _, chained := b.Store.OpaqueAccessTokens().(store.OpaqueAccessTokenChainRevoker); chained && got.ChainID != rt.ChainID {
		t.Fatalf("ChainID=%q want %q", got.ChainID, rt.ChainID)
	}
	consumed, err := b.Store.RefreshTokens().Consume(ctx, "rt-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	assertRefreshContext(t, consumed, rt)
	if consumed.ConsumedAt == nil {
		t.Fatal("Consume returned ConsumedAt=nil")
	}
	replayed, err := b.Store.RefreshTokens().Consume(ctx, "rt-1")
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("second Consume: want ErrAlreadyConsumed, got %v", err)
	}
	if replayed == nil {
		t.Fatal("second Consume returned nil record with ErrAlreadyConsumed")
	}
	assertRefreshContext(t, replayed, rt)
	if replayed.ConsumedAt == nil {
		t.Fatal("second Consume returned ConsumedAt=nil")
	}
}

func assertRefreshContext(t *testing.T, got, want *store.RefreshToken) {
	t.Helper()
	if got.SubjectPublic != want.SubjectPublic {
		t.Fatalf("SubjectPublic=%v want %v", got.SubjectPublic, want.SubjectPublic)
	}
	if got.Resource != want.Resource || got.Origin != want.Origin || got.ACR != want.ACR {
		t.Fatalf("refresh context mismatch: got resource=%q origin=%q acr=%q", got.Resource, got.Origin, got.ACR)
	}
	if !got.AuthTime.Equal(want.AuthTime) {
		t.Fatalf("AuthTime=%v want %v", got.AuthTime, want.AuthTime)
	}
	if !reflect.DeepEqual(got.AMR, want.AMR) {
		t.Fatalf("AMR=%v want %v", got.AMR, want.AMR)
	}
	if !reflect.DeepEqual(got.AuthorizationDetails, want.AuthorizationDetails) {
		t.Fatalf("AuthorizationDetails=%v want %v", got.AuthorizationDetails, want.AuthorizationDetails)
	}
	if !reflect.DeepEqual(got.AccessTokenExtra, want.AccessTokenExtra) {
		t.Fatalf("AccessTokenExtra=%v want %v", got.AccessTokenExtra, want.AccessTokenExtra)
	}
	// A backend may drop the claims request together with its marker
	// (the token endpoint then falls back to the grant), but not one
	// without the other.
	if got.AuthorizationRecorded {
		if !reflect.DeepEqual(got.Claims, want.Claims) {
			t.Fatalf("Claims=%v want %v", got.Claims, want.Claims)
		}
	} else if len(got.Claims) != 0 {
		t.Fatalf("unrecorded row carries Claims=%v", got.Claims)
	}
}

func refreshParentIDRoundTrip(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	root := newRefresh(b.Now(), "root", nil)
	child := newRefresh(b.Now(), "child", strPtr("root"))
	for _, rt := range []*store.RefreshToken{root, child} {
		if err := b.Store.RefreshTokens().Save(ctx, rt); err != nil {
			t.Fatalf("Save %s: %v", rt.ID, err)
		}
	}
	gotChild, err := b.Store.RefreshTokens().Find(ctx, "child")
	if err != nil {
		t.Fatalf("Find child: %v", err)
	}
	if gotChild.ParentID == nil {
		t.Fatal("Find child returned nil ParentID")
	}
	// A returned ParentID is a chain handle, not a bearer credential:
	// hash-on-store backends resolve it through RefreshChainResolver, while
	// backends that return a raw parent pointer round-trip it through Find.
	gotRoot, err := findChainParent(ctx, b.Store.RefreshTokens(), *gotChild.ParentID)
	if err != nil {
		t.Fatalf("resolve(Find(child).ParentID): %v", err)
	}
	if gotRoot.GrantID != root.GrantID || gotRoot.ClientID != root.ClientID {
		t.Fatalf("parent round-trip returned wrong record: %+v want root %+v", gotRoot, root)
	}
	// A backend that hashes IDs on store (implements RefreshChainResolver and
	// therefore returns a one-way digest as ParentID) MUST NOT let that digest
	// be redeemed through the bearer-credential Find: a leaked digest must be
	// inert. Backends that return a raw parent pointer have no such handle to
	// reject, so the check is gated on the optional interface.
	if _, ok := b.Store.RefreshTokens().(store.RefreshChainResolver); ok {
		if _, err := b.Store.RefreshTokens().Find(ctx, *gotChild.ParentID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Find(ParentID digest): want ErrNotFound, got %v — stored handle is redeemable as a credential", err)
		}
	}
	if err := b.Store.RefreshTokens().RevokeChain(ctx, *gotChild.ParentID); err != nil {
		t.Fatalf("RevokeChain(Find(child).ParentID): %v", err)
	}
	assertRevoked(t, b.Store, "child")
}

// findChainParent resolves a chain handle (a value returned as
// [store.RefreshToken.ParentID]) the way the OP's revocation walk does:
// through [store.RefreshChainResolver] when the backend hashes parent pointers,
// otherwise through the generic Find for backends that return raw pointers.
func findChainParent(ctx context.Context, tokens store.RefreshTokenStore, handle string) (*store.RefreshToken, error) {
	if r, ok := tokens.(store.RefreshChainResolver); ok {
		return r.FindByStoredHandle(ctx, handle)
	}
	return tokens.Find(ctx, handle)
}

func refreshRevokeChain(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	root := newRefresh(b.Now(), "root", nil)
	mid := newRefresh(b.Now(), "mid", strPtr("root"))
	leaf := newRefresh(b.Now(), "leaf", strPtr("mid"))
	other := newRefresh(b.Now(), "other", nil)
	for _, rt := range []*store.RefreshToken{root, mid, leaf, other} {
		if err := b.Store.RefreshTokens().Save(ctx, rt); err != nil {
			t.Fatalf("Save %s: %v", rt.ID, err)
		}
	}
	if err := b.Store.RefreshTokens().RevokeChain(ctx, "root"); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	for _, id := range []string{"root", "mid", "leaf"} {
		assertRevoked(t, b.Store, id)
	}
	got, err := b.Store.RefreshTokens().Find(ctx, "other")
	if err != nil {
		t.Fatalf("Find other: %v", err)
	}
	if got.ConsumedAt != nil {
		t.Fatalf("unrelated token revoked: %+v", got)
	}
}

func refreshRevokeChainMissing(t *testing.T, f Factory) {
	b := f(t)
	err := b.Store.RefreshTokens().RevokeChain(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RevokeChain missing: want ErrNotFound, got %v", err)
	}
}

func refreshRevokeByGrant(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	targetA := newRefresh(b.Now(), "grant-target-a", nil)
	targetA.GrantID = "grant-target"
	targetB := newRefresh(b.Now(), "grant-target-b", nil)
	targetB.GrantID = "grant-target"
	other := newRefresh(b.Now(), "grant-other", nil)
	other.GrantID = "grant-other"
	for _, rt := range []*store.RefreshToken{targetA, targetB, other} {
		if err := b.Store.RefreshTokens().Save(ctx, rt); err != nil {
			t.Fatalf("Save %s: %v", rt.ID, err)
		}
	}

	if err := b.Store.RefreshTokens().RevokeByGrant(ctx, "grant-target"); err != nil {
		t.Fatalf("RevokeByGrant: %v", err)
	}
	assertRevoked(t, b.Store, targetA.ID)
	assertRevoked(t, b.Store, targetB.ID)
	assertRefreshLive(t, b.Store, other.ID)
	if err := b.Store.RefreshTokens().RevokeByGrant(ctx, "grant-absent"); err != nil {
		t.Fatalf("RevokeByGrant absent: %v", err)
	}
}

// refreshRetryResponse exercises [store.RefreshRetryResponseStore], the
// durable half of the RFC 9700 delivery grace window. The extension is
// skippable here for the same reason every extension is — a backend that
// cannot make the successor insert and the cache write one operation is
// required not to expose it — but it is not optional in practice: with
// the refresh grant enabled and cookie keys configured, [op.New] refuses
// a store that lacks it.
//
// What the case pins is the association, not the bytes: the sealed
// response is reachable by the *predecessor* the client would present on
// a retry, and a predecessor that never had one reads as ErrNotFound
// rather than as an empty response. A backend that keyed the cache by
// the successor instead would pass every other refresh case and then
// answer a genuine retry with "no retry response", sending the client
// down the replay-revocation path with a token it legitimately holds.
func refreshRetryResponse(t *testing.T, f Factory) {
	b := f(t)
	retry, ok := b.Store.RefreshTokens().(store.RefreshRetryResponseStore)
	if !ok {
		t.Skipf("backend %T does not implement store.RefreshRetryResponseStore", b.Store.RefreshTokens())
	}
	ctx := context.Background()

	predecessor := newRefresh(b.Now(), "rt-retry-parent", nil)
	if err := b.Store.RefreshTokens().Save(ctx, predecessor); err != nil {
		t.Fatalf("Save predecessor: %v", err)
	}
	if _, err := b.Store.RefreshTokens().Consume(ctx, predecessor.ID); err != nil {
		t.Fatalf("Consume predecessor: %v", err)
	}

	sealed := []byte("sealed-token-response")
	successor := newRefresh(b.Now(), "rt-retry-child", &predecessor.ID)
	if err := retry.SaveRotationWithRetry(ctx, successor, sealed); err != nil {
		t.Fatalf("SaveRotationWithRetry: %v", err)
	}

	// The successor is an ordinary refresh token; storing the retry copy
	// alongside it must not change that.
	if _, err := b.Store.RefreshTokens().Find(ctx, successor.ID); err != nil {
		t.Fatalf("Find successor after SaveRotationWithRetry: %v", err)
	}

	got, err := retry.LoadRetryResponse(ctx, predecessor.ID)
	if err != nil {
		t.Fatalf("LoadRetryResponse: %v", err)
	}
	if !bytes.Equal(got, sealed) {
		t.Errorf("LoadRetryResponse = %q, want %q", got, sealed)
	}

	if _, err := retry.LoadRetryResponse(ctx, "rt-retry-absent"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("LoadRetryResponse for an unknown predecessor: want ErrNotFound, got %v", err)
	}
}

// refreshRetryResponseDiesWithPredecessor pins the retention bound
// [store.RefreshRetryResponseStore] puts on the sealed bytes: they may be
// kept no longer than the predecessor's own refresh-token lifetime. Once
// that lifetime is over the predecessor reads as absent everywhere else,
// and a grace window that still answered for it would re-deliver a
// response for a token the endpoint has stopped accepting — and would do
// so out of an encrypted copy the backend was supposed to have let go of.
//
// The bound is the predecessor's alone. A backend that ties retention to
// something coarser — the row's presence in a table swept per grant, the
// lifetime of the process — passes every other retry case and still
// serves the response for as long as an unrelated sibling chain happens
// to live.
//
// Two arrangements reach the same point, because backends differ in
// whether their test clock can be moved: a rotation off a predecessor
// that is already past its expiry, and a live rotation whose predecessor
// expires afterwards. The second runs only when the backend supplies
// [Backend.Advance].
func refreshRetryResponseDiesWithPredecessor(t *testing.T, f Factory) {
	b := f(t)
	retry, ok := b.Store.RefreshTokens().(store.RefreshRetryResponseStore)
	if !ok {
		t.Skipf("backend %T does not implement store.RefreshRetryResponseStore", b.Store.RefreshTokens())
	}
	ctx := context.Background()

	expired := newRefresh(b.Now(), "rt-retry-expired-parent", nil)
	expired.ExpiresAt = b.Now().Add(-time.Hour)
	if err := b.Store.RefreshTokens().Save(ctx, expired); err != nil {
		t.Fatalf("Save expired predecessor: %v", err)
	}
	successor := newRefresh(b.Now(), "rt-retry-expired-child", &expired.ID)
	if err := retry.SaveRotationWithRetry(ctx, successor, []byte("sealed-token-response")); err != nil {
		t.Fatalf("SaveRotationWithRetry onto an expired predecessor: %v", err)
	}
	if _, err := retry.LoadRetryResponse(ctx, expired.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("LoadRetryResponse for a predecessor past its ExpiresAt: want ErrNotFound, got %v — "+
			"the sealed response outlived the token it was cached against", err)
	}

	if b.Advance == nil {
		return
	}
	live := newRefresh(b.Now(), "rt-retry-lapsing-parent", nil)
	if err := b.Store.RefreshTokens().Save(ctx, live); err != nil {
		t.Fatalf("Save live predecessor: %v", err)
	}
	if _, err := b.Store.RefreshTokens().Consume(ctx, live.ID); err != nil {
		t.Fatalf("Consume live predecessor: %v", err)
	}
	sealed := []byte("sealed-token-response")
	rotated := newRefresh(b.Now(), "rt-retry-lapsing-child", &live.ID)
	if err := retry.SaveRotationWithRetry(ctx, rotated, sealed); err != nil {
		t.Fatalf("SaveRotationWithRetry: %v", err)
	}
	// Inside the predecessor's lifetime the retry is exactly what the
	// grace window is for, so the bound must not truncate it early.
	got, err := retry.LoadRetryResponse(ctx, live.ID)
	if err != nil {
		t.Fatalf("LoadRetryResponse inside the predecessor's lifetime: %v", err)
	}
	if !bytes.Equal(got, sealed) {
		t.Fatalf("LoadRetryResponse = %q, want %q", got, sealed)
	}
	b.Advance(25 * time.Hour)
	if _, err := retry.LoadRetryResponse(ctx, live.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("LoadRetryResponse after the predecessor expired: want ErrNotFound, got %v", err)
	}
}

// refreshRetryRotationOntoAbsentParent pins the parity
// [store.RefreshRetryResponseStore.SaveRotationWithRetry] declares with
// [store.RefreshTokenStore.Save]: the two share Save's conflict and
// replay semantics, so a rotation whose parent row is simply gone has to
// reach the same outcome through both.
//
// An absent parent proves no revocation — a chain root swept by GC, or
// one this backend never stored — so the rotation is kept. The retry
// cache is the optional half of the operation: there is no predecessor
// row to hang it on, and [store.RefreshRetryResponseStore.LoadRetryResponse]
// already answers ErrNotFound for a predecessor that never had one. A
// backend that fails the whole call because the cache found nothing to
// attach itself to loses a rotation the plain Save would have kept, and
// the client's refresh returns a storage error instead of tokens.
func refreshRetryRotationOntoAbsentParent(t *testing.T, f Factory) {
	b := f(t)
	retry, ok := b.Store.RefreshTokens().(store.RefreshRetryResponseStore)
	if !ok {
		t.Skipf("backend %T does not implement store.RefreshRetryResponseStore", b.Store.RefreshTokens())
	}
	ctx := context.Background()

	absent := "rt-absent-parent"
	// The plain Save is asserted first so the case reports the parity it
	// is about: the two calls differ only in whether a cache rides along.
	plain := newRefresh(b.Now(), "rt-absent-parent-plain", &absent)
	if err := b.Store.RefreshTokens().Save(ctx, plain); err != nil {
		t.Fatalf("Save onto an absent parent: want success, got %v", err)
	}
	successor := newRefresh(b.Now(), "rt-absent-parent-child", &absent)
	if err := retry.SaveRotationWithRetry(ctx, successor, []byte("sealed-token-response")); err != nil {
		t.Fatalf("SaveRotationWithRetry onto an absent parent: want the same success Save reports, got %v", err)
	}
	if _, err := b.Store.RefreshTokens().Find(ctx, successor.ID); err != nil {
		t.Fatalf("Find the rotated successor: %v — the rotation was rolled back because its retry "+
			"cache had no predecessor row to attach to", err)
	}
}

// refreshExpired pins the normative rule declared on
// [store.RefreshTokenStore.Find] and [store.RefreshTokenStore.Consume]:
// a token whose ExpiresAt has already passed MUST read as ErrNotFound,
// never as a live or already-consumed record. A backend that surfaces
// an expired token as replayable would let an expired-token presentation
// trigger a false replay-revocation cascade against the token's siblings.
func refreshExpired(t *testing.T, f Factory) {
	b := f(t)
	ctx := context.Background()
	rt := newRefresh(b.Now(), "rt-exp", nil)
	rt.ExpiresAt = b.Now().Add(-time.Hour)
	if err := b.Store.RefreshTokens().Save(ctx, rt); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := b.Store.RefreshTokens().Find(ctx, "rt-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find expired: want ErrNotFound, got %v", err)
	}
	if _, err := b.Store.RefreshTokens().Consume(ctx, "rt-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume expired: want ErrNotFound, got %v", err)
	}
}

// assertRevoked asserts that a refresh token is either absent or has
// ConsumedAt set. The contract permits backends to delete or to mark.
func assertRevoked(t *testing.T, s store.Store, id string) {
	t.Helper()
	got, err := s.RefreshTokens().Find(context.Background(), id)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		t.Fatalf("Find %s: %v", id, err)
	}
	if got.ConsumedAt == nil {
		t.Fatalf("token %s expected revoked, got ConsumedAt=nil", id)
	}
}

func assertRefreshLive(t *testing.T, s store.Store, id string) {
	t.Helper()
	got, err := s.RefreshTokens().Find(context.Background(), id)
	if err != nil {
		t.Fatalf("Find %s: %v", id, err)
	}
	if got.ConsumedAt != nil || got.Revoked {
		t.Fatalf("token %s unexpectedly revoked: %+v", id, got)
	}
}

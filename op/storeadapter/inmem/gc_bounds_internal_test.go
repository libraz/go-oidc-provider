package inmem

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

// The sweeps in this file are asserted on map length rather than on
// heap statistics: the property under test is that the substore stops
// retaining dead records, and only the map length states that
// directly. A heap measurement would additionally depend on when the
// runtime happens to collect.

// churn is how many records each bound test drives through a substore.
// It is a multiple of the sweep interval so the assertion sees several
// sweeps rather than a single boundary crossing.
const churn = 4 * int(authCodeFullGCSaveInterval)

func TestAuthCodeStore_DirectSaveStaysBounded(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()

	for i := range churn {
		if err := s.authCodes.Save(ctx, &store.AuthorizationCode{
			ID:        "expired-code-" + strconv.Itoa(i),
			ClientID:  "client-1",
			Subject:   "subject-1",
			ExpiresAt: clk.now.Add(-time.Second),
			CreatedAt: clk.now.Add(-time.Minute),
		}); err != nil {
			t.Fatalf("Save #%d: %v", i, err)
		}
	}

	if got := len(s.authCodes.m); got >= int(authCodeFullGCSaveInterval) {
		t.Fatalf("authorization-code map holds %d records after %d expired saves; "+
			"an unauthenticated /authorize loop must not grow it without bound", got, churn)
	}
}

func TestAuthCodeStore_TransactionalSaveStaysBounded(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()

	// The browser flow persists codes through a transaction, so the
	// bound has to hold on the commit path too.
	for i := range churn {
		tx, err := s.BeginTx(ctx)
		if err != nil {
			t.Fatalf("BeginTx #%d: %v", i, err)
		}
		if err := tx.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
			ID:        "tx-expired-code-" + strconv.Itoa(i),
			ClientID:  "client-1",
			Subject:   "subject-1",
			ExpiresAt: clk.now.Add(-time.Second),
			CreatedAt: clk.now.Add(-time.Minute),
		}); err != nil {
			t.Fatalf("tx Save #%d: %v", i, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("Commit #%d: %v", i, err)
		}
	}

	if got := len(s.authCodes.m); got >= int(authCodeFullGCSaveInterval) {
		t.Fatalf("authorization-code map holds %d records after %d committed expired saves", got, churn)
	}
}

func TestAuthCodeStore_SweepKeepsLiveCodes(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()

	if err := s.authCodes.Save(ctx, &store.AuthorizationCode{
		ID:        "live-code",
		ClientID:  "client-1",
		Subject:   "subject-1",
		ExpiresAt: clk.now.Add(time.Hour),
		CreatedAt: clk.now,
	}); err != nil {
		t.Fatalf("Save live: %v", err)
	}
	for i := range churn {
		if err := s.authCodes.Save(ctx, &store.AuthorizationCode{
			ID:        "expired-code-" + strconv.Itoa(i),
			ClientID:  "client-1",
			Subject:   "subject-1",
			ExpiresAt: clk.now.Add(-time.Second),
			CreatedAt: clk.now.Add(-time.Minute),
		}); err != nil {
			t.Fatalf("Save #%d: %v", i, err)
		}
	}

	if _, err := s.authCodes.Find(ctx, "live-code"); err != nil {
		t.Fatalf("Find live code after sweeps: %v (the sweep must only reclaim expired records)", err)
	}
}

func TestSessionStore_SaveStaysBounded(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()

	if err := s.sessions.Save(ctx, &store.Session{
		ID:        "live-session",
		Subject:   "subject-1",
		ExpiresAt: clk.now.Add(time.Hour),
		CreatedAt: clk.now,
		UpdatedAt: clk.now,
	}); err != nil {
		t.Fatalf("Save live: %v", err)
	}
	for i := range churn {
		if err := s.sessions.Save(ctx, &store.Session{
			ID:        "expired-session-" + strconv.Itoa(i),
			Subject:   "subject-1",
			ExpiresAt: clk.now.Add(-time.Second),
			CreatedAt: clk.now.Add(-time.Minute),
			UpdatedAt: clk.now.Add(-time.Minute),
		}); err != nil {
			t.Fatalf("Save #%d: %v", i, err)
		}
	}

	if got := len(s.sessions.m); got >= int(sessionFullGCSaveInterval) {
		t.Fatalf("session map holds %d records after %d expired saves", got, churn)
	}
	if _, err := s.sessions.Find(ctx, "live-session"); err != nil {
		t.Fatalf("Find live session after sweeps: %v", err)
	}
}

func TestInteractionStore_SaveStaysBounded(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()

	if err := s.interactions.Save(ctx, &store.Interaction{
		ID:        "live-interaction",
		ClientID:  "client-1",
		ExpiresAt: clk.now.Add(time.Hour),
		CreatedAt: clk.now,
		UpdatedAt: clk.now,
	}); err != nil {
		t.Fatalf("Save live: %v", err)
	}
	for i := range churn {
		if err := s.interactions.Save(ctx, &store.Interaction{
			ID:        "expired-interaction-" + strconv.Itoa(i),
			ClientID:  "client-1",
			ExpiresAt: clk.now.Add(-time.Second),
			CreatedAt: clk.now.Add(-time.Minute),
			UpdatedAt: clk.now.Add(-time.Minute),
		}); err != nil {
			t.Fatalf("Save #%d: %v", i, err)
		}
	}

	if got := len(s.interactions.m); got >= int(interactionFullGCSaveInterval) {
		t.Fatalf("interaction map holds %d records after %d expired saves", got, churn)
	}
	if _, err := s.interactions.Find(ctx, "live-interaction"); err != nil {
		t.Fatalf("Find live interaction after sweeps: %v", err)
	}
}

// TestRefreshStore_RetryResponsesStayBounded covers the one map in the
// refresh substore that is swept. The rotation records themselves are
// retained on purpose so a replay cascade can still walk the chain, but
// each sealed retry response is an encrypted token response that nothing
// may read past its predecessor's expiry, so holding them for the life of
// the process would grow the heap by one response per rotation forever.
func TestRefreshStore_RetryResponsesStayBounded(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()

	seedRetryRotation(t, s, clk, "live", clk.now.Add(time.Hour))
	for i := range churn {
		seedRetryRotation(t, s, clk, "lapsed-"+strconv.Itoa(i), clk.now.Add(-time.Second))
	}

	if got := len(s.refreshes.retries); got >= int(retryResponseFullGCSaveInterval) {
		t.Fatalf("retry map holds %d sealed responses after %d rotations past their predecessor's expiry; "+
			"an authenticated refresh loop must not grow it without bound", got, churn)
	}
	if _, err := s.refreshes.LoadRetryResponse(ctx, "live"); err != nil {
		t.Fatalf("LoadRetryResponse for a live predecessor after the sweeps: %v "+
			"(the sweep must only reclaim entries the read already refuses)", err)
	}
}

// TestRefreshStore_TransactionalRetryResponsesStayBounded holds the commit
// path to the same bound. The token endpoint rotates inside a transaction,
// so a sweep driven only from the direct write would never run in
// production.
func TestRefreshStore_TransactionalRetryResponsesStayBounded(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()

	for i := range churn {
		id := "tx-lapsed-" + strconv.Itoa(i)
		seedRetryPredecessor(t, s, clk, id, clk.now.Add(-time.Second))
		tx, err := s.BeginTx(ctx)
		if err != nil {
			t.Fatalf("BeginTx #%d: %v", i, err)
		}
		retries, ok := tx.RefreshTokens().(store.RefreshRetryResponseStore)
		if !ok {
			t.Fatalf("tx refresh substore %T does not implement store.RefreshRetryResponseStore", tx.RefreshTokens())
		}
		parent := id
		if err := retries.SaveRotationWithRetry(ctx, &store.RefreshToken{
			ID: id + "-successor", ClientID: "client-1", Subject: "subject-1", GrantID: "grant-1",
			ParentID: &parent, ExpiresAt: clk.now.Add(time.Hour), CreatedAt: clk.now,
		}, []byte("sealed-token-response")); err != nil {
			t.Fatalf("tx SaveRotationWithRetry #%d: %v", i, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("Commit #%d: %v", i, err)
		}
	}

	if got := len(s.refreshes.retries); got >= int(retryResponseFullGCSaveInterval) {
		t.Fatalf("retry map holds %d sealed responses after %d committed rotations past their predecessor's expiry",
			got, churn)
	}
}

// seedRetryPredecessor persists one predecessor record whose expiry the
// caller controls, so a rotation off it can be arranged either inside or
// past the retention bound.
func seedRetryPredecessor(t testing.TB, s *Store, clk *parTestClock, id string, expiresAt time.Time) {
	t.Helper()
	if err := s.refreshes.Save(context.Background(), &store.RefreshToken{
		ID: id, ClientID: "client-1", Subject: "subject-1", GrantID: "grant-1",
		ExpiresAt: expiresAt, CreatedAt: clk.now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("Save predecessor %s: %v", id, err)
	}
}

// seedRetryRotation seeds a predecessor and rotates off it through the
// direct (non-transactional) write, caching a sealed response against it.
func seedRetryRotation(t testing.TB, s *Store, clk *parTestClock, id string, expiresAt time.Time) {
	t.Helper()
	seedRetryPredecessor(t, s, clk, id, expiresAt)
	parent := id
	if err := s.refreshes.SaveRotationWithRetry(context.Background(), &store.RefreshToken{
		ID: id + "-successor", ClientID: "client-1", Subject: "subject-1", GrantID: "grant-1",
		ParentID: &parent, ExpiresAt: clk.now.Add(time.Hour), CreatedAt: clk.now,
	}, []byte("sealed-token-response")); err != nil {
		t.Fatalf("SaveRotationWithRetry %s: %v", id, err)
	}
}

func TestAuthnLockoutStore_SwapStaysBounded(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()
	ls := s.authnLockouts

	// A counter whose lock is still in force must survive every sweep;
	// dropping it would hand the attacker their budget back.
	locked := &store.AuthnLockoutRecord{
		Subject:        "locked-subject",
		FailedCount:    30,
		FirstFailureAt: clk.now.Add(-authnLockoutRetention - time.Hour),
		LockedUntil:    clk.now.Add(time.Hour),
	}
	if ok, err := ls.CompareAndSwap(ctx, 0, locked); err != nil || !ok {
		t.Fatalf("CompareAndSwap locked: ok=%v err=%v", ok, err)
	}
	// So must a counter whose window is still open.
	recent := &store.AuthnLockoutRecord{
		Subject:        "recent-subject",
		FailedCount:    3,
		FirstFailureAt: clk.now.Add(-time.Minute),
	}
	if ok, err := ls.CompareAndSwap(ctx, 0, recent); err != nil || !ok {
		t.Fatalf("CompareAndSwap recent: ok=%v err=%v", ok, err)
	}

	// An attacker probing a username list mints one row per guess.
	for i := range churn {
		stale := &store.AuthnLockoutRecord{
			Subject:        "guessed-subject-" + strconv.Itoa(i),
			FailedCount:    1,
			FirstFailureAt: clk.now.Add(-authnLockoutRetention - time.Hour),
		}
		if ok, err := ls.CompareAndSwap(ctx, 0, stale); err != nil || !ok {
			t.Fatalf("CompareAndSwap stale #%d: ok=%v err=%v", i, ok, err)
		}
	}

	if got := len(ls.m); got >= int(authnLockoutFullGCSwapInterval) {
		t.Fatalf("lockout map holds %d records after %d stale swaps", got, churn)
	}
	if _, err := ls.Get(ctx, "locked-subject"); err != nil {
		t.Fatalf("locked counter was reclaimed: %v", err)
	}
	if _, err := ls.Get(ctx, "recent-subject"); err != nil {
		t.Fatalf("counter inside its window was reclaimed: %v", err)
	}
}

func TestDeviceCodeStore_SaveAmortisesSweep(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()
	ds := s.deviceCodes

	if err := ds.Save(ctx, &store.DeviceCode{
		ID: "expired-1", ClientID: "client-1", UserCode: "EXPD-0001",
		Interval: 5 * time.Second, IssuedAt: clk.now.Add(-time.Hour),
		ExpiresAt: clk.now.Add(-time.Second),
	}); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	// The record is retained until the amortised sweep: a per-Save full
	// scan is what this store is required NOT to do.
	if len(ds.m) != 1 {
		t.Fatalf("after first save len=%d want 1", len(ds.m))
	}

	for i := uint32(1); i < deviceCodeFullGCSaveInterval; i++ {
		n := strconv.Itoa(int(i))
		if err := ds.Save(ctx, &store.DeviceCode{
			ID: "fresh-" + n, ClientID: "client-1", UserCode: "FRSH-" + n,
			Interval: 5 * time.Second, IssuedAt: clk.now,
			ExpiresAt: clk.now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Save fresh #%d: %v", i, err)
		}
	}

	if _, exists := ds.m[hashKey("expired-1")]; exists {
		t.Fatal("expired device code survived the amortised full sweep")
	}
	if _, exists := ds.userCodeIndex["EXPD-0001"]; exists {
		t.Fatal("expired device code left its user_code index entry behind")
	}
	if ds.savesSinceGC != 0 {
		t.Fatalf("savesSinceGC=%d want 0 after sweep", ds.savesSinceGC)
	}
}

func TestDeviceCodeStore_SaveEvictsCollidingUserCode(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()
	ds := s.deviceCodes

	if err := ds.Save(ctx, &store.DeviceCode{
		ID: "old-device-code", ClientID: "client-1", UserCode: "SHARED-01",
		Interval: 5 * time.Second, IssuedAt: clk.now.Add(-time.Hour),
		ExpiresAt: clk.now.Add(-time.Second),
	}); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	// A different device_code reusing the dead user_code must be
	// accepted without waiting for the amortised sweep.
	if err := ds.Save(ctx, &store.DeviceCode{
		ID: "new-device-code", ClientID: "client-1", UserCode: "SHARED-01",
		Interval: 5 * time.Second, IssuedAt: clk.now,
		ExpiresAt: clk.now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save reusing an expired user_code: %v", err)
	}
	got, err := ds.FindByUserCode(ctx, "SHARED-01")
	if err != nil {
		t.Fatalf("FindByUserCode: %v", err)
	}
	if got.ClientID != "client-1" || !got.ExpiresAt.Equal(clk.now.Add(time.Hour)) {
		t.Fatalf("user_code index points at the wrong record: %+v", got)
	}
}

func TestCIBARequestStore_SaveAmortisesSweep(t *testing.T) {
	t.Parallel()

	clk := &parTestClock{now: contract.Reference}
	s := New(WithClock(clk))
	ctx := context.Background()
	cs := s.cibaRequests

	if err := cs.Save(ctx, &store.CIBARequest{
		ID: "expired-1", ClientID: "client-1", Subject: "subject-1",
		Interval: 5 * time.Second, IssuedAt: clk.now.Add(-time.Hour),
		ExpiresAt: clk.now.Add(-time.Second),
	}); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if len(cs.m) != 1 {
		t.Fatalf("after first save len=%d want 1", len(cs.m))
	}

	for i := uint32(1); i < cibaFullGCSaveInterval; i++ {
		n := strconv.Itoa(int(i))
		if err := cs.Save(ctx, &store.CIBARequest{
			ID: "fresh-" + n, ClientID: "client-1", Subject: "subject-1",
			Interval: 5 * time.Second, IssuedAt: clk.now,
			ExpiresAt: clk.now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Save fresh #%d: %v", i, err)
		}
	}

	if _, exists := cs.m[hashKey("expired-1")]; exists {
		t.Fatal("expired CIBA request survived the amortised full sweep")
	}
	if cs.savesSinceGC != 0 {
		t.Fatalf("savesSinceGC=%d want 0 after sweep", cs.savesSinceGC)
	}
}

// TestBeginTx_StagingIsEmptyRegardlessOfStoreSize pins the structural
// property that replaced the per-transaction snapshot: BeginTx builds
// overlays, so the number of entries it materialises is zero no matter
// how many records the committed maps hold. Asserting on entry counts
// rather than on elapsed time keeps the check deterministic.
func TestBeginTx_StagingIsEmptyRegardlessOfStoreSize(t *testing.T) {
	t.Parallel()

	for _, records := range []int{0, 1000} {
		clk := &parTestClock{now: contract.Reference}
		s := New(WithClock(clk))
		ctx := context.Background()
		seedAuxCluster(t, s, records)

		handle, err := s.BeginTx(ctx)
		if err != nil {
			t.Fatalf("BeginTx with %d records: %v", records, err)
		}
		inner, ok := handle.(*tx)
		if !ok {
			t.Fatalf("BeginTx returned %T, want *tx", handle)
		}
		staged := len(inner.atStaging.written) + len(inner.atStaging.deleted) +
			len(inner.oatStaging.written) + len(inner.oatStaging.deleted) +
			len(inner.grvStaging.tombstonesWritten) + len(inner.grvStaging.tombstonesDeleted) +
			len(inner.grvStaging.denylistWritten) + len(inner.grvStaging.denylistDeleted)
		if staged != 0 {
			t.Errorf("BeginTx materialised %d staged entries for a store of %d records; "+
				"the cost of starting a transaction must not scale with the store", staged, records)
		}
		if err := inner.Rollback(); err != nil {
			t.Fatalf("Rollback: %v", err)
		}
	}
}

func seedAuxCluster(t testing.TB, s *Store, records int) {
	t.Helper()
	ctx := context.Background()
	now := contract.Reference
	for i := range records {
		n := strconv.Itoa(i)
		if err := s.accessTokens.Register(ctx, store.AccessTokenRecord{
			JTI: "jti-" + n, GrantID: "grant-" + n, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Register access token #%d: %v", i, err)
		}
		if err := s.opaqueAccessTokens.Save(ctx, &store.OpaqueAccessToken{
			ID: "opaque-" + n, GrantID: "grant-" + n, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Save opaque access token #%d: %v", i, err)
		}
		if err := s.grantRevocations.RevokeGrant(ctx, store.GrantTombstone{
			GrantID: "revoked-" + n, RevokedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("RevokeGrant #%d: %v", i, err)
		}
	}
}

func BenchmarkBeginTx(b *testing.B) {
	for _, records := range []int{0, 100, 10_000} {
		b.Run(strconv.Itoa(records)+"-records", func(b *testing.B) {
			clk := &parTestClock{now: contract.Reference}
			s := New(WithClock(clk))
			ctx := context.Background()
			seedAuxCluster(b, s, records)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				handle, err := s.BeginTx(ctx)
				if err != nil {
					b.Fatalf("BeginTx: %v", err)
				}
				if err := handle.Rollback(); err != nil {
					b.Fatalf("Rollback: %v", err)
				}
			}
		})
	}
}

package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// sweepBound is comfortably above the number of Saves between two
// housekeeping sweeps; a substore that never sweeps fails the bound.
const sweepBound = 200

func openSweepStore(t *testing.T) (*oidcsql.Store, *databasesql.DB, time.Time) {
	t.Helper()
	ctx := context.Background()
	db := openSQLite(t)
	clock := &fixedClock{now: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithClock(clock))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s, db, clock.Now()
}

func countRows(t *testing.T, db *databasesql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// Saves on the device-code substore evict expired rows without a
// scheduler: the expired row is gone after a bounded number of Saves and
// every fresh row survives.
func TestSQLite_DeviceCodeSave_EvictsExpiredRowsWithinSweepInterval(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s, db, now := openSweepStore(t)
	dc := s.DeviceCodes()

	if err := dc.Save(ctx, &store.DeviceCode{
		ID: "expired-device-code", ClientID: "client-1", UserCode: "EXPD-0001",
		Interval: 5 * time.Second, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Save expired device code: %v", err)
	}

	fresh := 0
	for fresh < sweepBound && countRows(t, db, "oidc_device_codes") != fresh {
		fresh++
		if err := dc.Save(ctx, &store.DeviceCode{
			ID: fmt.Sprintf("fresh-%d", fresh), ClientID: "client-1", UserCode: fmt.Sprintf("FRSH-%04d", fresh),
			Interval: 5 * time.Second, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Save fresh device code: %v", err)
		}
	}
	if got := countRows(t, db, "oidc_device_codes"); got != fresh {
		t.Fatalf("expired row not evicted within %d Saves: %d rows, want %d", sweepBound, got, fresh)
	}
}

// A Save whose user_code is held by an expired row reclaims the slot
// immediately; a live holder still reports ErrAlreadyExists.
func TestSQLite_DeviceCodeSave_ReclaimsExpiredUserCode(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s, _, now := openSweepStore(t)
	dc := s.DeviceCodes()

	save := func(id, userCode string, expires time.Time) error {
		return dc.Save(ctx, &store.DeviceCode{
			ID: id, ClientID: "client-1", UserCode: userCode,
			Interval: 5 * time.Second, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: expires,
		})
	}
	// The first Save of a store runs the pacing sweep; burn it so the
	// collision below is resolved by the retry path alone.
	if err := save("warmup", "WARM-0001", now.Add(time.Hour)); err != nil {
		t.Fatalf("warmup Save: %v", err)
	}
	if err := save("dead", "SHARED-1", now.Add(-time.Hour)); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if err := save("alive", "SHARED-1", now.Add(time.Hour)); err != nil {
		t.Fatalf("Save over expired user_code: %v", err)
	}
	got, err := dc.FindByUserCode(ctx, "SHARED-1")
	if err != nil {
		t.Fatalf("FindByUserCode: %v", err)
	}
	if got.ExpiresAt.Before(now) {
		t.Fatalf("FindByUserCode returned the expired holder: %+v", got)
	}
	if err := save("other", "SHARED-1", now.Add(time.Hour)); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("Save over live user_code = %v, want ErrAlreadyExists", err)
	}
}

// Saves on the CIBA-request substore evict expired rows without a
// scheduler: the expired row is gone after a bounded number of Saves and
// every fresh row survives.
func TestSQLite_CIBARequestSave_EvictsExpiredRowsWithinSweepInterval(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s, db, now := openSweepStore(t)
	cr := s.CIBARequests()

	if err := cr.Save(ctx, &store.CIBARequest{
		ID: "expired-auth-req-id", ClientID: "client-1", Subject: "user-1",
		Interval: 5 * time.Second, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Save expired CIBA request: %v", err)
	}

	fresh := 0
	for fresh < sweepBound && countRows(t, db, "oidc_ciba_requests") != fresh {
		fresh++
		if err := cr.Save(ctx, &store.CIBARequest{
			ID: fmt.Sprintf("fresh-%d", fresh), ClientID: "client-1", Subject: "user-2",
			Interval: 5 * time.Second, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Save fresh CIBA request: %v", err)
		}
	}
	if got := countRows(t, db, "oidc_ciba_requests"); got != fresh {
		t.Fatalf("expired row not evicted within %d Saves: %d rows, want %d", sweepBound, got, fresh)
	}
}

// A Save reusing the identifier of an expired CIBA row replaces it.
func TestSQLite_CIBARequestSave_ReclaimsExpiredID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s, _, now := openSweepStore(t)
	cr := s.CIBARequests()

	save := func(id string, expires time.Time) error {
		return cr.Save(ctx, &store.CIBARequest{
			ID: id, ClientID: "client-1", Subject: "user-1",
			Interval: 5 * time.Second, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: expires,
		})
	}
	if err := save("warmup", now.Add(time.Hour)); err != nil {
		t.Fatalf("warmup Save: %v", err)
	}
	if err := save("same", now.Add(-time.Hour)); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if err := save("same", now.Add(time.Hour)); err != nil {
		t.Fatalf("Save over expired id: %v", err)
	}
	if _, err := cr.FindByAuthReqID(ctx, "same"); err != nil {
		t.Fatalf("FindByAuthReqID after reclaim: %v", err)
	}
	if err := save("same", now.Add(time.Hour)); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("Save over live id = %v, want ErrAlreadyExists", err)
	}
}

package oidcsql_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestSQLite_DeviceCodeSave_GCEvictsExpiredRows verifies that calling
// Save on the device-code substore runs gcExpired and removes rows
// whose expires_at is in the past while leaving fresh rows intact.
func TestSQLite_DeviceCodeSave_GCEvictsExpiredRows(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openSQLite(t)
	clock := fixedClock{now: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithClock(clock))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	now := clock.Now()
	dc := s.DeviceCodes()

	// Save an already-expired record (ExpiresAt one hour in the past).
	if err := dc.Save(ctx, &store.DeviceCode{
		ID:        "expired-device-code",
		ClientID:  "client-1",
		UserCode:  "EXPD-0001",
		Scope:     []string{"openid"},
		Interval:  5 * time.Second,
		IssuedAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Save expired device code: %v", err)
	}

	// Confirm the expired row exists before the GC-triggering Save.
	var countBefore int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM oidc_device_codes").Scan(&countBefore); err != nil {
		t.Fatalf("count before: %v", err)
	}
	if countBefore != 1 {
		t.Fatalf("expected 1 row before second Save, got %d", countBefore)
	}

	// Save a fresh record. This triggers gcExpired inside Save, which
	// must delete the expired row above.
	if err := dc.Save(ctx, &store.DeviceCode{
		ID:        "fresh-device-code",
		ClientID:  "client-1",
		UserCode:  "FRSH-0001",
		Scope:     []string{"openid"},
		Interval:  5 * time.Second,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save fresh device code: %v", err)
	}

	// Only the fresh row must survive.
	var countAfter int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM oidc_device_codes").Scan(&countAfter); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if countAfter != 1 {
		t.Fatalf("expected 1 row after GC-triggering Save, got %d (expired row not evicted)", countAfter)
	}

	// Confirm the surviving row is the fresh one, not the expired one.
	var userCode string
	if err := db.QueryRowContext(ctx,
		"SELECT user_code FROM oidc_device_codes").Scan(&userCode); err != nil {
		t.Fatalf("read surviving user_code: %v", err)
	}
	if userCode != "FRSH-0001" {
		t.Fatalf("surviving row has user_code %q, want FRSH-0001", userCode)
	}
}

// TestSQLite_CIBARequestSave_GCEvictsExpiredRows verifies that calling
// Save on the CIBA-request substore runs gcExpired and removes rows
// whose expires_at is in the past while leaving fresh rows intact.
func TestSQLite_CIBARequestSave_GCEvictsExpiredRows(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openSQLite(t)
	clock := fixedClock{now: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithClock(clock))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	now := clock.Now()
	cr := s.CIBARequests()

	// Save an already-expired record (ExpiresAt one hour in the past).
	if err := cr.Save(ctx, &store.CIBARequest{
		ID:        "expired-auth-req-id",
		ClientID:  "client-1",
		Subject:   "user-1",
		Scope:     []string{"openid"},
		Interval:  5 * time.Second,
		IssuedAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Save expired CIBA request: %v", err)
	}

	// Confirm the expired row exists before the GC-triggering Save.
	var countBefore int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM oidc_ciba_requests").Scan(&countBefore); err != nil {
		t.Fatalf("count before: %v", err)
	}
	if countBefore != 1 {
		t.Fatalf("expected 1 row before second Save, got %d", countBefore)
	}

	// Save a fresh record. This triggers gcExpired inside Save, which
	// must delete the expired row above.
	if err := cr.Save(ctx, &store.CIBARequest{
		ID:        "fresh-auth-req-id",
		ClientID:  "client-1",
		Subject:   "user-2",
		Scope:     []string{"openid"},
		Interval:  5 * time.Second,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save fresh CIBA request: %v", err)
	}

	// Only the fresh row must survive.
	var countAfter int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM oidc_ciba_requests").Scan(&countAfter); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if countAfter != 1 {
		t.Fatalf("expected 1 row after GC-triggering Save, got %d (expired row not evicted)", countAfter)
	}

	// Confirm the surviving row is the fresh one, not the expired one.
	var subject string
	if err := db.QueryRowContext(ctx,
		"SELECT subject FROM oidc_ciba_requests").Scan(&subject); err != nil {
		t.Fatalf("read surviving subject: %v", err)
	}
	if subject != "user-2" {
		t.Fatalf("surviving row has subject %q, want user-2", subject)
	}
}

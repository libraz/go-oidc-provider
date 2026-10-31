package oidcsql_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestRunGC_SweepsAtStartAndStopsWithContext pins that RunGC sweeps
// before its first tick, cuts off at the adapter clock, reports the
// sweep, and returns nil once the context is cancelled.
func TestRunGC_SweepsAtStartAndStopsWithContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := contract.Reference
	s, err := oidcsql.New(openSQLite(t), oidcsql.SQLite(), oidcsql.WithClock(&fixedClock{now: base}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI: "urn:par:expired", ClientID: "c", RawParams: []byte("a=b"),
		ExpiresAt: base.Add(-time.Minute), CreatedAt: base.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("save par: %v", err)
	}

	reports := make(chan oidcsql.GCStats, 1)
	done := make(chan error, 1)
	go func() {
		done <- s.RunGC(ctx, time.Hour, func(stats oidcsql.GCStats, err error) {
			if err != nil {
				t.Errorf("sweep: %v", err)
			}
			reports <- stats
		})
	}()

	select {
	case stats := <-reports:
		if stats.PushedAuthRequests != 1 {
			t.Fatalf("first sweep deleted %d PAR rows, want 1", stats.PushedAuthRequests)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunGC did not sweep before its first tick")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunGC returned %v after cancellation, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunGC did not return after cancellation")
	}
}

func TestRunGC_RejectsNonPositiveInterval(t *testing.T) {
	t.Parallel()

	s, err := oidcsql.New(openSQLite(t), oidcsql.SQLite())
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.RunGC(context.Background(), 0, nil); err == nil {
		t.Fatal("RunGC accepted a zero interval")
	}
}

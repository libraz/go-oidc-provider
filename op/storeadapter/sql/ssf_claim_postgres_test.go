//go:build testcontainers

package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// ssfClaimBacklog is the due backlog queued ahead of the other streams.
const ssfClaimBacklog = 300

// TestPostgres_SSFClaimDueReadsNoBacklogPastAStreamsShare queues one
// stream's large due backlog ahead of two other streams' due events and
// counts, from the server's own statistics, the tuples a claim taking one
// event per stream reads from the queue table: a few per stream, not the
// backlog it passes over.
func TestPostgres_SSFClaimDueReadsNoBacklogPastAStreamsShare(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := newPostgresDBFactory(t)(t)
	// One backend, so its statistics can be flushed and read back.
	db.SetMaxOpenConns(1)
	s, err := oidcsql.New(db, oidcsql.Postgres(), oidcsql.WithClock(&fixedClock{now: contract.Reference}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	events := s.SSFEvents()
	for i := range ssfClaimBacklog {
		ev := ssfClaimEvent(fmt.Sprintf("a-%03d", i), "stream-a", contract.Reference.Add(-time.Hour+time.Duration(i)*time.Second))
		if err := events.Enqueue(ctx, ev); err != nil {
			t.Fatalf("Enqueue %s: %v", ev.JTI, err)
		}
	}
	for _, ev := range []*store.SSFEvent{
		ssfClaimEvent("b-0", "stream-b", contract.Reference.Add(-time.Minute)),
		ssfClaimEvent("c-0", "stream-c", contract.Reference.Add(-time.Minute)),
		ssfClaimEvent("c-1", "stream-c", contract.Reference.Add(-time.Second)),
	} {
		if err := events.Enqueue(ctx, ev); err != nil {
			t.Fatalf("Enqueue %s: %v", ev.JTI, err)
		}
	}
	if _, err := db.ExecContext(ctx, "ANALYZE oidc_ssf_events"); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	before := ssfTuplesRead(t, db)
	got, err := events.ClaimDue(ctx, contract.Reference, 3, 1, time.Minute)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	read := ssfTuplesRead(t, db) - before

	jtis := make([]string, 0, len(got))
	for _, ev := range got {
		jtis = append(jtis, ev.JTI)
	}
	slices.Sort(jtis)
	if want := []string{"a-000", "b-0", "c-0"}; !slices.Equal(jtis, want) {
		t.Fatalf("ClaimDue(n=3, perStream=1) = %v, want %v", jtis, want)
	}
	// About four index reads per stream (walk step, head, candidate,
	// lease), with slack; the backlog's 300 never enter into it.
	if limit := int64(3 * 6); read > limit {
		t.Fatalf("ClaimDue read %d tuples of a %d-event queue for 3 streams with a share of 1, want at most %d",
			read, ssfClaimBacklog+3, limit)
	}
}

// ssfTuplesRead flushes this backend's statistics and returns the tuples
// read so far from the queue table, through any index or a sequential
// scan.
func ssfTuplesRead(t *testing.T, db *databasesql.DB) int64 {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "SELECT pg_stat_force_next_flush()"); err != nil {
		t.Fatalf("pg_stat_force_next_flush: %v", err)
	}
	if _, err := db.ExecContext(ctx, "SELECT pg_stat_clear_snapshot()"); err != nil {
		t.Fatalf("pg_stat_clear_snapshot: %v", err)
	}
	var n int64
	err := db.QueryRowContext(ctx,
		"SELECT COALESCE(seq_tup_read, 0) + COALESCE((SELECT SUM(idx_tup_read) FROM pg_stat_user_indexes i"+
			" WHERE i.relid = t.relid), 0) FROM pg_stat_user_tables t WHERE t.relname = 'oidc_ssf_events'").Scan(&n)
	if err != nil {
		t.Fatalf("read statistics: %v", err)
	}
	return n
}

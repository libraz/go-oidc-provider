//go:build testcontainers

package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestMySQL_SSFClaimDueReadsNoBacklogPastAStreamsShare queues one stream's
// large due backlog ahead of two other streams' due events and counts,
// from the session's handler statistics, the index and row reads a claim
// taking one event per stream makes: a few per stream, not the backlog.
func TestMySQL_SSFClaimDueReadsNoBacklogPastAStreamsShare(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := newMySQLDBFactory(t, false)(t)
	// One session, so its handler counters cover exactly the claim.
	db.SetMaxOpenConns(1)
	s, err := oidcsql.New(db, oidcsql.MySQL(), oidcsql.WithClock(&fixedClock{now: contract.Reference}))
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
	if _, err := db.ExecContext(ctx, "ANALYZE TABLE oidc_ssf_events"); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	if _, err := db.ExecContext(ctx, "FLUSH STATUS"); err != nil {
		t.Fatalf("FLUSH STATUS: %v", err)
	}
	got, err := events.ClaimDue(ctx, contract.Reference, 3, 1, time.Minute)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	read := mysqlHandlerReads(t, db)

	jtis := make([]string, 0, len(got))
	for _, ev := range got {
		jtis = append(jtis, ev.JTI)
	}
	slices.Sort(jtis)
	if want := []string{"a-000", "b-0", "c-0"}; !slices.Equal(jtis, want) {
		t.Fatalf("ClaimDue(n=3, perStream=1) = %v, want %v", jtis, want)
	}
	// A handful of reads per stream for the heads, candidates and leases;
	// the backlog's 300 never enter into it.
	if limit := int64(3 * 10); read > limit {
		t.Fatalf("ClaimDue made %d handler reads over a %d-event queue for 3 streams with a share of 1, want at most %d",
			read, ssfClaimBacklog+3, limit)
	}
}

// mysqlHandlerReads sums this session's Handler_read_* counters.
func mysqlHandlerReads(t *testing.T, db *databasesql.DB) int64 {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), "SHOW SESSION STATUS LIKE 'Handler_read%'")
	if err != nil {
		t.Fatalf("SHOW SESSION STATUS: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var total int64
	for rows.Next() {
		var (
			name string
			n    int64
		)
		if err := rows.Scan(&name, &n); err != nil {
			t.Fatalf("scan status: %v", err)
		}
		if !strings.HasPrefix(name, "Handler_read_") {
			continue
		}
		total += n
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("status rows: %v", err)
	}
	return total
}

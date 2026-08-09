//go:build testcontainers

package oidcsql_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// The retention sweep is the one statement group an embedder runs on a
// schedule rather than on a request, so a dialect that rejects it fails
// silently in production long after the deployment that introduced it.
// These cases run the same sweep against the engines the contract
// harness covers.

func TestPostgres_GC(t *testing.T) {
	t.Parallel()
	runGCAcrossEngine(t, newPostgresFactory(t))
}

func TestMySQL_GC(t *testing.T) {
	t.Parallel()
	runGCAcrossEngine(t, newMySQLFactory(t))
}

func runGCAcrossEngine(t *testing.T, f contract.Factory) {
	t.Helper()
	b := f(t)
	s, ok := b.Store.(*oidcsql.Store)
	if !ok {
		t.Fatalf("factory produced %T, want *oidcsql.Store", b.Store)
	}
	ctx := t.Context()
	cutoff := b.Now()

	if err := s.Sessions().Save(ctx, &store.Session{
		ID: "session-dead", Subject: "subject-1",
		ExpiresAt: cutoff.Add(-time.Hour),
		CreatedAt: cutoff.Add(-2 * time.Hour),
		UpdatedAt: cutoff.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("Save expired session: %v", err)
	}
	if err := s.Sessions().Save(ctx, &store.Session{
		ID: "session-live", Subject: "subject-1",
		ExpiresAt: cutoff.Add(time.Hour),
		CreatedAt: cutoff, UpdatedAt: cutoff,
	}); err != nil {
		t.Fatalf("Save live session: %v", err)
	}
	if err := s.Interactions().Save(ctx, &store.Interaction{
		ID: "interaction-dead", ClientID: "client-1", Step: "login",
		RawState: []byte("{}"), ExpiresAt: cutoff.Add(-time.Hour),
		CreatedAt: cutoff.Add(-2 * time.Hour), UpdatedAt: cutoff.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("Save expired interaction: %v", err)
	}
	if err := s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI: "urn:ietf:params:oauth:request_uri:dead", ClientID: "client-1",
		RawParams: []byte("response_type=code"),
		ExpiresAt: cutoff.Add(-time.Hour), CreatedAt: cutoff.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("Save expired PAR: %v", err)
	}

	stats, err := s.GC(ctx, cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if stats.Sessions != 1 || stats.Interactions != 1 || stats.PushedAuthRequests != 1 {
		t.Errorf("GC reported %+v, want one row per seeded expired table", stats)
	}
	if _, err := s.Sessions().Find(ctx, "session-live"); err != nil {
		t.Errorf("Find live session after the sweep: %v", err)
	}
}

package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"errors"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

func TestSQLite_ReconcileStaticClients_IsAtomicAndIdempotent(t *testing.T) {
	t.Parallel()

	db, err := databasesql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	st, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	existing := &store.Client{
		ID:     "client-b",
		Source: store.ClientSourceStatic,
		Scopes: []string{"openid"},
	}
	if err := st.ReconcileStaticClients(ctx, []*store.Client{existing}); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	if err := st.ReconcileStaticClients(ctx, []*store.Client{existing}); err != nil {
		t.Fatalf("idempotent reconcile: %v", err)
	}

	missing := &store.Client{ID: "client-a", Source: store.ClientSourceStatic}
	conflict := &store.Client{
		ID:     "client-b",
		Source: store.ClientSourceStatic,
		Scopes: []string{"profile"},
	}
	err = st.ReconcileStaticClients(ctx, []*store.Client{missing, conflict})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("conflicting reconcile error=%v want ErrConflict", err)
	}
	if _, err := st.GetClient(ctx, missing.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("client-a after rollback err=%v want ErrNotFound", err)
	}
	got, err := st.GetClient(ctx, existing.ID)
	if err != nil {
		t.Fatalf("GetClient(client-b): %v", err)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "openid" {
		t.Errorf("client-b scopes=%v want unchanged [openid]", got.Scopes)
	}
}

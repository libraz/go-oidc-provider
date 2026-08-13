package oidcsql_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

// runClientUpdateContracts pins what UpdateClient reports on every engine
// the adapter supports. Engines disagree on whether an UPDATE counts
// matched rows or changed rows, so re-writing a client with the metadata
// it already carries — the steady state of a client reconciling its own
// registration — must succeed rather than read as a missing row. Only an
// absent client may be reported as [store.ErrNotFound].
//
// Each dialect's contract test calls this alongside [contract.Run] so the
// three engines are compared under the same fixtures.
func runClientUpdateContracts(t *testing.T, f contract.Factory) {
	t.Helper()

	registry := func(t *testing.T) store.ClientRegistry {
		t.Helper()
		b := f(t)
		reg, ok := b.Store.(store.ClientRegistry)
		if !ok {
			t.Fatalf("factory produced %T, want store.ClientRegistry", b.Store)
		}
		return reg
	}

	t.Run("ClientUpdateUnchanged", func(t *testing.T) {
		t.Parallel()
		reg := registry(t)
		ctx := context.Background()
		c := &store.Client{
			ID:                      "unchanged-update",
			RedirectURIs:            []string{"https://rp.example.com/cb"},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			Scopes:                  []string{"openid", "email"},
			TokenEndpointAuthMethod: "client_secret_basic",
			ClientName:              "Reconciling RP",
			Source:                  store.ClientSourceDynamic,
		}
		if err := reg.RegisterClient(ctx, c); err != nil {
			t.Fatalf("RegisterClient: %v", err)
		}
		stored, err := reg.GetClient(ctx, c.ID)
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
		if err := reg.UpdateClient(ctx, stored); err != nil {
			t.Fatalf("UpdateClient with unchanged metadata: %v", err)
		}
		// A reconcile loop repeats indefinitely; the second no-op has to
		// be as successful as the first.
		if err := reg.UpdateClient(ctx, stored); err != nil {
			t.Fatalf("repeated UpdateClient with unchanged metadata: %v", err)
		}
		after, err := reg.GetClient(ctx, c.ID)
		if err != nil {
			t.Fatalf("GetClient after unchanged update: %v", err)
		}
		if !reflect.DeepEqual(stored, after) {
			t.Fatalf("unchanged update altered the record:\nbefore %+v\nafter  %+v", stored, after)
		}
	})

	t.Run("ClientUpdateAbsent", func(t *testing.T) {
		t.Parallel()
		reg := registry(t)
		err := reg.UpdateClient(context.Background(), &store.Client{ID: "absent-update"})
		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("UpdateClient on absent client: want ErrNotFound, got %v", err)
		}
	})
}

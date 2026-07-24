package oidcsql

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

// ReconcileStaticClients implements [store.StaticClientReconciler] with one
// database transaction. Existing equivalent records are left untouched;
// missing records are inserted; any difference rolls the complete batch back.
func (s *Store) ReconcileStaticClients(ctx context.Context, clients []*store.Client) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrapErr("clients.ReconcileStaticClients.BeginTx", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	registry := newClientStore(s, tx)
	if err := reconcileStaticClientsInTx(ctx, registry, clients); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return wrapErr("clients.ReconcileStaticClients.Commit", err)
	}
	return nil
}

func reconcileStaticClientsInTx(ctx context.Context, registry *clientStore, clients []*store.Client) error {
	seen := make(map[string]struct{}, len(clients))
	for _, desired := range clients {
		if err := validateStaticClient(ctx, desired, seen); err != nil {
			return err
		}
		if err := reconcileStaticClientInTx(ctx, registry, desired); err != nil {
			return err
		}
	}
	return nil
}

func validateStaticClient(
	ctx context.Context,
	desired *store.Client,
	seen map[string]struct{},
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if desired == nil {
		return errors.New("oidcsql: nil static client")
	}
	if desired.Source != "" && desired.Source != store.ClientSourceStatic {
		return store.ErrConflict
	}
	if _, duplicate := seen[desired.ID]; duplicate {
		return store.ErrConflict
	}
	seen[desired.ID] = struct{}{}
	return nil
}

func reconcileStaticClientInTx(
	ctx context.Context,
	registry *clientStore,
	desired *store.Client,
) error {
	existing, err := registry.GetClient(ctx, desired.ID)
	if err == nil {
		if !store.StaticClientEquivalent(existing, desired) {
			return store.ErrConflict
		}
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := registry.Register(ctx, desired); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

var _ store.StaticClientReconciler = (*Store)(nil)

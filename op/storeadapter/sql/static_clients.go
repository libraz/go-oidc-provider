package oidcsql

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

// staticReconcileAttempts bounds how often a reconcile that lost an insert
// race to a concurrent replica is retried against the winner's record.
const staticReconcileAttempts = 3

// errStaticInsertRace marks a reconcile whose insert lost to a concurrent
// writer of the same ID; the transaction is abandoned and rerun.
var errStaticInsertRace = errors.New("oidcsql: static client insert lost a race")

// ReconcileStaticClients implements [store.StaticClientReconciler] with one
// database transaction. Existing equivalent records are left untouched;
// missing records are inserted; any difference rolls the complete batch back.
// A reconcile that loses an insert race reruns in a fresh transaction, where
// the winner's record is compared like any stored one.
func (s *Store) ReconcileStaticClients(ctx context.Context, clients []*store.Client) error {
	for range staticReconcileAttempts {
		err := s.reconcileStaticClientsOnce(ctx, clients)
		if !errors.Is(err, errStaticInsertRace) {
			return err
		}
	}
	return store.ErrConflict
}

func (s *Store) reconcileStaticClientsOnce(ctx context.Context, clients []*store.Client) error {
	itx, err := s.beginInternalTx(ctx, "clients.ReconcileStaticClients.BeginTx")
	if err != nil {
		return err
	}
	defer func() {
		_ = itx.Rollback()
	}()

	registry := newClientStore(s, itx.tx)
	if err := reconcileStaticClientsInTx(ctx, registry, clients); err != nil {
		return err
	}
	if err := itx.Commit(); err != nil {
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
			return errStaticInsertRace
		}
		return err
	}
	return nil
}

var _ store.StaticClientReconciler = (*Store)(nil)

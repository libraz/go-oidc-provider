package oidcsql_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// gatedCall is one entry point that opens a transaction of its own
// rather than one the embedder asked for. Each is driven twice: once
// while the gate is held by somebody else, where it must wait, and once
// with the gate free, where it must reach the database.
type gatedCall struct {
	name string
	run  func(ctx context.Context, s *oidcsql.Store) error
	// freeErr accepts the outcome when the gate is free. A sentinel is
	// as good as success here: what matters is that the call got as far
	// as the engine instead of timing out on the gate.
	freeErr func(error) bool
}

func succeeds(err error) bool { return err == nil }

func gatedCalls(now time.Time) []gatedCall {
	credential := []byte{0x01, 0x02, 0x03}
	parent := "gate-parent"
	return []gatedCall{
		{
			name: "passkeys.Put",
			run: func(ctx context.Context, s *oidcsql.Store) error {
				return s.Passkeys().Put(ctx, &store.PasskeyRecord{
					Subject:      "gate-subject",
					CredentialID: credential,
					PublicKey:    []byte{0x0a},
					CreatedAt:    now,
				})
			},
			freeErr: succeeds,
		},
		{
			name: "passkeys.UpdateAssertion",
			run: func(ctx context.Context, s *oidcsql.Store) error {
				_, err := s.Passkeys().UpdateAssertion(ctx, credential, store.PasskeyAssertionUpdate{
					SignCount:   1,
					UserPresent: true,
				})
				return err
			},
			// The credential is only present once passkeys.Put above has
			// run with the gate free, which is the phase this expectation
			// belongs to.
			freeErr: succeeds,
		},
		{
			name: "recoveryCodes.Put",
			run: func(ctx context.Context, s *oidcsql.Store) error {
				return s.RecoveryCodes().Put(ctx, &store.RecoveryBatch{
					Subject:     "gate-subject",
					GeneratedAt: now,
					Codes:       []store.RecoveryCode{{Hash: "hash-0"}, {Hash: "hash-1"}},
				})
			},
			freeErr: succeeds,
		},
		{
			name: "refreshes.Save rotation",
			run: func(ctx context.Context, s *oidcsql.Store) error {
				return s.RefreshTokens().Save(ctx, guardRefresh(now, "gate-rotated", &parent))
			},
			freeErr: succeeds,
		},
		{
			name: "refreshes.SaveRotationWithRetry",
			run: func(ctx context.Context, s *oidcsql.Store) error {
				retries, ok := s.RefreshTokens().(store.RefreshRetryResponseStore)
				if !ok {
					return errors.New("RefreshTokenStore does not implement RefreshRetryResponseStore")
				}
				return retries.SaveRotationWithRetry(ctx, guardRefresh(now, "gate-retried", &parent), []byte("sealed"))
			},
			// The parent row is written by the free-gate phase of
			// "refreshes.Save rotation" only as a descendant, so the
			// cached response has no row to attach to. The rotation still
			// lands: an absent parent proves the chain was never revoked,
			// and the cache is the optional half of the operation.
			freeErr: succeeds,
		},
		{
			name: "refreshes.RevokeChain",
			run: func(ctx context.Context, s *oidcsql.Store) error {
				return s.RefreshTokens().RevokeChain(ctx, "gate-rotated")
			},
			freeErr: succeeds,
		},
		{
			name: "clients.ReconcileStaticClients",
			run: func(ctx context.Context, s *oidcsql.Store) error {
				return s.ReconcileStaticClients(ctx, []*store.Client{{
					ID:     "gate-client",
					Source: store.ClientSourceStatic,
					Scopes: []string{"openid"},
				}})
			},
			freeErr: succeeds,
		},
	}
}

// TestSQLite_InternalTransactionsHonourTheTransactionGate pins the
// single-writer promise the SQLite dialect makes across both kinds of
// transaction. The gate is held here by an ordinary [store.Tx], and
// every substore method that opens a transaction on the caller's behalf
// has to queue behind it: a call that proceeds anyway is a second
// concurrent transaction on an engine that has no row lock to resolve
// one with, which is what turns a read-amend-write into an outright
// refusal instead of a wait.
//
// Waiting is observed as the caller's own deadline expiring. That is
// also what an embedder sees, and it is the reason the wait honours the
// context at all.
func TestSQLite_InternalTransactionsHonourTheTransactionGate(t *testing.T) {
	t.Parallel()

	b := newSQLiteFactory(t)(t)
	s, ok := b.Store.(*oidcsql.Store)
	if !ok {
		t.Fatalf("factory produced %T, want *oidcsql.Store", b.Store)
	}
	ctx := context.Background()
	calls := gatedCalls(b.Now())

	held, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	for _, c := range calls {
		waiting, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		err := c.run(waiting, s)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s with the gate held: err=%v, want the call to wait until its deadline", c.name, err)
		}
	}
	if err := held.Rollback(); err != nil {
		t.Fatalf("Rollback the holding transaction: %v", err)
	}

	// The negative control: the deadlines above have to come from the
	// gate and not from a call that is stuck whatever the gate does.
	// These calls run under a deadline of their own so that a slot a
	// previous call took and never returned fails the test here rather
	// than hanging it.
	for _, c := range calls {
		free, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := c.run(free, s)
		cancel()
		if !c.freeErr(err) {
			t.Errorf("%s with the gate free: err=%v, want the call to reach the database", c.name, err)
		}
	}
}

// TestSQLite_ConcurrentInternalTransactionsStayOffTheDriverError drives
// the three flows that open their own transactions against each other:
// a passkey login, a refresh rotation, and a static-client
// reconciliation. On SQLite a read-amend-write that overlaps another
// transaction is refused rather than delayed, and the driver's refusal
// satisfies no store sentinel — an embedder sees a bare storage fault
// and returns 500 for what is a valid login.
func TestSQLite_ConcurrentInternalTransactionsStayOffTheDriverError(t *testing.T) {
	t.Parallel()

	b := newSQLiteFactory(t)(t)
	s, ok := b.Store.(*oidcsql.Store)
	if !ok {
		t.Fatalf("factory produced %T, want *oidcsql.Store", b.Store)
	}
	ctx := context.Background()
	now := b.Now()

	credential := []byte{0xC0, 0xDE}
	if err := s.Passkeys().Put(ctx, &store.PasskeyRecord{
		Subject:      "race-subject",
		CredentialID: credential,
		PublicKey:    []byte{0x0a},
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("seed passkey: %v", err)
	}
	if err := s.RefreshTokens().Save(ctx, guardRefresh(now, "race-root", nil)); err != nil {
		t.Fatalf("seed refresh root: %v", err)
	}
	staticClient := &store.Client{ID: "race-client", Source: store.ClientSourceStatic, Scopes: []string{"openid"}}
	if err := s.ReconcileStaticClients(ctx, []*store.Client{staticClient}); err != nil {
		t.Fatalf("seed static client: %v", err)
	}

	const rounds = 20
	errCh := make(chan error, 4*rounds)
	root := "race-root"
	flows := []func(i int) error{
		func(i int) error {
			_, err := s.Passkeys().UpdateAssertion(ctx, credential, store.PasskeyAssertionUpdate{
				SignCount:   uint32(i + 1), //nolint:gosec // bounded by rounds.
				UserPresent: true,
			})
			return err
		},
		func(i int) error {
			return s.RefreshTokens().Save(ctx, guardRefresh(now, fmt.Sprintf("race-rotated-%d", i), &root))
		},
		func(int) error {
			return s.ReconcileStaticClients(ctx, []*store.Client{staticClient})
		},
		func(i int) error {
			return s.RecoveryCodes().Put(ctx, &store.RecoveryBatch{
				Subject:     fmt.Sprintf("race-recovery-%d", i),
				GeneratedAt: now,
				Codes:       []store.RecoveryCode{{Hash: "hash-0"}},
			})
		},
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, flow := range flows {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := range rounds {
				if err := flow(i); err != nil {
					errCh <- err
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		// The driver's own wording is what an embedder would have to
		// match on, and matching on it is not something the store
		// contract asks of anybody.
		if msg := strings.ToLower(err.Error()); strings.Contains(msg, "locked") || strings.Contains(msg, "busy") {
			t.Fatalf("a driver lock conflict reached the caller: %v", err)
		}
		t.Errorf("concurrent internal transaction failed: %v", err)
	}
}

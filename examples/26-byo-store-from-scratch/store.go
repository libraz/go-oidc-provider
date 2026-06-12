//go:build example

// store.go — the scratchStore aggregate that satisfies store.Store and
// store.Transactional, plus the substore accessors and the duplicate-key
// helper the substores share.
//
// Every accessor returns a substore bound to the aggregate's *sql.DB.
// The optional store.Tx accessors (see tx.go) return substores bound to a
// single *sql.Tx for embedders that need manual cross-substore transactions.

package main

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// scratchStore is the hand-rolled store.Store. It holds only the
// *sql.DB and a clock; every substore is a tiny value constructed on
// demand against the shared querier.
type scratchStore struct {
	db  *databasesql.DB
	now func() time.Time
}

// newScratchStore builds the aggregate. The clock is time.Now wrapped
// once here; examples MAY call time.Now (internal/timex is unreachable
// from examples/).
func newScratchStore(db *databasesql.DB) *scratchStore {
	return &scratchStore{
		db:  db,
		now: time.Now, //nolint:forbidigo // example store — not OP business logic; internal/timex is unreachable from examples/.
	}
}

// Migrate applies the hand-rolled DDL. Production embedders run this
// through their own migration tooling instead.
func (s *scratchStore) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaDDL); err != nil {
		return fmt.Errorf("scratch.Migrate: %w", err)
	}
	return nil
}

// --- store.Store accessors (db-bound) ------------------------------------

func (s *scratchStore) Clients() store.ClientStore { return &clientStore{q: s.db} }

func (s *scratchStore) AuthorizationCodes() store.AuthorizationCodeStore {
	return &authCodeStore{q: s.db, now: s.now}
}

func (s *scratchStore) RefreshTokens() store.RefreshTokenStore {
	return &refreshStore{q: s.db, now: s.now}
}

func (s *scratchStore) Grants() store.GrantStore { return &grantStore{q: s.db, now: s.now} }

func (s *scratchStore) Sessions() store.SessionStore { return &sessionStore{q: s.db, now: s.now} }

func (s *scratchStore) PushedAuthRequests() store.PushedAuthRequestStore {
	return &parStore{q: s.db, now: s.now}
}

func (s *scratchStore) Interactions() store.InteractionStore {
	return &interactionStore{q: s.db, now: s.now}
}

func (s *scratchStore) ConsumedJTIs() store.ConsumedJTIStore { return &jtiStore{q: s.db, now: s.now} }

func (s *scratchStore) Users() store.UserStore { return &userStore{q: s.db} }

func (s *scratchStore) AccessTokens() store.AccessTokenRegistry {
	return &accessTokenStore{q: s.db}
}

func (s *scratchStore) Metadata() store.MetadataStore { return &metadataStore{q: s.db} }

// --- substores the demo does not exercise return nil --------------------
//
// The library detects each nil at op.New and either skips the feature
// or requires the matching option to be off. buildProvider pins
// op.WithAccessTokenRevocationStrategy(op.RevocationStrategyNone) so the
// nil GrantRevocations() is accepted; the opaque-AT, DCR, device, and
// CIBA features are simply never enabled.

func (s *scratchStore) OpaqueAccessTokens() store.OpaqueAccessTokenStore { return nil }

func (s *scratchStore) InitialAccessTokens() store.InitialAccessTokenStore { return nil }

func (s *scratchStore) RegistrationAccessTokens() store.RegistrationAccessTokenStore { return nil }

func (s *scratchStore) GrantRevocations() store.GrantRevocationStore { return nil }

func (s *scratchStore) DeviceCodes() store.DeviceCodeStore { return nil }

func (s *scratchStore) CIBARequests() store.CIBARequestStore { return nil }

// Compile-time proof that the aggregate satisfies both contracts.
var (
	_ store.Store         = (*scratchStore)(nil)
	_ store.Transactional = (*scratchStore)(nil)
)

// isDuplicate reports whether err describes a unique-constraint or
// primary-key collision. Driver-specific error types would drag the
// driver into a typed import, so the check is by message substring —
// the standard portable approach. modernc.org/sqlite reports
// "UNIQUE constraint failed".
func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "primary key constraint")
}

package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// grantRevocationStore is the SQL implementation of
// [store.GrantRevocationStore] (ADR 0025). The substore fronts two
// physical tables under one Go type:
//
//   - oidc_grant_revocations holds per-grant tombstones written when a
//     cascade fires (logout, code-replay, refresh rotation). The PK is
//     grant_id; expires_at is indexed so the GC sweep is bounded.
//   - oidc_revoked_jtis holds the per-JTI denylist written by the
//     RFC 7009 single-AT revocation path. The PK is jti; expires_at is
//     indexed for the same reason.
//
// The split mirrors how production deployments are expected to
// physically lay the rows out so audit tooling can reason about each
// shape independently. [grantRevocationStore.IsRevoked] honours the
// ADR-mandated precedence rule (denylist first, tombstone second) and
// the "revoked iff iat <= revoked_at" semantics on the tombstone match.
type grantRevocationStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newGrantRevocationStore(s *Store, tx *databasesql.Tx) *grantRevocationStore {
	return &grantRevocationStore{parent: s, tx: tx}
}

func (s *grantRevocationStore) runner() runner { return pickRunner(s.parent, s.tx) }

// RevokeGrant implements [store.GrantRevocationStore]. The call is
// idempotent at the database layer: a second insert against the same
// grant_id extends expires_at to max(existing, supplied) (rendered via
// the dialect's GREATEST / MAX scalar) and leaves revoked_at unchanged
// so the verifier's "iat <= revoked_at" rule keeps its meaning across
// retries. An empty GrantID is a no-op so cascade call sites can shed
// guard branches.
func (s *grantRevocationStore) RevokeGrant(ctx context.Context, t store.GrantTombstone) error {
	if t.GrantID == "" {
		return nil
	}
	if _, err := s.runner().ExecContext(ctx, s.parent.queries.grantTombstoneUpsert,
		t.GrantID, timeToInt64(t.RevokedAt), timeToInt64(t.ExpiresAt), t.Reason); err != nil {
		return wrapErr("grantRevocations.RevokeGrant", err)
	}
	return nil
}

// RevokeJTI implements [store.GrantRevocationStore]. The call is
// idempotent at the database layer: a second insert against the same
// jti is elided by the dialect-specific DO NOTHING tail so the
// existing row's expires_at and grant_id remain unchanged. An empty
// JTI is a no-op.
func (s *grantRevocationStore) RevokeJTI(ctx context.Context, r store.RevokedJTI) error {
	if r.JTI == "" {
		return nil
	}
	if _, err := s.runner().ExecContext(ctx, s.parent.queries.revokedJTIInsert,
		r.JTI, r.GrantID, timeToInt64(r.ExpiresAt)); err != nil {
		return wrapErr("grantRevocations.RevokeJTI", err)
	}
	return nil
}

// IsRevoked implements [store.GrantRevocationStore]. The lookup order
// is JTI denylist first (cheap, small, short-circuiting) then grant
// tombstone with the rule "revoked iff iat <= revoked_at". The two
// SELECTs are deliberate: a UNION ALL would always touch both tables,
// while the denylist short-circuit avoids the tombstone read in the
// (rare) case the AT was directly revoked through RFC 7009. Embedders
// who measure tombstone-read pressure can add a denormalised cache in
// front of this method without changing the contract.
//
// An empty grantID skips the tombstone check (the legacy fallback path
// from ADR 0025 §Migration); an empty jti skips the denylist check
// (the mint-refusal path where the OP has not yet allocated a JTI).
func (s *grantRevocationStore) IsRevoked(ctx context.Context, grantID, jti string, iat time.Time) (bool, error) {
	if jti != "" {
		// A row exists if and only if the jti is denylisted; the SELECT
		// list keeps a single column so the driver short-circuits the
		// per-row buffering path. Any error other than ErrNoRows is a
		// transport fault and surfaces as a fatal error to the caller
		// (userinfo / introspection treat this as deny rather than
		// re-introducing a cascade gap).
		var expiresAt int64
		err := s.runner().QueryRowContext(ctx, s.parent.queries.revokedJTIFind, jti).Scan(&expiresAt)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, databasesql.ErrNoRows) {
			return false, wrapErr("grantRevocations.IsRevoked.jti", err)
		}
	}
	if grantID == "" {
		return false, nil
	}
	var revokedAt int64
	err := s.runner().QueryRowContext(ctx, s.parent.queries.grantTombstoneFind, grantID).Scan(&revokedAt)
	if errors.Is(err, databasesql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrapErr("grantRevocations.IsRevoked.grant", err)
	}
	// "revoked iff iat <= revoked_at": equivalently, NOT iat.After.
	// timeToInt64 maps the zero time to 0, which any real iat will
	// trivially exceed; embedders that legitimately revoke at the unix
	// epoch are not in scope.
	if !iat.After(int64ToTime(revokedAt)) {
		return true, nil
	}
	return false, nil
}

// GC implements [store.GrantRevocationStore]. Drops every tombstone
// and denylist row whose expires_at is strictly before cutoff, and
// returns the total number of rows removed. Rows whose expires_at is
// the unix epoch (the persisted form of the zero time) opt out of GC
// so the substore never silently drops a row that was registered
// without a TTL — mirroring the inmem reference adapter byte-for-byte.
//
// Two DELETEs are run in sequence; if the first fails the second is
// skipped and the partial effect is rolled back by the caller's
// transaction (when one is in flight). Outside a transaction the two
// DELETEs are independent: a partial failure leaves the surviving
// table cleaner, which is acceptable because GC is idempotent and a
// retry converges on the empty set.
func (s *grantRevocationStore) GC(ctx context.Context, cutoff time.Time) (int, error) {
	cutoffInt := timeToInt64(cutoff)
	tombRes, err := s.runner().ExecContext(ctx, s.parent.queries.grantTombstoneGC, cutoffInt)
	if err != nil {
		return 0, wrapErr("grantRevocations.GC.tombstones", err)
	}
	tombN, err := tombRes.RowsAffected()
	if err != nil {
		return 0, wrapErr("grantRevocations.GC.tombstones.RowsAffected", err)
	}
	jtiRes, err := s.runner().ExecContext(ctx, s.parent.queries.revokedJTIGC, cutoffInt)
	if err != nil {
		return int(tombN), wrapErr("grantRevocations.GC.jtis", err)
	}
	jtiN, err := jtiRes.RowsAffected()
	if err != nil {
		return int(tombN), wrapErr("grantRevocations.GC.jtis.RowsAffected", err)
	}
	return int(tombN + jtiN), nil
}

package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

type refreshStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newRefreshStore(s *Store, tx *databasesql.Tx) *refreshStore {
	return &refreshStore{parent: s, tx: tx}
}

func (s *refreshStore) runner() runner { return pickRunner(s.parent, s.tx) }

// Save honours the hash-on-store contract documented on
// [store.RefreshTokenStore.Save]: both [store.RefreshToken.ID] and
// [store.RefreshToken.ParentID] are bearer secrets, so the row stores
// the SHA-256 digest of each via [patterns.Digest] and never the raw
// value. The chain walk in [RevokeChain] already drives lookups by
// id-digest, so the parent pointer is digested at the same call site.
func (s *refreshStore) Save(ctx context.Context, t *store.RefreshToken) error {
	idDigest := patterns.Digest(t.ID)
	parentDigest := digestNullableID(t.ParentID)
	_, err := s.runner().ExecContext(ctx, s.parent.queries.refreshSave,
		idDigest, t.ClientID, t.GrantID, parentDigest, t.Subject,
		encodeStrings(t.Scope), t.Resource,
		t.DPoPJKT, t.MTLSCertThumbprint, t.Nonce, boolToInt64(t.Revoked),
		timeToInt64(t.ExpiresAt), timePtrToInt64Ptr(t.ConsumedAt), timeToInt64(t.CreatedAt))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return wrapErr("refreshes.Save", err)
	}
	return nil
}

// digestNullableID maps a *string holding a raw bearer ID to the
// nullable bind value the schema expects: nil stays nil so a root
// chain entry persists NULL in parent_id, otherwise the digest is
// returned as a string the driver can bind into the TEXT / VARCHAR
// column. The helper exists so refreshSave keeps a single line of
// argument prep regardless of whether the token roots a chain;
// pgx, the mysql driver, and modernc.org/sqlite all accept the
// untyped-nil interface value as NULL.
func digestNullableID(s *string) any {
	if s == nil {
		return nil
	}
	return patterns.Digest(*s)
}

// find resolves a row by hashing the presented id and comparing in
// constant time against the stored digest. The returned record's ID
// is restored to the caller's raw value so call sites observe the
// same opaque bearer token they passed in; the parent_id digest stays
// in the returned [store.RefreshToken.ParentID] because the chain
// walk in [RevokeChain] consumes parent pointers as digests already.
func (s *refreshStore) find(ctx context.Context, id string) (*store.RefreshToken, error) {
	idDigest := patterns.Digest(id)
	var (
		t        store.RefreshToken
		stored   string
		scope    []byte
		parent   *string
		consumed *int64
		expires  int64
		created  int64
		revoked  int64
	)
	err := s.runner().QueryRowContext(ctx, s.parent.queries.refreshFind, idDigest).Scan(
		&stored, &t.ClientID, &t.Subject, &t.GrantID,
		&scope, &t.Resource, &parent, &consumed, &expires, &created,
		&t.DPoPJKT, &t.MTLSCertThumbprint, &t.Nonce, &revoked)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("refreshes.Find", err)
	}
	if !patterns.ConstantTimeKeyMatch(stored, idDigest) {
		return nil, store.ErrNotFound
	}
	dec, err := decodeStrings(scope)
	if err != nil {
		return nil, err
	}
	t.ID = id
	t.Scope = dec
	t.ParentID = parent
	t.ConsumedAt = int64PtrToTimePtr(consumed)
	t.ExpiresAt = int64ToTime(expires)
	t.CreatedAt = int64ToTime(created)
	t.Revoked = int64ToBool(revoked)
	return &t, nil
}

func (s *refreshStore) Find(ctx context.Context, id string) (*store.RefreshToken, error) {
	t, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *refreshStore) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	t, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if t.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	now := s.parent.clock.Now()
	idDigest := patterns.Digest(id)
	res, err := s.runner().ExecContext(ctx, s.parent.queries.refreshConsume, timeToInt64(now), idDigest)
	if err != nil {
		return nil, wrapErr("refreshes.Consume", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, wrapErr("refreshes.Consume.RowsAffected", err)
	}
	if n == 0 {
		return nil, store.ErrAlreadyConsumed
	}
	t.ConsumedAt = &now
	return t, nil
}

// RevokeChain marks every refresh token in the rotation chain rooted
// at rootID as consumed. Backends that delete or mark equivalently
// satisfy the contract; the SQL adapter marks (preserving the audit
// trail). The walk is bounded by the chain depth, which the library
// caps at the refresh-token TTL by construction.
//
// The walk operates entirely in the digest space: rootID is hashed
// once on entry, every descendant lookup uses the parent_id digest
// the row was stored with, and the BFS queue holds digests rather
// than raw IDs. This keeps the rotation graph internally consistent
// even though no code path outside this method ever observes the raw
// IDs of the descendants.
//
// Atomicity (H-G3): when the substore is not already running inside a
// caller-owned transaction the BFS auto-wraps itself in a fresh
// transaction so a concurrent rotation cannot interleave a refresh
// Save between the parent's mark and its children-lookup. The chain
// depth is bounded by the rotation TTL, so the auto-Tx stays short
// even on aggressively rotated grants.
func (s *refreshStore) RevokeChain(ctx context.Context, rootID string) error {
	if s.tx == nil {
		tx, err := s.parent.db.BeginTx(ctx, nil)
		if err != nil {
			return wrapErr("refreshes.RevokeChain.begin", err)
		}
		defer func() { _ = tx.Rollback() }()
		txStore := &refreshStore{parent: s.parent, tx: tx}
		if err := txStore.revokeChainBFS(ctx, rootID); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return wrapErr("refreshes.RevokeChain.commit", err)
		}
		return nil
	}
	return s.revokeChainBFS(ctx, rootID)
}

// revokeChainBFS performs the BFS walk under the substore's current
// runner (transaction or direct DB). [refreshStore.RevokeChain] picks
// between auto-Tx wrapping and direct dispatch and routes through
// here.
//
//nolint:gocognit // structure mirrors the prior inline BFS body.
func (s *refreshStore) revokeChainBFS(ctx context.Context, rootID string) error {
	if _, err := s.find(ctx, rootID); err != nil {
		return err
	}
	now := s.parent.clock.Now()
	rootDigest := patterns.Digest(rootID)
	visited := map[string]struct{}{rootDigest: {}}
	queue := []string{rootDigest}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		// Mark current consumed + revoked.
		if _, err := s.runner().ExecContext(ctx,
			s.parent.queries.refreshRevokeChainUpdate, timeToInt64(now), current); err != nil {
			return wrapErr("refreshes.RevokeChain.update", err)
		}
		// Enqueue every direct descendant. parent_id rows hold the
		// digest of the bearer secret the parent token was stored
		// with, so the comparison is digest-against-digest.
		rows, err := s.runner().QueryContext(ctx,
			s.parent.queries.refreshRevokeChainChildren, current)
		if err != nil {
			return wrapErr("refreshes.RevokeChain.children", err)
		}
		var children []string
		for rows.Next() {
			var id string
			if scanErr := rows.Scan(&id); scanErr != nil {
				_ = rows.Close()
				return wrapErr("refreshes.RevokeChain.scan", scanErr)
			}
			children = append(children, id)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return wrapErr("refreshes.RevokeChain.iter", err)
		}
		if err := rows.Close(); err != nil {
			return wrapErr("refreshes.RevokeChain.close", err)
		}
		for _, child := range children {
			if _, ok := visited[child]; ok {
				continue
			}
			visited[child] = struct{}{}
			queue = append(queue, child)
		}
	}
	return nil
}

// RevokeByGrant marks every refresh token whose grant_id equals
// grantID as consumed + revoked. The library calls it from the
// code-replay cascade. A missing grant is not an error.
func (s *refreshStore) RevokeByGrant(ctx context.Context, grantID string) error {
	now := s.parent.clock.Now()
	if _, err := s.runner().ExecContext(ctx,
		s.parent.queries.refreshRevokeByGrant, timeToInt64(now), grantID); err != nil {
		return wrapErr("refreshes.RevokeByGrant", err)
	}
	return nil
}

// RevokeByClient implements [store.RevokeByClient]. The dynamic
// registration cascade invokes it after a successful
// DELETE /register/{client_id} so a deleted client's outstanding
// refresh tokens are stamped consumed + revoked. A missing client
// is not an error.
func (s *refreshStore) RevokeByClient(ctx context.Context, clientID string) error {
	if clientID == "" {
		return nil
	}
	now := s.parent.clock.Now()
	if _, err := s.runner().ExecContext(ctx,
		s.parent.queries.refreshRevokeByClient, timeToInt64(now), clientID); err != nil {
		return wrapErr("refreshes.RevokeByClient", err)
	}
	return nil
}

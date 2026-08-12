package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"

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
// value. Find accepts either a raw ID or a digest returned as ParentID,
// so the digest-only schema still satisfies the store round-trip contract.
//
// A rotation Save (non-nil ParentID) is guarded against the RFC 9700
// §2.2.2 replay-revocation race: it returns [store.ErrAlreadyConsumed]
// (rolling the descendant back) when a concurrent RevokeChain revoked
// the parent chain link, so a rotation cannot outrun a replay cascade.
// Root saves and duplicate collisions retain their prior semantics
// ([store.ErrAlreadyExists] on a hashed-ID collision).
func (s *refreshStore) Save(ctx context.Context, t *store.RefreshToken) error {
	// A root-of-chain Save has no parent link to race a revocation
	// cascade against, so it takes the plain single-statement path.
	if t.ParentID == nil {
		return s.insert(ctx, s.runner(), t)
	}
	// A rotation Save (non-nil ParentID) must not win a race against a
	// concurrent RevokeChain: RFC 9700 §2.2.2 requires the whole chain
	// to die once a replay is detected, so a descendant persisted after
	// the cascade scanned would keep the attacker's chain alive until
	// natural expiry. When the substore already runs inside a
	// caller-owned transaction the caller scopes atomicity; otherwise
	// wrap the insert and a parent-still-alive re-check in one short
	// transaction (see [refreshStore.saveRotation]).
	if s.tx != nil {
		return s.saveRotation(ctx, s.runner(), t)
	}
	tx, err := s.parent.db.BeginTx(ctx, nil)
	if err != nil {
		return wrapErr("refreshes.Save.begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.saveRotation(ctx, tx, t); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return wrapErr("refreshes.Save.commit", err)
	}
	return nil
}

// SaveRotationWithRetry persists the successor and its already-encrypted
// response cache in one database transaction. The cache is attached to the
// consumed predecessor (t.ParentID), so a grace retry never needs a raw child
// identifier from the hash-on-store schema.
func (s *refreshStore) SaveRotationWithRetry(ctx context.Context, t *store.RefreshToken, sealed []byte) error {
	if t == nil || t.ParentID == nil || len(sealed) == 0 {
		return errors.New("oidcsql: retryable refresh rotation requires successor, parent, and sealed response")
	}
	if s.tx != nil {
		return s.saveRotationWithRetry(ctx, s.runner(), t, sealed)
	}
	tx, err := s.parent.db.BeginTx(ctx, nil)
	if err != nil {
		return wrapErr("refreshes.SaveRotationWithRetry.begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.saveRotationWithRetry(ctx, tx, t, sealed); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return wrapErr("refreshes.SaveRotationWithRetry.commit", err)
	}
	return nil
}

func (s *refreshStore) saveRotationWithRetry(ctx context.Context, run runner, t *store.RefreshToken, sealed []byte) error {
	if err := s.saveRotation(ctx, run, t); err != nil {
		return err
	}
	res, err := run.ExecContext(ctx, s.parent.queries.refreshRetrySave, sealed, patterns.Digest(*t.ParentID))
	if err != nil {
		return wrapErr("refreshes.SaveRotationWithRetry.cache", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("refreshes.SaveRotationWithRetry.cache.RowsAffected", err)
	}
	if n != 1 {
		return store.ErrNotFound
	}
	return nil
}

func (s *refreshStore) LoadRetryResponse(ctx context.Context, predecessorID string) ([]byte, error) {
	var sealed []byte
	err := s.runner().QueryRowContext(ctx, s.parent.queries.refreshRetryFind, patterns.Digest(predecessorID)).Scan(&sealed)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("refreshes.LoadRetryResponse", err)
	}
	return append([]byte(nil), sealed...), nil
}

// insert persists t verbatim through the shared refreshSave template. It
// is the single raw write both the root-chain path and the guarded
// rotation path funnel through, so the column order lives in exactly one
// place.
func (s *refreshStore) insert(ctx context.Context, run runner, t *store.RefreshToken) error {
	idDigest := patterns.Digest(t.ID)
	parentDigest := digestNullableID(t.ParentID)
	details, err := encodeObjectArray(t.AuthorizationDetails)
	if err != nil {
		return fmt.Errorf("oidcsql: refreshes.Save authorization details: %w", err)
	}
	extra, err := encodeMap(t.AccessTokenExtra)
	if err != nil {
		return fmt.Errorf("oidcsql: refreshes.Save access token extra: %w", err)
	}
	_, err = run.ExecContext(ctx, s.parent.queries.refreshSave,
		idDigest, t.ClientID, t.GrantID, parentDigest, t.Subject,
		boolToInt64(t.SubjectPublic), encodeStrings(t.Scope), t.Resource,
		string(t.Origin), timeToInt64(t.AuthTime), t.ACR, encodeStrings(t.AMR),
		details, extra,
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

// saveRotation inserts a rotated descendant and then re-reads its parent
// under a row lock (see [Dialect.forUpdate]). A concurrent RevokeChain
// that tombstones the parent either blocks this re-check until it
// commits (so the parent reads back revoked) or is itself forced to
// observe the freshly inserted descendant and revoke it. If the parent
// was revoked meanwhile the rotation is treated as a replay: the caller
// rolls the transaction back so the descendant never becomes redeemable,
// and [store.ErrAlreadyConsumed] is returned to mirror the sentinel the
// exchanger already maps a replayed chain onto. A missing parent (GC'd
// or unknown) proves no revocation, so the rotation is kept.
func (s *refreshStore) saveRotation(ctx context.Context, run runner, t *store.RefreshToken) error {
	if err := s.insert(ctx, run, t); err != nil {
		return err
	}
	parentDigest := patterns.Digest(*t.ParentID)
	var revoked int64
	err := run.QueryRowContext(ctx, s.parent.queries.refreshParentRevoked, parentDigest).Scan(&revoked)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return wrapErr("refreshes.Save.recheck", err)
	}
	if revoked != 0 {
		return store.ErrAlreadyConsumed
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

// find resolves a row by accepting either the raw bearer ID or an ID digest
// previously returned as [store.RefreshToken.ParentID]. Public callers
// present raw refresh_token strings; internal chain-root walks may present
// the stored parent_id digest so Find round-trips its own ParentID output
// without exposing raw parent secrets in the database.
func (s *refreshStore) find(ctx context.Context, id string) (*store.RefreshToken, error) {
	t, _, err := s.findStored(ctx, id)
	return t, err
}

// findStored resolves a row presented as a BEARER CREDENTIAL: the presented id
// is hashed and only the resulting digest is matched, so a stored digest leaked
// from a database snapshot, replica, or backup cannot be redeemed by presenting
// it verbatim. Find and Consume route here.
//
// A row whose ExpiresAt has already passed is treated as absent
// ([store.ErrNotFound]), matching [store.RefreshTokenStore.Find] and
// [store.RefreshTokenStore.Consume]'s documented contract and the
// in-memory reference adapter: an expired refresh token MUST NOT be
// treated as a live, replayable credential (a token that expired
// naturally is not evidence of a replay attempt, so surfacing it as
// "already consumed" would trigger a false chain-revocation cascade).
func (s *refreshStore) findStored(ctx context.Context, id string) (*store.RefreshToken, string, error) {
	t, stored, err := s.lookup(ctx, id, refreshCredentialKeys(id))
	if err != nil {
		return nil, "", err
	}
	if isExpired(t.ExpiresAt, s.parent.clock) {
		return nil, "", store.ErrNotFound
	}
	return t, stored, nil
}

// findStoredByHandle resolves a row presented as an INTERNAL CHAIN HANDLE: a
// stored parent/root digest previously returned by Find as
// [store.RefreshToken.ParentID], or a raw root id from a depth-0 walk. Both
// representations resolve. The tolerant lookup is safe here because the path is
// reachable only from the OP's own replay-revocation walk (RevokeChain /
// [store.RefreshChainResolver]), never the public credential Find/Consume.
func (s *refreshStore) findStoredByHandle(ctx context.Context, id string) (*store.RefreshToken, string, error) {
	return s.lookup(ctx, id, refreshHandleKeys(id))
}

func (s *refreshStore) lookup(ctx context.Context, id string, keys [2]string) (*store.RefreshToken, string, error) {
	return s.lookupWithQuery(ctx, s.parent.queries.refreshFind, id, keys)
}

func (s *refreshStore) lookupForUpdate(ctx context.Context, id string, keys [2]string) (*store.RefreshToken, string, error) {
	return s.lookupWithQuery(ctx, s.parent.queries.refreshFindForUpdate, id, keys)
}

func (s *refreshStore) lookupWithQuery(
	ctx context.Context,
	query string,
	id string,
	keys [2]string,
) (*store.RefreshToken, string, error) {
	var (
		t        store.RefreshToken
		stored   string
		scope    []byte
		amr      []byte
		details  []byte
		extra    []byte
		parent   *string
		consumed *int64
		expires  int64
		created  int64
		revoked  int64
		subPub   int64
		authTime int64
		origin   string
	)
	err := s.runner().QueryRowContext(ctx, query, keys[0], keys[1]).Scan(
		&stored, &t.ClientID, &t.Subject, &subPub, &t.GrantID,
		&scope, &t.Resource, &origin, &authTime, &t.ACR, &amr, &details, &extra,
		&parent, &consumed, &expires, &created,
		&t.DPoPJKT, &t.MTLSCertThumbprint, &t.Nonce, &revoked,
	)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, "", store.ErrNotFound
	}
	if err != nil {
		return nil, "", wrapErr("refreshes.Find", err)
	}
	if !refreshKeyMatches(stored, keys) {
		return nil, "", store.ErrNotFound
	}
	dec, err := decodeStrings(scope)
	if err != nil {
		return nil, "", err
	}
	amrDec, err := decodeStrings(amr)
	if err != nil {
		return nil, "", err
	}
	detailsDec, err := decodeObjectArray(details)
	if err != nil {
		return nil, "", err
	}
	extraDec, err := decodeMap(extra)
	if err != nil {
		return nil, "", err
	}
	t.ID = id
	t.SubjectPublic = int64ToBool(subPub)
	t.Scope = dec
	t.ParentID = parent
	t.ConsumedAt = int64PtrToTimePtr(consumed)
	t.ExpiresAt = int64ToTime(expires)
	t.CreatedAt = int64ToTime(created)
	t.Revoked = int64ToBool(revoked)
	t.Origin = store.RefreshTokenOrigin(origin)
	t.AuthTime = int64ToTime(authTime)
	t.AMR = amrDec
	t.AuthorizationDetails = detailsDec
	t.AccessTokenExtra = extraDec
	return &t, stored, nil
}

// refreshCredentialKeys derives the lookup keys for a bearer-credential
// presentation: the presented value is hashed and only the digest is matched
// (both slots hold the digest), so possession of a stored digest alone never
// resolves a row.
func refreshCredentialKeys(id string) [2]string {
	d := patterns.Digest(id)
	return [2]string{d, d}
}

// refreshHandleKeys derives the lookup keys for an internal chain handle: the
// value may be a raw id or a stored digest, so both representations resolve.
func refreshHandleKeys(id string) [2]string {
	return [2]string{patterns.Digest(id), id}
}

func refreshKeyMatches(stored string, keys [2]string) bool {
	return patterns.ConstantTimeKeyMatch(stored, keys[0]) ||
		patterns.ConstantTimeKeyMatch(stored, keys[1])
}

func (s *refreshStore) Find(ctx context.Context, id string) (*store.RefreshToken, error) {
	t, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// FindByStoredHandle implements [store.RefreshChainResolver]. The handle is an
// internal chain pointer (a stored parent/root digest previously returned as
// [store.RefreshToken.ParentID], or a raw root id from a depth-0 walk), not a
// bearer credential, so the tolerant lookup that accepts the digest verbatim is
// safe here: it is reachable only from the OP's own replay-revocation walk,
// never from the public Find/Consume credential path.
func (s *refreshStore) FindByStoredHandle(ctx context.Context, handle string) (*store.RefreshToken, error) {
	t, _, err := s.findStoredByHandle(ctx, handle)
	return t, err
}

func (s *refreshStore) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	now := s.parent.clock.Now()
	// Consume is intentionally write-first. A snapshot-establishing read
	// before this conditional update is unsafe under MySQL repeatable-read:
	// a concurrent rotation can win the write while a stale snapshot still
	// reports the predecessor as unconsumed. The update itself serialises the
	// one winner and also rejects naturally expired rows.
	res, err := s.runner().ExecContext(ctx, s.parent.queries.refreshConsume,
		timeToInt64(now), patterns.Digest(id), timeToInt64(now))
	if err != nil {
		return nil, wrapErr("refreshes.Consume", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, wrapErr("refreshes.Consume.RowsAffected", err)
	}
	// A locking read after the write sees the current committed version even
	// inside a repeatable-read transaction. SQLite has no FOR UPDATE suffix,
	// but its write lock already serialises this read with another writer.
	t, _, err := s.lookupForUpdate(ctx, id, refreshCredentialKeys(id))
	if errors.Is(err, store.ErrNotFound) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if n > 0 {
		// The row was just marked by this call. Keep the exact database
		// value when available; the fallback covers drivers that scan a
		// nullable consumed_at as nil immediately after the write.
		if t.ConsumedAt == nil {
			t.ConsumedAt = &now
		}
		return t, nil
	}
	if t.ConsumedAt != nil {
		return t, store.ErrAlreadyConsumed
	}
	if isExpired(t.ExpiresAt, s.parent.clock) {
		return nil, store.ErrNotFound
	}
	return nil, store.ErrAlreadyConsumed
}

// RevokeChain marks every refresh token in the rotation chain rooted
// at rootID as consumed. Backends that delete or mark equivalently
// satisfy the contract; the SQL adapter marks (preserving the audit
// trail). The walk is bounded by the chain depth, which the library
// caps at the refresh-token TTL by construction.
//
// The walk operates entirely in the stored-ID space: rootID may be a raw
// bearer secret or a digest returned from Find, and findStored resolves it
// to the exact id column value before the BFS starts. Descendant lookup
// compares parent_id against those stored digest values, keeping the graph
// internally consistent without ever persisting raw parent secrets.
//
// Atomicity: when the substore is not already running inside a
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
	// rootID is a chain handle (a stored digest from FindRoot, or a raw root
	// id for a depth-0 chain), not a bearer credential, so resolve it through
	// the tolerant handle lookup rather than the hash-only credential path.
	_, rootStoredID, err := s.findStoredByHandle(ctx, rootID)
	if err != nil {
		return err
	}
	now := s.parent.clock.Now()
	visited := map[string]struct{}{rootStoredID: {}}
	queue := []string{rootStoredID}
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

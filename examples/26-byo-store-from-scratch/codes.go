//go:build example

// codes.go — store.AuthorizationCodeStore (vault_grant_codes) and
// store.RefreshTokenStore (vault_renewal_slips).
//
// Both substores belong to the atomic-routing cluster. They are
// constructed against a querier so the same code runs on the database
// or inside a transaction. Both honour the hash-on-store contract: the
// bearer secret (code / refresh-token id) is hashed before it reaches
// the database and looked up by digest, never stored raw.
//
// The refresh substore draws one further line, between the two kinds of
// value it is handed:
//
//   - A BEARER CREDENTIAL — the refresh_token the client presents — only
//     ever reaches the database as a digest, and only ever matches a row
//     whose stored digest equals the digest of what was presented. Find
//     and Consume are the credential paths.
//   - A CHAIN HANDLE — the pointer from a rotated token to its
//     predecessor — is not a credential. It never leaves the OP: it
//     travels from this store to the replay-revocation walk and back. So
//     it may be persisted and returned in digest form, which is what
//     keeps every superseded generation's raw secret out of the database.
//     FindByStoredHandle and RevokeChain are the handle paths.

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- authorization codes -------------------------------------------------

type authCodeStore struct {
	q   querier
	now func() time.Time
}

const (
	authCodeInsert = `
INSERT INTO vault_grant_codes
  (token_secret_digest, relying_party, principal, ledger_id, return_target,
   requested_scope, resource_hint, pkce_challenge, pkce_method, nonce_echo,
   state_echo, dpop_thumb, expires_epoch, consumed_epoch, issued_epoch)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	authCodeSelect = `
SELECT token_secret_digest, relying_party, principal, ledger_id, return_target,
       requested_scope, resource_hint, pkce_challenge, pkce_method, nonce_echo,
       state_echo, dpop_thumb, expires_epoch, consumed_epoch, issued_epoch
FROM vault_grant_codes WHERE token_secret_digest = ?`

	authCodeConsume = `
UPDATE vault_grant_codes SET consumed_epoch = ?
WHERE token_secret_digest = ? AND consumed_epoch IS NULL`
)

func (s *authCodeStore) Save(ctx context.Context, code *store.AuthorizationCode) error {
	d := digest(code.ID)
	_, err := s.q.ExecContext(ctx, authCodeInsert,
		d, code.ClientID, code.Subject, code.GrantID, code.RedirectURI,
		encodeStrings(code.Scope), code.Resource, code.CodeChallenge, code.CodeChallengeMethod,
		code.Nonce, code.State, code.DPoPJKT,
		epochOf(code.ExpiresAt), epochPtr(code.ConsumedAt), epochOf(code.CreatedAt))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return fmt.Errorf("authCodes.Save: %w", err)
	}
	return nil
}

func (s *authCodeStore) Find(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	rec, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if expiredStrict(rec.ExpiresAt, s.now()) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

// find resolves a row by digest and restores the caller's raw ID onto
// the returned record. It does not filter on expiry so Consume can
// return a post-mortem record.
func (s *authCodeStore) find(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	d := digest(id)
	var (
		c        store.AuthorizationCode
		stored   string
		scope    string
		expires  int64
		consumed *int64
		created  int64
	)
	err := s.q.QueryRowContext(ctx, authCodeSelect, d).Scan(
		&stored, &c.ClientID, &c.Subject, &c.GrantID, &c.RedirectURI,
		&scope, &c.Resource, &c.CodeChallenge, &c.CodeChallengeMethod,
		&c.Nonce, &c.State, &c.DPoPJKT,
		&expires, &consumed, &created,
	)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("authCodes.find: %w", err)
	}
	if !constantTimeMatch(stored, d) {
		return nil, store.ErrNotFound
	}
	c.ID = id
	c.Scope = decodeStrings(scope)
	c.ExpiresAt = timeOf(expires)
	c.ConsumedAt = timePtr(consumed)
	c.CreatedAt = timeOf(created)
	return &c, nil
}

func (s *authCodeStore) Consume(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	rec, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if expiredStrict(rec.ExpiresAt, s.now()) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		// Replay: return the consumed record so the caller can recover
		// GrantID for the revocation cascade.
		return rec, store.ErrAlreadyConsumed
	}
	now := s.now()
	res, err := s.q.ExecContext(ctx, authCodeConsume, now.Unix(), digest(id))
	if err != nil {
		return nil, fmt.Errorf("authCodes.Consume: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("authCodes.Consume.RowsAffected: %w", err)
	}
	if n == 0 {
		// Lost the compare-and-swap to a concurrent Consume.
		if replay, ferr := s.find(ctx, id); ferr == nil && replay.ConsumedAt != nil {
			return replay, store.ErrAlreadyConsumed
		}
		return nil, store.ErrAlreadyConsumed
	}
	rec.ConsumedAt = &now
	return rec, nil
}

// --- refresh tokens ------------------------------------------------------

type refreshStore struct {
	q   querier
	now func() time.Time

	// db is set only when the substore was handed out by the plain
	// store, and is nil when it came from a transaction. Saving a
	// rotated token needs its own transaction so a rejected rotation
	// can be rolled back (see save); when the caller already supplied
	// one, that rollback is theirs to perform.
	db *databasesql.DB
}

// Compile-time proof of the optional companions this substore opts into.
// [store.RefreshChainResolver] is what licenses the digest-only parent
// pointer: it gives the revocation walk a way to resolve a stored handle
// that does not run through the bearer-credential Find.
var (
	_ store.RefreshTokenStore         = (*refreshStore)(nil)
	_ store.RefreshChainResolver      = (*refreshStore)(nil)
	_ store.RefreshRetryResponseStore = (*refreshStore)(nil)
)

const (
	refreshInsert = `
INSERT INTO vault_renewal_slips
  (token_secret_digest, relying_party, principal, ledger_id, requested_scope,
   resource_hint, principal_is_wire, origin_kind, auth_epoch, acr_value,
   amr_values, authorization_detail, access_token_extra, parent_secret_digest,
   retry_sealed,
   dpop_thumb, mtls_thumb, nonce_echo, is_void, expires_epoch, consumed_epoch,
   issued_epoch)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	// refreshRetrySelect joins the successor row that carries the sealed
	// response back to the predecessor it is keyed by, because the
	// retention bound belongs to the predecessor and the row holding the
	// bytes is the successor — whose expiry is later by construction.
	// store.RefreshRetryResponseStore forbids keeping a response past the
	// predecessor's own refresh-token lifetime, so the predecessor's
	// expires_epoch, not the successor's, decides whether this read may
	// answer. A predecessor row that is gone answers nothing: the client
	// could not have presented that token either.
	refreshRetrySelect = `
SELECT successor.retry_sealed
FROM vault_renewal_slips AS successor
JOIN vault_renewal_slips AS predecessor
  ON predecessor.token_secret_digest = successor.parent_secret_digest
WHERE successor.parent_secret_digest = ? AND successor.retry_sealed IS NOT NULL
  AND (predecessor.expires_epoch = 0 OR predecessor.expires_epoch >= ?)`

	// refreshSelect takes two keys rather than one so a single statement
	// serves both lookup kinds: the credential path binds the same digest
	// twice, the handle path binds (digest, verbatim). See refreshKeys.
	refreshSelect = `
SELECT token_secret_digest, relying_party, principal, ledger_id, requested_scope,
       resource_hint, principal_is_wire, origin_kind, auth_epoch, acr_value,
       amr_values, authorization_detail, access_token_extra, parent_secret_digest,
       dpop_thumb, mtls_thumb, nonce_echo, is_void, expires_epoch, consumed_epoch,
       issued_epoch
FROM vault_renewal_slips WHERE token_secret_digest = ? OR token_secret_digest = ?`

	refreshConsume = `
UPDATE vault_renewal_slips SET consumed_epoch = ?
WHERE token_secret_digest = ? AND consumed_epoch IS NULL`

	refreshMark = `
UPDATE vault_renewal_slips SET consumed_epoch = ?, is_void = 1
WHERE token_secret_digest = ?`

	refreshParentVoid = `
SELECT is_void FROM vault_renewal_slips WHERE token_secret_digest = ?`

	refreshChildren = `
SELECT token_secret_digest FROM vault_renewal_slips WHERE parent_secret_digest = ?`

	refreshByGrant = `
UPDATE vault_renewal_slips SET consumed_epoch = ?, is_void = 1 WHERE ledger_id = ?`
)

func (s *refreshStore) Save(ctx context.Context, t *store.RefreshToken) error {
	return s.save(ctx, t, nil)
}

// SaveRotationWithRetry implements [store.RefreshRetryResponseStore]. The
// sealed response rides along in the successor's INSERT, which is what
// makes the pair atomic: there is no window in which the successor exists
// without its retry copy, so a client that retries a rotation whose
// response it never received cannot be answered with a second branch of
// the chain. A store that could not write both in one operation is
// required not to expose this interface at all.
func (s *refreshStore) SaveRotationWithRetry(ctx context.Context, successor *store.RefreshToken, sealed []byte) error {
	if successor == nil || successor.ParentID == nil {
		// A root token has no predecessor to key the response by, so
		// there is nothing a retry could present.
		return errors.New("refreshes.SaveRotationWithRetry: successor has no parent")
	}
	return s.save(ctx, successor, sealed)
}

// LoadRetryResponse implements [store.RefreshRetryResponseStore].
// predecessorID arrives raw — it is the refresh_token the client just
// re-presented — so it is hashed here and matched against the stored
// digest. Nothing on this path accepts a stored digest verbatim: a
// database reader holds no value that redeems a cached response.
//
// The read is bounded by the predecessor's own expiry as well: the
// interface allows a store to retain a sealed response no longer than the
// refresh token it was cached against, and past that instant the OP would
// refuse the presented token anyway, so re-delivering a response for it
// would hand back credentials derived from a token the endpoint has
// stopped accepting. Rows are reclaimed on a schedule the embedder owns;
// this bound is what makes the read independent of when that runs.
func (s *refreshStore) LoadRetryResponse(ctx context.Context, predecessorID string) ([]byte, error) {
	var sealed []byte
	err := s.q.QueryRowContext(ctx, refreshRetrySelect,
		digest(predecessorID), epochOf(s.now())).Scan(&sealed)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("refreshes.LoadRetryResponse: %w", err)
	}
	return sealed, nil
}

// save persists t. A token that roots its own chain is a plain INSERT; a
// rotated token additionally has to prove its parent's chain is still
// alive, which is what saveRotation does.
func (s *refreshStore) save(ctx context.Context, t *store.RefreshToken, sealed []byte) error {
	if t.ParentID == nil {
		return s.insert(ctx, s.q, t, sealed)
	}
	if s.db == nil {
		// Already inside the caller's transaction: do the work on it and
		// let the caller roll back when saveRotation refuses.
		return s.saveRotation(ctx, s.q, t, sealed)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("refreshes.Save.begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.saveRotation(ctx, txQuerier{tx: tx}, t, sealed); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("refreshes.Save.commit: %w", err)
	}
	return nil
}

// saveRotation writes the rotated token and then re-reads its parent,
// refusing the rotation with [store.ErrAlreadyConsumed] when the parent
// turns out to belong to a revoked chain. Writing a live child onto a
// dead chain would resurrect it, which is exactly the replay RFC 9700
// §2.2.2 revocation exists to stop.
//
// The INSERT deliberately comes first. Checking the parent and then
// inserting leaves a window in which a concurrent RevokeChain walks past
// a child that does not exist yet and the child survives the revocation.
// Inserting first closes it: the revoking walk either sees the new row
// and marks it, or has not committed yet — in which case this re-read
// blocks on it and observes the revoked parent. A parent that is simply
// gone proves no revocation, so the rotation stands.
//
// t.ParentID is raw on this path: a rotation Save carries the raw id of
// the refresh token the library has just consumed, so it is hashed here
// to reach the parent's row.
func (s *refreshStore) saveRotation(ctx context.Context, q querier, t *store.RefreshToken, sealed []byte) error {
	if err := s.insert(ctx, q, t, sealed); err != nil {
		return err
	}
	var void int64
	err := q.QueryRowContext(ctx, refreshParentVoid, digest(*t.ParentID)).Scan(&void)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("refreshes.Save.recheck: %w", err)
	}
	if void == 1 {
		return store.ErrAlreadyConsumed
	}
	return nil
}

// insert is the single raw write both paths funnel through, so the
// column order lives in exactly one place.
//
// Both secrets the library hands in are raw and both are hashed on the
// way to the database: t.ID is the refresh_token about to be returned to
// the client, and t.ParentID — non-nil only on a rotation — is the raw id
// of the token just consumed. The parent lands in the same digest space
// its own row is keyed by, which is what lets the revocation walk follow
// the pointers without either generation's raw secret being stored.
func (s *refreshStore) insert(ctx context.Context, q querier, t *store.RefreshToken, sealed []byte) error {
	_, err := q.ExecContext(ctx, refreshInsert,
		digest(t.ID), t.ClientID, t.Subject, t.GrantID,
		encodeStrings(t.Scope), t.Resource, boolToInt(t.SubjectPublic),
		string(t.Origin), epochOf(t.AuthTime), t.ACR, encodeStrings(t.AMR),
		encodeObjectArray(t.AuthorizationDetails), encodeMap(t.AccessTokenExtra),
		digestNullable(t.ParentID), sealed,
		t.DPoPJKT, t.MTLSCertThumbprint, t.Nonce, boolToInt(t.Revoked),
		epochOf(t.ExpiresAt), epochPtr(t.ConsumedAt), epochOf(t.CreatedAt))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return fmt.Errorf("refreshes.Save: %w", err)
	}
	return nil
}

func (s *refreshStore) Find(ctx context.Context, id string) (*store.RefreshToken, error) {
	return s.find(ctx, id)
}

// FindByStoredHandle implements [store.RefreshChainResolver]. It resolves a
// chain handle — the digest this store returns as [store.RefreshToken.ParentID],
// or the raw id the walk started from when the replayed token roots its own
// chain — and it does NOT re-hash a value that is already a stored digest.
//
// Only the OP's replay-revocation walk reaches this method, and the walk
// revokes rather than issues, so admitting a stored digest here costs nothing:
// the credential paths (Find, Consume) still refuse it, which is what makes a
// digest read out of a backup inert.
func (s *refreshStore) FindByStoredHandle(ctx context.Context, handle string) (*store.RefreshToken, error) {
	t, _, err := s.findHandle(ctx, handle)
	return t, err
}

// find resolves a value presented as a BEARER CREDENTIAL: the presented id is
// hashed and only the resulting digest can match, so a digest lifted from a
// database snapshot is not redeemable. An expired row reads as absent, never as
// a live or already-consumed record — natural expiry is not replay evidence and
// must not trigger a revocation cascade.
//
// The returned record's ID is restored to the caller's raw value; its ParentID
// is a chain handle (see findHandle).
func (s *refreshStore) find(ctx context.Context, id string) (*store.RefreshToken, error) {
	t, _, err := s.lookup(ctx, id, refreshCredentialKeys(id))
	if err != nil {
		return nil, err
	}
	if expiredStrict(t.ExpiresAt, s.now()) {
		return nil, store.ErrNotFound
	}
	return t, nil
}

// findHandle resolves a value presented as a CHAIN HANDLE and additionally
// returns the row's stored digest, which the revocation walk needs as its
// queue key. Expiry is not filtered: a chain must stay revocable after its
// tokens have aged out, for as long as the rows are retained.
func (s *refreshStore) findHandle(ctx context.Context, handle string) (*store.RefreshToken, string, error) {
	return s.lookup(ctx, handle, refreshHandleKeys(handle))
}

// refreshCredentialKeys derives the lookup keys for a bearer credential. Both
// slots hold the digest of the presented secret, so possession of a stored
// digest alone never resolves a row.
func refreshCredentialKeys(id string) [2]string {
	d := digest(id)
	return [2]string{d, d}
}

// refreshHandleKeys derives the lookup keys for a chain handle: a stored
// parent digest matches verbatim, and a raw id matches through its digest.
// Both have to resolve because a walk that starts at a token with no parent
// hands the raw id straight back as the chain root.
func refreshHandleKeys(handle string) [2]string {
	return [2]string{digest(handle), handle}
}

func refreshKeyMatches(stored string, keys [2]string) bool {
	return constantTimeMatch(stored, keys[0]) || constantTimeMatch(stored, keys[1])
}

// lookup is the single row read both presentations funnel through. keys
// decides what may match; nothing else about the two paths differs.
func (s *refreshStore) lookup(ctx context.Context, id string, keys [2]string) (*store.RefreshToken, string, error) {
	var (
		t        store.RefreshToken
		stored   string
		scope    string
		amr      string
		details  string
		extra    string
		parent   *string
		consumed *int64
		expires  int64
		created  int64
		void     int64
		subPub   int64
		authE    int64
		origin   string
	)
	err := s.q.QueryRowContext(ctx, refreshSelect, keys[0], keys[1]).Scan(
		&stored, &t.ClientID, &t.Subject, &t.GrantID, &scope,
		&t.Resource, &subPub, &origin, &authE, &t.ACR, &amr, &details, &extra,
		&parent, &t.DPoPJKT, &t.MTLSCertThumbprint, &t.Nonce, &void,
		&expires, &consumed, &created,
	)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, "", store.ErrNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("refreshes.find: %w", err)
	}
	if !refreshKeyMatches(stored, keys) {
		return nil, "", store.ErrNotFound
	}
	t.ID = id
	t.SubjectPublic = subPub == 1
	t.Scope = decodeStrings(scope)
	t.Origin = store.RefreshTokenOrigin(origin)
	t.AuthTime = timeOf(authE)
	t.AMR = decodeStrings(amr)
	t.AuthorizationDetails = decodeObjectArray(details)
	t.AccessTokenExtra = decodeMap(extra)
	// parent is the digest column, so the ParentID handed back is itself a
	// chain handle and the walk can keep climbing with it.
	t.ParentID = parent
	t.ConsumedAt = timePtr(consumed)
	t.ExpiresAt = timeOf(expires)
	t.CreatedAt = timeOf(created)
	t.Revoked = void == 1
	return &t, stored, nil
}

// Consume is a credential path: id is the raw refresh_token the client
// presented, so the compare-and-set targets its digest.
func (s *refreshStore) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	t, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if t.ConsumedAt != nil {
		// Replay: return the consumed record so the caller can recover
		// the chain root for refresh-token replay revocation.
		return t, store.ErrAlreadyConsumed
	}
	now := s.now()
	res, err := s.q.ExecContext(ctx, refreshConsume, now.Unix(), digest(id))
	if err != nil {
		return nil, fmt.Errorf("refreshes.Consume: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("refreshes.Consume.RowsAffected: %w", err)
	}
	if n == 0 {
		// Lost the compare-and-swap to a concurrent Consume.
		if replay, ferr := s.find(ctx, id); ferr == nil && replay.ConsumedAt != nil {
			return replay, store.ErrAlreadyConsumed
		}
		return nil, store.ErrAlreadyConsumed
	}
	t.ConsumedAt = &now
	return t, nil
}

// RevokeChain marks every token in the rotation chain rooted at rootID
// consumed + void.
//
// rootID is a chain handle, not a credential: the revocation walk hands
// back the stored parent digest it climbed to, or the raw id it started
// from when the replayed token roots its own chain. Both resolve, and the
// row's own stored digest seeds the traversal — from there the walk stays
// entirely in digest space, since every descendant lookup matches the
// parent_secret_digest the child was written with.
func (s *refreshStore) RevokeChain(ctx context.Context, rootID string) error {
	_, root, err := s.findHandle(ctx, rootID)
	if err != nil {
		return err
	}
	now := s.now().Unix()
	visited := map[string]struct{}{root: {}}
	queue := []string{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if _, err := s.q.ExecContext(ctx, refreshMark, now, cur); err != nil {
			return fmt.Errorf("refreshes.RevokeChain.mark: %w", err)
		}
		children, err := s.childrenOf(ctx, cur)
		if err != nil {
			return err
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

func (s *refreshStore) childrenOf(ctx context.Context, parentDigest string) ([]string, error) {
	rows, err := s.q.QueryContext(ctx, refreshChildren, parentDigest)
	if err != nil {
		return nil, fmt.Errorf("refreshes.RevokeChain.children: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, fmt.Errorf("refreshes.RevokeChain.scan: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("refreshes.RevokeChain.iter: %w", err)
	}
	return out, nil
}

// RevokeByGrant marks every token under grantID consumed + void. A
// missing grant is not an error.
func (s *refreshStore) RevokeByGrant(ctx context.Context, grantID string) error {
	if _, err := s.q.ExecContext(ctx, refreshByGrant, s.now().Unix(), grantID); err != nil {
		return fmt.Errorf("refreshes.RevokeByGrant: %w", err)
	}
	return nil
}

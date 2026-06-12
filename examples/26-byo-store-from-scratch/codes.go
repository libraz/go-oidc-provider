//go:build example

// codes.go — store.AuthorizationCodeStore (vault_grant_codes) and
// store.RefreshTokenStore (vault_renewal_slips).
//
// Both substores belong to the atomic-routing cluster. They are
// constructed against a querier so the same code runs on the database
// or inside a transaction. Both honour the hash-on-store contract: the
// bearer secret (code / refresh-token id) is hashed before it reaches
// the database and looked up by digest, never stored raw.

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
		&expires, &consumed, &created)
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
}

const (
	refreshInsert = `
INSERT INTO vault_renewal_slips
  (token_secret_digest, relying_party, principal, ledger_id, requested_scope,
   resource_hint, principal_is_wire, origin_kind, auth_epoch, acr_value,
   amr_values, authorization_detail, access_token_extra, parent_secret_digest,
   dpop_thumb, mtls_thumb, nonce_echo, is_void, expires_epoch, consumed_epoch,
   issued_epoch)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	refreshSelect = `
SELECT token_secret_digest, relying_party, principal, ledger_id, requested_scope,
       resource_hint, principal_is_wire, origin_kind, auth_epoch, acr_value,
       amr_values, authorization_detail, access_token_extra, parent_secret_digest,
       dpop_thumb, mtls_thumb, nonce_echo, is_void, expires_epoch, consumed_epoch,
       issued_epoch
FROM vault_renewal_slips WHERE token_secret_digest = ?`

	refreshConsume = `
UPDATE vault_renewal_slips SET consumed_epoch = ?
WHERE token_secret_digest = ? AND consumed_epoch IS NULL`

	refreshMark = `
UPDATE vault_renewal_slips SET consumed_epoch = ?, is_void = 1
WHERE token_secret_digest = ?`

	refreshChildren = `
SELECT token_secret_digest FROM vault_renewal_slips WHERE parent_secret_digest = ?`

	refreshByGrant = `
UPDATE vault_renewal_slips SET consumed_epoch = ?, is_void = 1 WHERE ledger_id = ?`
)

func (s *refreshStore) Save(ctx context.Context, t *store.RefreshToken) error {
	_, err := s.q.ExecContext(ctx, refreshInsert,
		digest(t.ID), t.ClientID, t.Subject, t.GrantID,
		encodeStrings(t.Scope), t.Resource, boolToInt(t.SubjectPublic),
		string(t.Origin), epochOf(t.AuthTime), t.ACR, encodeStrings(t.AMR),
		encodeObjectArray(t.AuthorizationDetails), encodeMap(t.AccessTokenExtra),
		digestNullable(t.ParentID),
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

// find resolves a row by digest. The returned record's ID is restored
// to the caller's raw value; ParentID stays a digest because the chain
// walk in RevokeChain consumes parent pointers as digests.
func (s *refreshStore) find(ctx context.Context, id string) (*store.RefreshToken, error) {
	d := digest(id)
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
	err := s.q.QueryRowContext(ctx, refreshSelect, d).Scan(
		&stored, &t.ClientID, &t.Subject, &t.GrantID, &scope,
		&t.Resource, &subPub, &origin, &authE, &t.ACR, &amr, &details, &extra,
		&parent, &t.DPoPJKT, &t.MTLSCertThumbprint, &t.Nonce, &void,
		&expires, &consumed, &created)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("refreshes.find: %w", err)
	}
	if !constantTimeMatch(stored, d) {
		return nil, store.ErrNotFound
	}
	t.ID = id
	t.SubjectPublic = subPub == 1
	t.Scope = decodeStrings(scope)
	t.Origin = store.RefreshTokenOrigin(origin)
	t.AuthTime = timeOf(authE)
	t.AMR = decodeStrings(amr)
	t.AuthorizationDetails = decodeObjectArray(details)
	t.AccessTokenExtra = decodeMap(extra)
	t.ParentID = parent
	t.ConsumedAt = timePtr(consumed)
	t.ExpiresAt = timeOf(expires)
	t.CreatedAt = timeOf(created)
	t.Revoked = void == 1
	return &t, nil
}

func (s *refreshStore) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	t, err := s.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if t.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
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
		return nil, store.ErrAlreadyConsumed
	}
	t.ConsumedAt = &now
	return t, nil
}

// RevokeChain marks every token in the rotation chain rooted at rootID
// consumed + void. The walk operates entirely in digest space: rootID
// is hashed once, every descendant lookup uses the parent_secret_digest
// the row was stored with, and the queue holds digests.
func (s *refreshStore) RevokeChain(ctx context.Context, rootID string) error {
	if _, err := s.find(ctx, rootID); err != nil {
		return err
	}
	now := s.now().Unix()
	root := digest(rootID)
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

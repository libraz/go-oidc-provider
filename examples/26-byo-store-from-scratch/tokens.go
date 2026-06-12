//go:build example

// tokens.go — store.AccessTokenRegistry against vault_wire_tokens. The
// registry is the JWT access-token shadow: Register writes a row at
// issuance, Revoke* flip is_void, GC drops expired rows. Part of the
// atomic-routing cluster.

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

type accessTokenStore struct{ q querier }

const (
	atRegister = `
INSERT INTO vault_wire_tokens
  (ticket_id, ledger_id, principal, relying_party, granted_scope,
   issued_epoch, expires_epoch, is_void)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	atSelect = `
SELECT ticket_id, ledger_id, principal, relying_party, granted_scope,
       issued_epoch, expires_epoch, is_void
FROM vault_wire_tokens WHERE ticket_id = ?`

	atRevokeByJTI   = `UPDATE vault_wire_tokens SET is_void = 1 WHERE ticket_id = ?`
	atRevokeByGrant = `UPDATE vault_wire_tokens SET is_void = 1 WHERE ledger_id = ? AND is_void = 0`
	atGC            = `DELETE FROM vault_wire_tokens WHERE expires_epoch <> 0 AND expires_epoch < ?`
)

func (s *accessTokenStore) Register(ctx context.Context, rec store.AccessTokenRecord) error {
	if rec.JTI == "" {
		return errors.New("scratch: AccessTokenRecord requires a non-empty JTI")
	}
	_, err := s.q.ExecContext(ctx, atRegister,
		rec.JTI, rec.GrantID, rec.Subject, rec.ClientID, encodeStrings(rec.Scopes),
		epochOf(rec.IssuedAt), epochOf(rec.ExpiresAt), boolToInt(rec.Revoked))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return fmt.Errorf("accessTokens.Register: %w", err)
	}
	return nil
}

// Find returns (nil, nil) for an absent record, the shape the contract
// permits so callers distinguish "not registered" from a fault.
func (s *accessTokenStore) Find(ctx context.Context, jti string) (*store.AccessTokenRecord, error) {
	if jti == "" {
		return nil, nil //nolint:nilnil // contract permits (nil, nil) for absent records.
	}
	var (
		rec     store.AccessTokenRecord
		scopes  string
		issued  int64
		expires int64
		void    int64
	)
	err := s.q.QueryRowContext(ctx, atSelect, jti).Scan(
		&rec.JTI, &rec.GrantID, &rec.Subject, &rec.ClientID, &scopes,
		&issued, &expires, &void)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, nil //nolint:nilnil // contract permits (nil, nil) for absent records.
	}
	if err != nil {
		return nil, fmt.Errorf("accessTokens.Find: %w", err)
	}
	rec.Scopes = decodeStrings(scopes)
	rec.IssuedAt = timeOf(issued)
	rec.ExpiresAt = timeOf(expires)
	rec.Revoked = void == 1
	return &rec, nil
}

func (s *accessTokenStore) RevokeByJTI(ctx context.Context, jti string) error {
	if jti == "" {
		return nil
	}
	if _, err := s.q.ExecContext(ctx, atRevokeByJTI, jti); err != nil {
		return fmt.Errorf("accessTokens.RevokeByJTI: %w", err)
	}
	return nil
}

func (s *accessTokenStore) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	if grantID == "" {
		return 0, nil
	}
	res, err := s.q.ExecContext(ctx, atRevokeByGrant, grantID)
	if err != nil {
		return 0, fmt.Errorf("accessTokens.RevokeByGrant: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("accessTokens.RevokeByGrant.RowsAffected: %w", err)
	}
	return int(n), nil
}

func (s *accessTokenStore) GC(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.q.ExecContext(ctx, atGC, cutoff.Unix())
	if err != nil {
		return 0, fmt.Errorf("accessTokens.GC: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("accessTokens.GC.RowsAffected: %w", err)
	}
	return int(n), nil
}

package oidcsql

import (
	"context"
	"crypto/sha256"
	databasesql "database/sql"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// opaqueAccessTokenStore is the SQL implementation of
// [store.OpaqueAccessTokenStore] (ADR 0024). The substore keys rows on
// the SHA-256 digest of the raw bearer ID, never the raw value, so a
// database leak alone does not yield usable tokens.
type opaqueAccessTokenStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newOpaqueAccessTokenStore(s *Store, tx *databasesql.Tx) *opaqueAccessTokenStore {
	return &opaqueAccessTokenStore{parent: s, tx: tx}
}

func (s *opaqueAccessTokenStore) runner() runner { return pickRunner(s.parent, s.tx) }

// digest hashes the raw bearer ID. Returning []byte rather than a hex
// string lets the binary PK column store the 32-byte value verbatim
// across MySQL VARBINARY, Postgres BYTEA, and SQLite BLOB.
func (s *opaqueAccessTokenStore) digest(rawID string) []byte {
	sum := sha256.Sum256([]byte(rawID))
	return sum[:]
}

// Save implements [store.OpaqueAccessTokenStore]. The raw ID is hashed
// before binding so the database never sees the bearer secret in
// plaintext.
func (s *opaqueAccessTokenStore) Save(ctx context.Context, tok *store.OpaqueAccessToken) error {
	if tok == nil {
		return errors.New("oidcsql: nil opaque access token")
	}
	if tok.ID == "" {
		return errors.New("oidcsql: OpaqueAccessToken requires a non-empty ID")
	}
	hash := s.digest(tok.ID)
	_, err := s.runner().ExecContext(ctx, s.parent.queries.opaqueAccessTokenSave,
		hash, tok.GrantID, tok.Subject, tok.ClientID, tok.Audience,
		encodeStrings(tok.Scope), tok.ACR, encodeStrings(tok.AMR),
		timeToInt64(tok.AuthTime), tok.DPoPJKT, tok.MTLSCertThumbprint,
		timeToInt64(tok.IssuedAt), timeToInt64(tok.ExpiresAt),
		boolToInt64(tok.Revoked))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return wrapErr("opaqueAccessTokens.Save", err)
	}
	return nil
}

// Find implements [store.OpaqueAccessTokenStore]. The presented id is
// hashed before lookup; revoked or expired records are returned with
// their flags intact so the caller (introspection, userinfo) can
// inspect them.
func (s *opaqueAccessTokenStore) Find(ctx context.Context, id string) (*store.OpaqueAccessToken, error) {
	if id == "" {
		return nil, store.ErrNotFound
	}
	hash := s.digest(id)
	var (
		tok      store.OpaqueAccessToken
		scope    []byte
		amr      []byte
		authTime int64
		issued   int64
		expires  int64
		revoked  int64
	)
	// token_hash is selected for round-trip parity with the INSERT
	// column list but discarded on the way out: the lookup already
	// matched the hash via the WHERE clause, and the caller receives
	// the raw ID restored at the bottom of the function. A discard
	// target is bound so the column count agrees with the SELECT.
	var hashOut []byte
	err := s.runner().QueryRowContext(ctx, s.parent.queries.opaqueAccessTokenFind, hash).Scan(
		&hashOut, &tok.GrantID, &tok.Subject, &tok.ClientID, &tok.Audience,
		&scope, &tok.ACR, &amr,
		&authTime, &tok.DPoPJKT, &tok.MTLSCertThumbprint,
		&issued, &expires, &revoked)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("opaqueAccessTokens.Find", err)
	}
	scopeDec, err := decodeStrings(scope)
	if err != nil {
		return nil, err
	}
	amrDec, err := decodeStrings(amr)
	if err != nil {
		return nil, err
	}
	tok.Scope = scopeDec
	tok.AMR = amrDec
	tok.AuthTime = int64ToTime(authTime)
	tok.IssuedAt = int64ToTime(issued)
	tok.ExpiresAt = int64ToTime(expires)
	tok.Revoked = int64ToBool(revoked)
	// Restore the raw ID for the caller so the returned record is
	// indistinguishable from what was passed to Save. The stored row
	// retains the digest in token_hash; the field is not surfaced.
	tok.ID = id
	return &tok, nil
}

// RevokeByID implements [store.OpaqueAccessTokenStore]. The call is
// idempotent: a missing hash returns nil so the revocation endpoint
// stays aligned with RFC 7009 §2.2.
func (s *opaqueAccessTokenStore) RevokeByID(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	if _, err := s.runner().ExecContext(ctx,
		s.parent.queries.opaqueAccessTokenRevokeByID, s.digest(id)); err != nil {
		return wrapErr("opaqueAccessTokens.RevokeByID", err)
	}
	return nil
}

// RevokeByGrant implements [store.OpaqueAccessTokenStore]. Returns the
// number of rows the call flipped (rows already revoked are not
// counted, mirroring the [accessTokenStore.RevokeByGrant] cascade
// shape).
func (s *opaqueAccessTokenStore) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	if grantID == "" {
		return 0, nil
	}
	res, err := s.runner().ExecContext(ctx,
		s.parent.queries.opaqueAccessTokenRevokeByGrant, grantID)
	if err != nil {
		return 0, wrapErr("opaqueAccessTokens.RevokeByGrant", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, wrapErr("opaqueAccessTokens.RevokeByGrant.RowsAffected", err)
	}
	return int(n), nil
}

// GC implements [store.OpaqueAccessTokenStore]. Drops every row whose
// expires_at is strictly before cutoff.
func (s *opaqueAccessTokenStore) GC(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.runner().ExecContext(ctx,
		s.parent.queries.opaqueAccessTokenGC, timeToInt64(cutoff))
	if err != nil {
		return 0, wrapErr("opaqueAccessTokens.GC", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, wrapErr("opaqueAccessTokens.GC.RowsAffected", err)
	}
	return int(n), nil
}

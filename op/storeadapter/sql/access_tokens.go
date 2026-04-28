package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

type accessTokenStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newAccessTokenStore(s *Store, tx *databasesql.Tx) *accessTokenStore {
	return &accessTokenStore{parent: s, tx: tx}
}

func (s *accessTokenStore) runner() runner { return pickRunner(s.parent, s.tx) }

func (s *accessTokenStore) Register(ctx context.Context, rec store.AccessTokenRecord) error {
	_, err := s.runner().ExecContext(ctx, s.parent.queries.accessTokenRegister,
		rec.JTI, rec.GrantID, rec.Subject, rec.ClientID,
		encodeStrings(rec.Scopes),
		timeToInt64(rec.IssuedAt), timeToInt64(rec.ExpiresAt),
		boolToInt64(rec.Revoked))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return wrapErr("accessTokens.Register", err)
	}
	return nil
}

func (s *accessTokenStore) Find(ctx context.Context, jti string) (*store.AccessTokenRecord, error) {
	var (
		rec     store.AccessTokenRecord
		scopes  []byte
		issued  int64
		expires int64
		revoked int64
	)
	err := s.runner().QueryRowContext(ctx, s.parent.queries.accessTokenFind, jti).Scan(
		&rec.JTI, &rec.GrantID, &rec.Subject, &rec.ClientID,
		&scopes, &issued, &expires, &revoked)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, nil //nolint:nilnil // store.AccessTokenRegistry contract: missing JTI yields (nil, nil), distinguishing "absent" from "lookup failed".
	}
	if err != nil {
		return nil, wrapErr("accessTokens.Find", err)
	}
	dec, err := decodeStrings(scopes)
	if err != nil {
		return nil, err
	}
	rec.Scopes = dec
	rec.IssuedAt = int64ToTime(issued)
	rec.ExpiresAt = int64ToTime(expires)
	rec.Revoked = int64ToBool(revoked)
	return &rec, nil
}

func (s *accessTokenStore) RevokeByJTI(ctx context.Context, jti string) error {
	if _, err := s.runner().ExecContext(ctx, s.parent.queries.accessTokenRevokeByJTI, jti); err != nil {
		return wrapErr("accessTokens.RevokeByJTI", err)
	}
	return nil
}

func (s *accessTokenStore) RevokeByGrant(ctx context.Context, grantID string) (int, error) {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.accessTokenRevokeByGrant, grantID)
	if err != nil {
		return 0, wrapErr("accessTokens.RevokeByGrant", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, wrapErr("accessTokens.RevokeByGrant.RowsAffected", err)
	}
	return int(n), nil
}

func (s *accessTokenStore) GC(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.accessTokenGC, timeToInt64(cutoff))
	if err != nil {
		return 0, wrapErr("accessTokens.GC", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, wrapErr("accessTokens.GC.RowsAffected", err)
	}
	return int(n), nil
}

package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

// passkeyStore is the SQL-backed [store.PasskeyStore].
//
// UpdateAssertion is the only method with non-trivial semantics. The
// read, the monotonicity comparison, and the write have to be one
// atomic operation, so it runs inside a transaction that locks the
// credential row first (SQLite has no row lock but serialises writers
// once the transaction takes the write lock). Expressing the comparison
// as SQL CASE arms would keep it to a single statement but would put
// the WebAuthn counter rules in three dialects' worth of SQL instead of
// in one readable Go function.
type passkeyStore struct {
	parent *Store
}

func newPasskeyStore(s *Store) *passkeyStore { return &passkeyStore{parent: s} }

func (s *passkeyStore) Get(ctx context.Context, credentialID []byte) (*store.PasskeyRecord, error) {
	row := s.parent.db.QueryRowContext(ctx, s.parent.queries.passkeyGet, nonNilBytes(credentialID))
	return scanPasskey(row)
}

func (s *passkeyStore) ListBySubject(ctx context.Context, subject string) ([]*store.PasskeyRecord, error) {
	rows, err := s.parent.db.QueryContext(ctx, s.parent.queries.passkeyListBySubject, subject)
	if err != nil {
		return nil, wrapErr("passkeys.ListBySubject", err)
	}
	defer func() { _ = rows.Close() }()

	// A subject with no passkeys yields an empty, non-nil slice: the
	// interface forbids reporting "none registered" as ErrNotFound.
	out := make([]*store.PasskeyRecord, 0)
	for rows.Next() {
		rec, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("passkeys.ListBySubject.Rows", err)
	}
	return out, nil
}

// Put upserts the credential record. The upsert is keyed on the
// credential ID, so it runs under the same row lock UpdateAssertion
// takes: the owner check and the write have to be one atomic operation
// or a registration racing another subject's could still overwrite the
// row the check just cleared.
func (s *passkeyStore) Put(ctx context.Context, r *store.PasskeyRecord) error {
	if r == nil {
		return errors.New("oidcsql: nil passkey record")
	}
	if len(r.CredentialID) == 0 {
		return errors.New("oidcsql: passkey record missing CredentialID")
	}

	tx, err := s.parent.db.BeginTx(ctx, nil)
	if err != nil {
		return wrapErr("passkeys.Put.BeginTx", err)
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, s.parent.queries.passkeyGetForUpdate, nonNilBytes(r.CredentialID))
	current, err := scanPasskey(row)
	switch {
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return err
	case err == nil && current.Subject != r.Subject:
		// The credential belongs to somebody else. Replacing it here
		// would unlink their authenticator.
		return store.ErrAlreadyExists
	}

	if _, err := tx.ExecContext(ctx, s.parent.queries.passkeyPut,
		nonNilBytes(r.CredentialID),
		r.Subject,
		nonNilBytes(r.PublicKey),
		nonNilBytes(r.AAGUID),
		int64(r.SignCount),
		r.AttestationType,
		encodeStrings(r.Transports),
		r.Attachment,
		boolToInt64(r.UserPresent),
		boolToInt64(r.UserVerified),
		boolToInt64(r.BackupEligible),
		boolToInt64(r.BackupState),
		boolToInt64(r.CloneWarning),
		timeToInt64(r.CreatedAt),
	); err != nil {
		return wrapErr("passkeys.Put", err)
	}
	if err := tx.Commit(); err != nil {
		return wrapErr("passkeys.Put.Commit", err)
	}
	return nil
}

func (s *passkeyStore) UpdateAssertion(
	ctx context.Context,
	credentialID []byte,
	update store.PasskeyAssertionUpdate,
) (*store.PasskeyRecord, error) {
	tx, err := s.parent.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, wrapErr("passkeys.UpdateAssertion.BeginTx", err)
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, s.parent.queries.passkeyGetForUpdate, nonNilBytes(credentialID))
	current, err := scanPasskey(row)
	if err != nil {
		return nil, err
	}

	next := applyAssertion(*current, update)
	if _, err := tx.ExecContext(ctx, s.parent.queries.passkeyUpdate,
		int64(next.SignCount),
		boolToInt64(next.UserPresent),
		boolToInt64(next.UserVerified),
		boolToInt64(next.BackupState),
		boolToInt64(next.CloneWarning),
		nonNilBytes(credentialID),
	); err != nil {
		return nil, wrapErr("passkeys.UpdateAssertion", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, wrapErr("passkeys.UpdateAssertion.Commit", err)
	}
	return &next, nil
}

func (s *passkeyStore) Delete(ctx context.Context, credentialID []byte) error {
	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.passkeyDelete, nonNilBytes(credentialID))
	if err != nil {
		return wrapErr("passkeys.Delete", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("passkeys.Delete.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// applyAssertion folds one verified assertion into the stored record,
// implementing the monotonicity rules [store.PasskeyStore] declares:
// the sign counter never moves backwards, the clone warning is sticky
// once raised, and a counterless authenticator (all three counters
// zero) still refreshes the ceremony flags.
func applyAssertion(rec store.PasskeyRecord, update store.PasskeyAssertionUpdate) store.PasskeyRecord {
	counterless := rec.SignCount == 0 && update.ExpectedSignCount == 0 && update.SignCount == 0
	if update.SignCount > rec.SignCount || counterless {
		rec.SignCount = update.SignCount
		rec.UserPresent = update.UserPresent
		rec.UserVerified = update.UserVerified
		rec.BackupState = update.BackupState
	}
	rec.CloneWarning = rec.CloneWarning || update.CloneWarning
	return rec
}

// scanPasskey maps one row onto a record. It takes the package's
// [scanner] so the single-record Get and the multi-row ListBySubject
// share one column mapping.
//
//nolint:funlen // one scan target per column; splitting it would only hide the mapping.
func scanPasskey(sc scanner) (*store.PasskeyRecord, error) {
	var (
		rec          store.PasskeyRecord
		credentialID []byte
		publicKey    []byte
		aaguid       []byte
		transports   []byte
		signCount    int64
		created      int64
		present      int64
		verified     int64
		eligible     int64
		backupState  int64
		cloneWarning int64
	)
	err := sc.Scan(
		&credentialID,
		&rec.Subject,
		&publicKey,
		&aaguid,
		&signCount,
		&rec.AttestationType,
		&transports,
		&rec.Attachment,
		&present,
		&verified,
		&eligible,
		&backupState,
		&cloneWarning,
		&created,
	)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("passkeys.Scan", err)
	}
	decoded, err := decodeStrings(transports)
	if err != nil {
		return nil, err
	}
	rec.CredentialID = append([]byte(nil), credentialID...)
	rec.PublicKey = append([]byte(nil), publicKey...)
	rec.AAGUID = append([]byte(nil), aaguid...)
	rec.SignCount = uint32(signCount) //nolint:gosec // the column only ever holds values this adapter wrote from a uint32.
	rec.Transports = decoded
	rec.UserPresent = int64ToBool(present)
	rec.UserVerified = int64ToBool(verified)
	rec.BackupEligible = int64ToBool(eligible)
	rec.BackupState = int64ToBool(backupState)
	rec.CloneWarning = int64ToBool(cloneWarning)
	rec.CreatedAt = int64ToTime(created)
	return &rec, nil
}

var _ store.PasskeyStore = (*passkeyStore)(nil)

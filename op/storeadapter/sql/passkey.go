package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

// passkeyStore is the SQL-backed [store.PasskeyStore].
//
// Put and UpdateAssertion are the methods with non-trivial semantics;
// Put's owner check is described on it. In UpdateAssertion the read,
// the monotonicity comparison, and the write have to be one
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

// passkeyPutAttempts bounds how often Put re-inserts after finding the
// row it collided with already deleted.
const passkeyPutAttempts = 3

// Put writes the credential record, keyed on the credential ID.
//
// The owner check rides on the engine's own refusals rather than on a
// row lock. A locking read of a credential ID nobody holds yet locks
// nothing on PostgreSQL and only a gap on InnoDB, so two first
// registrations from different subjects either both pass the check and
// the later upsert moves the credential, or deadlock each other. The
// insert claims the ID by its primary key; a duplicate falls through to
// a rewrite conditioned on the subject that holds the row.
func (s *passkeyStore) Put(ctx context.Context, r *store.PasskeyRecord) error {
	if r == nil {
		return errors.New("oidcsql: nil passkey record")
	}
	if len(r.CredentialID) == 0 {
		return errors.New("oidcsql: passkey record missing CredentialID")
	}

	values := []any{
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
	}
	id := nonNilBytes(r.CredentialID)
	for range passkeyPutAttempts {
		_, err := s.parent.db.ExecContext(ctx, s.parent.queries.passkeyInsert, append([]any{id}, values...)...)
		if err == nil {
			return nil
		}
		if !isDuplicate(err) {
			return wrapErr("passkeys.Put.insert", err)
		}

		res, err := s.parent.db.ExecContext(ctx, s.parent.queries.passkeyRewriteOwn, append(values[1:], id, r.Subject)...)
		if err != nil {
			return wrapErr("passkeys.Put.rewrite", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return wrapErr("passkeys.Put.RowsAffected", err)
		}
		if n > 0 {
			return nil
		}

		// No row changed: another subject holds the ID, the rewrite
		// matched an identical row on a connection that counts changed
		// rather than matched rows, or the row was deleted in between.
		current, err := s.Get(ctx, r.CredentialID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue
		case err != nil:
			return err
		case current.Subject != r.Subject:
			// Replacing it would unlink the holder's authenticator.
			return store.ErrAlreadyExists
		default:
			return nil
		}
	}
	return errors.New("oidcsql: passkeys.Put: the colliding row kept disappearing before the write landed")
}

func (s *passkeyStore) UpdateAssertion(
	ctx context.Context,
	credentialID []byte,
	update store.PasskeyAssertionUpdate,
) (*store.PasskeyRecord, error) {
	tx, err := s.parent.beginInternalTx(ctx, "passkeys.UpdateAssertion.BeginTx")
	if err != nil {
		return nil, err
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

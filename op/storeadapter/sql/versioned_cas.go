package oidcsql

import (
	"context"
	"fmt"
	"math"

	internalkeys "github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Helpers for the subject-keyed factor substores (TOTP, email OTP),
// whose rows carry an opaque store-issued Version that every write
// replaces.

// newVersion draws the Version a write stamps on its row. except is the
// Version being replaced (zero for a new row); label names the operation
// in a failure.
func newVersion(label string, except int64) (int64, error) {
	v, err := internalkeys.RandomInt63Except(except)
	if err != nil {
		return 0, fmt.Errorf("oidcsql: %s: generate Version: %w", label, err)
	}
	return v, nil
}

// usableVersion reports whether v can anchor a compare-and-swap: zero
// means "never issued" and MaxInt64 is outside the range newVersion
// produces.
func usableVersion(v uint64) bool {
	return v != 0 && v < math.MaxInt64
}

// versionedPut runs an unconditional upsert that stamps a fresh Version
// on the subject's row. values are the record columns after
// (subject, version).
func versionedPut(ctx context.Context, e execer, query, label, subject string, values []any) error {
	version, err := newVersion(label, 0)
	if err != nil {
		return err
	}
	args := append([]any{subject, version}, values...)
	if _, err := e.ExecContext(ctx, query, args...); err != nil {
		return wrapErr(label, err)
	}
	return nil
}

// versionedSwap runs the compare-and-swap UPDATE shared by the factor
// stores. The statement binds the next values, the replacement Version,
// the subject, the Version being replaced, and the previous values it
// must still match. Any shape of miss — a stale or unusable Version, or
// zero affected rows — reports [store.ErrAlreadyConsumed].
func versionedSwap(
	ctx context.Context,
	e execer,
	query, label, subject string,
	previousVersion, nextVersion uint64,
	nextValues, previousValues []any,
) error {
	if !usableVersion(previousVersion) || nextVersion != previousVersion {
		return store.ErrAlreadyConsumed
	}
	version, err := newVersion(label, int64(previousVersion))
	if err != nil {
		return err
	}
	args := make([]any, 0, len(nextValues)+3+len(previousValues))
	args = append(args, nextValues...)
	args = append(args, version, subject, int64(previousVersion))
	args = append(args, previousValues...)
	changed, err := execAffects(ctx, e, query, label, args)
	if err != nil {
		return err
	}
	if !changed {
		return store.ErrAlreadyConsumed
	}
	return nil
}

// execAffects runs a conditional statement and reports whether it
// changed a row. The label names the operation in a wrapped backend
// error.
func execAffects(ctx context.Context, e execer, query, label string, args []any) (bool, error) {
	res, err := e.ExecContext(ctx, query, args...)
	if err != nil {
		return false, wrapErr(label, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, wrapErr(label+".RowsAffected", err)
	}
	return n > 0, nil
}

package store

import (
	"context"
	"time"
)

// AuthnLockoutRecord is the persistent representation of the cross-factor
// brute-force counter the library uses to defend against an attacker
// pivoting between authentication factors (TOTP, email-OTP, ...) on the
// same subject. The struct is the storage projection of the rolling
// 24-hour window: a single counter
// that aggregates failures across every factor so the attacker's budget
// cannot be doubled by trying TOTP after exhausting email-OTP attempts.
//
// Records carry a small surface that mirrors the per-factor record's
// counter trio (FailedCount, FirstFailureAt, LockedUntil); the difference
// is that this row is keyed only by Subject, so every factor backed by a
// per-subject counter contributes to and reads from the same row.
//
// Backends MUST persist the state fields verbatim and manage Version
// as described by [AuthnLockoutStore.CompareAndSwap]. Every mutation
// is a versioned transition so a window rollover,
// successful-authentication reset, or lock stamp cannot overwrite a
// concurrently recorded failure.
type AuthnLockoutRecord struct {
	// Subject is the OP-internal stable user identifier this counter
	// belongs to. It is the primary key of the record.
	Subject string

	// FailedCount is the cumulative number of cross-factor failed
	// authentication attempts within the current 24-hour window. The
	// library reads it on every Begin / Continue and increments it on
	// every recoverable verify failure regardless of which factor
	// produced the failure.
	FailedCount int

	// FirstFailureAt anchors the rolling 24-hour window. A zero value
	// means "no failures recorded yet" or "window rolled over"; the
	// library re-stamps it from the current clock on the next failure.
	FirstFailureAt time.Time

	// LockedUntil is the wall-clock time until which Begin / Continue
	// is rejected with a lockout error regardless of which factor is
	// being driven. The library stamps a 1-hour lock at the short
	// threshold and a 24-hour lock at the long threshold (the values
	// match the per-factor thresholds so an embedder reading either
	// record sees the same numbers).
	// A zero value means "not locked".
	LockedUntil time.Time

	// Version is an opaque, monotonically increasing value managed by the
	// backend. Version zero denotes a record that has not been persisted.
	// Callers MUST NOT assign semantic meaning to a nonzero value beyond
	// passing it back to CompareAndSwap as the expected version.
	Version uint64
}

// AuthnLockoutStore is the substore for the cross-factor brute-force
// counter. Get and CompareAndSwap form a versioned state machine shared by
// failure increments, window rollover, lock stamping, and success reset.
//
// # Concurrency contract
//
// CompareAndSwap MUST atomically compare the persisted Version and replace
// the complete record. A stale transition MUST NOT modify any field. This
// includes races between two failures and between a failure and a success
// reset: losing a failure would let an attacker exceed the configured
// threshold by issuing parallel requests.
//
// SQL backends typically implement this with
// "UPDATE ... WHERE subject = ? AND version = ?"; Redis backends need a
// transaction or Lua script covering the compare and replacement. A plain
// Get followed by an unconditional write does not satisfy this contract.
//
// Backends MUST NOT log AuthnLockoutRecord values: the field set is
// privacy-sensitive (the row reveals authentication failure counts per
// subject, which is sufficient signal for an external observer to model
// the user's recent activity).
type AuthnLockoutStore interface {
	// Get returns the lockout record for subject. It MUST return
	// [ErrNotFound] when no record exists; any other non-nil error
	// indicates a backend fault. A first-time-ever subject has no
	// record, which is the normal "no failures yet" state.
	Get(ctx context.Context, subject string) (*AuthnLockoutRecord, error)

	// CompareAndSwap replaces the complete record only when its current
	// Version equals expectedVersion and reports whether the replacement
	// was committed.
	//
	// expectedVersion zero is an insert-only transition: it succeeds only
	// when no record exists for next.Subject. A nonzero expectedVersion
	// succeeds only when the existing row has exactly that version.
	// Version mismatch or insert contention returns (false, nil) and MUST
	// leave the persisted record unchanged.
	//
	// On success the backend MUST persist Version=expectedVersion+1,
	// ignoring next.Version, and MUST NOT mutate next. This backend-owned
	// increment prevents ABA when a record is reset to field values seen
	// earlier. Implementations MUST reject nil records, empty subjects,
	// and version overflow.
	CompareAndSwap(ctx context.Context, expectedVersion uint64, next *AuthnLockoutRecord) (bool, error)
}

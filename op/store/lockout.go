package store

import (
	"context"
	"time"
)

// AuthnLockoutRecord is the persistent representation of the cross-factor
// brute-force counter the library uses to defend against an attacker
// pivoting between authentication factors (TOTP, email-OTP, ...) on the
// same subject. The struct is the storage projection of the rolling
// 24-hour window described in 02-product-design.md §M.6: a single counter
// that aggregates failures across every factor so the attacker's budget
// cannot be doubled by trying TOTP after exhausting email-OTP attempts.
//
// Records carry a small surface that mirrors the per-factor record's
// counter trio (FailedCount, FirstFailureAt, LockedUntil); the difference
// is that this row is keyed only by Subject, so every factor backed by a
// per-subject counter contributes to and reads from the same row.
//
// Backends MUST persist all four fields verbatim. The library increments
// FailedCount through [AuthnLockoutStore.Increment] (which is required
// to be an atomic compare-and-set / "UPDATE ... SET counter = counter + 1"
// to defeat the lost-update race documented in M-AUTHN-4); other fields
// are written via [AuthnLockoutStore.Put] in the slow path (window
// rollover, success reset, lockout stamping).
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
	// match the per-factor thresholds documented at 02-product-design.md
	// §M.6 so an embedder reading either record sees the same numbers).
	// A zero value means "not locked".
	LockedUntil time.Time
}

// AuthnLockoutStore is the substore for the cross-factor brute-force
// counter. The interface is intentionally minimal — Get / Put / Increment
// — because the library serialises all access through the lockout helper
// in internal/authn/lockout.
//
// # Concurrency contract
//
// Increment MUST be atomic with respect to concurrent calls for the same
// subject: a "lost update" where two concurrent Increments both observe
// FailedCount=N and write FailedCount=N+1 (instead of N+2) would let an
// attacker exceed the configured threshold by issuing parallel verify
// requests. SQL backends typically implement this with
// "UPDATE ... SET failed_count = failed_count + 1"; in-memory backends
// hold a mutex around the read-modify-write.
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

	// Put creates or replaces the lockout record for r.Subject with
	// upsert semantics. The library uses Put for the slow paths:
	// window rollover (FirstFailureAt re-stamped), success reset
	// (FailedCount=0, LockedUntil=zero), and lockout stamping
	// (LockedUntil set to a future time).
	Put(ctx context.Context, r *AuthnLockoutRecord) error

	// Increment atomically increments the FailedCount for subject and
	// returns the post-increment count. Implementations MUST guarantee
	// the read-modify-write is atomic with respect to concurrent calls
	// for the same subject (see the concurrency contract above).
	//
	// The now parameter is the wall-clock reading the caller wants
	// stamped on FirstFailureAt when the record is being created
	// (FailedCount transitions 0 → 1). For subsequent increments the
	// existing FirstFailureAt MUST NOT be modified by Increment; the
	// caller drives window rollover separately through [Put].
	//
	// Implementations MUST NOT consult LockedUntil — Increment counts
	// every failed attempt the orchestrator surfaced, including ones
	// that happened during a soft retry against a still-locked record;
	// the lockout gate runs in the lockout helper before the call to
	// the underlying verifier.
	Increment(ctx context.Context, subject string, now time.Time) (int, error)
}

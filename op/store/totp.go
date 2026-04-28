package store

import (
	"context"
	"time"
)

// TOTPRecord is the persistent representation of a user's RFC 6238 TOTP
// enrolment. The library reads it on every verify, mutates the
// brute-force counters in place, and writes the new state back through
// [TOTPStore.Put]. The struct is a plain data carrier: every policy
// decision (lockout thresholds, skew window, secret encryption) lives in
// internal/authn/totp.
// Backends MUST treat the record as opaque. In particular,
// SecretCiphertext is the AES-256-GCM blob (nonce || ciphertext || tag)
// produced by the library; the backend MUST NOT inspect, parse, or
// re-encode it.
type TOTPRecord struct {
	// Subject is the OP-internal stable user identifier this enrolment
	// belongs to (the same value that becomes the "sub" claim of issued
	// tokens). It is the primary key of the record and the AAD bound
	// into the AES-256-GCM tag of SecretCiphertext: the library will
	// fail to decrypt a record whose row was copied under a different
	// subject.
	Subject string

	// SecretCiphertext is the encrypted RFC 6238 shared secret. The
	// blob is produced by internal/authn/totp.Codec.Seal and consumed
	// by Codec.Open. Its layout (nonce prefix, GCM tag suffix) is an
	// implementation detail; backends store and return the bytes
	// verbatim.
	SecretCiphertext []byte

	// ConfirmedAt is the wall-clock time the user proved possession of
	// the secret by entering a valid code during enrolment. A zero
	// value means "enrolment started but never confirmed"; the library
	// refuses to accept such a record at verify time. Backends SHOULD
	// sweep unconfirmed records older than a few minutes.
	ConfirmedAt time.Time

	// FailedCount is the cumulative number of wrong codes the user has
	// entered within the current 24-hour window (see
	// 02-product-design.md §M.6). It increments on every
	// [internal/authn/totp.Verifier.Verify] miss and resets on success
	// or after the 24-hour rollover. Backends MUST persist the field
	// verbatim; the library updates it through [TOTPStore.Put].
	FailedCount int

	// FirstFailureAt is the wall-clock time of the first failed verify
	// in the current window. It anchors the 24-hour rollover: when
	// (now - FirstFailureAt) > 24h the counter is treated as expired
	// and the next failure resets the anchor to now. A zero value
	// means "no failures recorded yet" and is treated identically to a
	// freshly rolled-over counter.
	FirstFailureAt time.Time

	// LockedUntil is the wall-clock time until which verify is
	// rejected with [internal/authn/totp.ErrLocked]. The library
	// stamps a 1-hour lock at FailedCount==30 and a 24-hour lock at
	// FailedCount==90. A zero value means "not locked".
	LockedUntil time.Time
}

// TOTPStore is the substore for RFC 6238 TOTP enrolments. It is a
// transactional substore in spirit — verify failures and successes both
// rewrite the record — but the library accesses it through a
// non-transactional handle today because the writes are localised to a
// single row and do not need to be atomic with token issuance.
// Backends MUST NOT log or audit SecretCiphertext: the encryption is
// at-rest defence in depth, not a substitute for log hygiene.
type TOTPStore interface {
	// Get returns the enrolment for subject. It MUST return
	// [ErrNotFound] when no enrolment exists; any other non-nil error
	// indicates a backend fault.
	Get(ctx context.Context, subject string) (*TOTPRecord, error)

	// Put creates or replaces the enrolment for r.Subject. Backends
	// implement upsert semantics: the library uses Put for the initial
	// confirmation, every brute-force counter update, and the post-
	// success counter reset.
	Put(ctx context.Context, r *TOTPRecord) error

	// Delete removes the enrolment for subject. It MUST return
	// [ErrNotFound] if no such enrolment exists so callers can
	// distinguish a no-op delete from a successful one. The library
	// invokes Delete when the user unenrols TOTP from the account
	// management UI or after a successful recovery-code-driven reset.
	Delete(ctx context.Context, subject string) error
}

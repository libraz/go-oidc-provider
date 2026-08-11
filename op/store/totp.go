package store

import (
	"context"
	"time"
)

// TOTPRecord is the persistent representation of a user's RFC 6238 TOTP
// enrolment. The library reads it on every verify, mutates the
// brute-force counters in place, and persists the new state through
// [TOTPStore.CompareAndSwap]. The struct is a plain data carrier: every policy
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
	// entered within the current 24-hour window. It increments on every
	// rejected code and resets on success or after the 24-hour
	// rollover. Backends MUST persist the field
	// verbatim; the library updates it through [TOTPStore.CompareAndSwap].
	FailedCount int

	// FirstFailureAt is the wall-clock time of the first failed verify
	// in the current window. It anchors the 24-hour rollover: when
	// (now - FirstFailureAt) > 24h the counter is treated as expired
	// and the next failure resets the anchor to now. A zero value
	// means "no failures recorded yet" and is treated identically to a
	// freshly rolled-over counter.
	FirstFailureAt time.Time

	// LockedUntil is the wall-clock time until which verify is
	// rejected outright, without even comparing the submitted code.
	// The library stamps a 1-hour lock at FailedCount==30 and a
	// 24-hour lock at FailedCount==90. A zero value means "not locked".
	LockedUntil time.Time

	// LastAcceptedStep is the RFC 6238 step counter the most recent
	// successful verify accepted (i.e., (now / step_duration) at the
	// moment of the matched verify). The library refuses to accept a
	// step value <= LastAcceptedStep on subsequent verifies so a
	// network-level replay of a code within the same 30-second
	// window cannot redeem twice. A zero value means "no successful
	// verify recorded yet"; the library stamps the field on every
	// OutcomeSuccess and persists the record through
	// [TOTPStore.Accept].
	LastAcceptedStep int64
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
	// implement upsert semantics. The library uses Put for enrolment
	// setup; verification transitions use CompareAndSwap or Accept so a
	// stale snapshot cannot overwrite replay state or counters.
	Put(ctx context.Context, r *TOTPRecord) error

	// CompareAndSwap replaces previous with next only when the stored
	// enrolment still exactly matches previous. It returns ErrAlreadyConsumed
	// when another verification or failure update won the race, preventing
	// a stale wrong-code write from rolling LastAcceptedStep or counters
	// backward.
	CompareAndSwap(ctx context.Context, previous, next *TOTPRecord) error

	// Accept atomically persists a successful verification result. It
	// MUST succeed for at most one caller for a given TOTP step and
	// MUST return [ErrAlreadyConsumed] when the stored
	// LastAcceptedStep is already greater than or equal to
	// r.LastAcceptedStep. Failed-code counter updates continue to use
	// CompareAndSwap; Accept exists solely for the single-use success
	// transition.
	Accept(ctx context.Context, r *TOTPRecord) error

	// Delete removes the enrolment for subject. It MUST return
	// [ErrNotFound] if no such enrolment exists so callers can
	// distinguish a no-op delete from a successful one. The library
	// invokes Delete when the user unenrols TOTP from the account
	// management UI or after a successful recovery-code-driven reset.
	Delete(ctx context.Context, subject string) error
}

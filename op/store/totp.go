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

	// Version is an opaque, store-issued compare-and-swap token. Zero means the
	// value has not been persisted. Backends assign a fresh non-zero token on
	// Put and every successful transition that leaves a record stored. Tokens
	// are equality-only: a
	// caller MUST NOT infer ordering or arithmetic from them. In particular, a
	// backend MUST NOT intentionally reuse a token for the same subject after
	// replacement, deletion, or re-creation; that prevents an old snapshot
	// from becoming valid again after an ABA lifecycle. The caller must carry
	// the value from Get into CompareAndSwap / Accept and must not modify either
	// input record when the backend assigns the stored successor token.
	Version uint64 `json:"-"`

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
	// implement upsert semantics and assign a fresh Version to their stored
	// clone; they ignore r.Version and MUST NOT mutate r. The library uses Put
	// for enrolment setup; verification transitions use CompareAndSwap or Accept
	// so a stale snapshot cannot overwrite replay state or counters.
	Put(ctx context.Context, r *TOTPRecord) error

	// CompareAndSwap replaces previous with next only when the stored
	// enrolment still equals previous field for field: its Version, and
	// every value the record carries. It returns
	// ErrAlreadyConsumed when another verification or failure update won the
	// race, preventing a stale wrong-code write from rolling LastAcceptedStep
	// or counters backward. next.Version MUST equal previous.Version; the
	// backend assigns a fresh opaque successor token to its stored clone and
	// MUST NOT mutate either caller-owned record. A zero, signed-max, or otherwise
	// malformed generation snapshot is reported as [ErrAlreadyConsumed], the
	// same retry/conflict signal used for a stale snapshot.
	//
	// Matching the whole record is not a stricter reading of the Version
	// rule but a superset of it, and on a conforming backend the two
	// never disagree: a backend that assigns a fresh, non-zero Version to
	// every transition it retains cannot hold a record whose Version
	// equals previous.Version while a value differs. They part company
	// only where a value moved out of band and left the Version behind,
	// and there the swap MUST be refused — the record previous describes
	// is not the record that would be overwritten.
	CompareAndSwap(ctx context.Context, previous, next *TOTPRecord) error

	// Accept atomically persists a successful verification result. It
	// MUST succeed for at most one caller for a given TOTP step and
	// MUST return [ErrAlreadyConsumed] when the stored
	// LastAcceptedStep is already greater than or equal to
	// r.LastAcceptedStep. In addition to the step monotonicity check, the
	// stored enrollment identity and generation MUST still match r: at minimum,
	// SecretCiphertext and ConfirmedAt must be equal. This prevents a
	// verification that read an old enrollment from replacing a newer one
	// installed while the code was being checked. A mismatch is reported as
	// [ErrAlreadyConsumed], the same retry/conflict signal used for a replay.
	// A zero or signed-max generation is likewise rejected with
	// [ErrAlreadyConsumed].
	// Failed-code counter updates continue to use CompareAndSwap; Accept
	// exists solely for the single-use success transition.
	Accept(ctx context.Context, r *TOTPRecord) error

	// Delete removes the enrolment for subject. It MUST return
	// [ErrNotFound] if no such enrolment exists so callers can
	// distinguish a no-op delete from a successful one. Account-management
	// and recovery flows implemented by the embedder use it when they remove an
	// enrolment.
	Delete(ctx context.Context, subject string) error
}

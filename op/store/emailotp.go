package store

import (
	"context"
	"time"
)

// EmailOTPRecord is the persistent representation of a pending email-OTP
// challenge. The library writes one record per attempt: a fresh code
// invalidates the previous record by overwriting it. Backends MUST treat
// the struct as opaque; CodeSalt and CodeHash are produced by
// internal/authn/emailotp and SHOULD NOT be parsed or re-encoded.
// Records carry plaintext-equivalent material (CodeHash + Salt are a
// 6-digit code's preimage; brute-forceable in milliseconds without the
// brute-force counter). Backends MUST NOT log or audit either field.
type EmailOTPRecord struct {
	// Subject is the OP-internal stable user identifier the challenge
	// belongs to (the same value that becomes the "sub" claim of issued
	// tokens). It is the primary key of the record and is bound into the
	// hash via CodeSalt so a record copied across subjects fails verify.
	Subject string

	// CodeSalt is the 16-byte random salt mixed into CodeHash. The
	// library generates a fresh salt on every code issuance; backends
	// store and return the bytes verbatim.
	CodeSalt []byte

	// CodeHash is the SHA-256 digest of (CodeSalt || Subject || code).
	// The plaintext code never leaves the in-memory buffer the
	// authenticator hands to the [Mailer]; only the hash is persisted.
	CodeHash []byte

	// SentAt is the wall-clock time the [Mailer] was invoked. A zero
	// value means the send was skipped (e.g. the user-supplied email
	// did not match the bound address); the record is then a sentinel
	// that always fails verify, by design, to keep the response shape
	// constant across registered / unregistered branches.
	SentAt time.Time

	// ExpiresAt is the wall-clock time at which the issued code stops
	// being acceptable. The library re-checks it on every verify
	// (Verify returns an "expired" outcome past this instant) and
	// [EmailOTPStore.Consume] MUST reject a code past it, so a stale
	// code can never be redeemed. ExpiresAt governs CODE validity only;
	// record retention is governed by [EmailOTPRecord.RetainUntil].
	ExpiresAt time.Time

	// RetainUntil is the wall-clock time until which the record MUST
	// remain readable via [EmailOTPStore.Get], independent of the code's
	// ExpiresAt. The rate-limit and brute-force bookkeeping below
	// (FailedCount / LockedUntil / SendCount / SendWindowStart / ...)
	// outlives a single code: were the record dropped the moment the
	// code expired, an attacker who paces to the code TTL would see the
	// resend cap and the lockout counter silently reset. The library
	// stamps RetainUntil to the far edge of the longest active window
	// (the 24-hour brute-force window) on every write, so Get keeps
	// returning the record — and its counters — while any window is
	// live, while Verify / Consume still reject the expired code.
	//
	// A zero value means "retention defaults to ExpiresAt" so a backend
	// or caller that predates this field keeps its previous behaviour.
	RetainUntil time.Time

	// FailedCount is the cumulative number of wrong codes the user has
	// entered within the current 24-hour window. It increments on every
	// verify miss and resets on success or after the rollover. Backends
	// MUST persist the field verbatim; the library updates it through
	// [EmailOTPStore.CompareAndSwap].
	FailedCount int

	// FirstFailureAt is the wall-clock time of the first failed verify
	// in the current window. It anchors the 24-hour rollover. A zero
	// value means "no failures recorded yet".
	FirstFailureAt time.Time

	// LockedUntil is the wall-clock time until which verify is rejected
	// outright. The library stamps a 1-hour lock at FailedCount==30 and
	// a 24-hour lock at FailedCount==90. A zero value means "not locked".
	LockedUntil time.Time

	// ConsumedAt is the wall-clock time the code was successfully
	// redeemed. A non-zero value means the record has already been
	// used and any subsequent verify against the same record MUST be
	// rejected. The library stamps the field on a successful Verify
	// and persists it through [EmailOTPStore.Consume]. A zero
	// value means "not yet consumed". Backends MAY sweep records with
	// non-zero ConsumedAt older than a deployment-defined retention
	// window; the library never reads them after the stamp.
	ConsumedAt time.Time

	// SendCount is the number of OTP send events the authenticator
	// has issued for this subject within the current rolling window
	// anchored at SendWindowStart. It is incremented on every send
	// (including sends that hit the unmatched-email branch and skip
	// the mailer). Backends MUST persist the field verbatim; the
	// library updates it through [EmailOTPStore.CompareAndSwap].
	SendCount int

	// SendWindowStart anchors the rolling send-rate window. A zero
	// value means "no window active yet"; sends older than the
	// configured rolling window (one hour) are dropped on the next
	// send by resetting the anchor and SendCount to 1. Backends MUST
	// persist the field verbatim.
	SendWindowStart time.Time

	// LastSendAttemptAt is the wall-clock time of the most recent
	// send attempt, regardless of whether the user-supplied email
	// matched the bound address. The library uses it to enforce the
	// per-subject minimum interval between consecutive sends; SentAt
	// alone would only count successful (matched) sends and let an
	// attacker bypass the gate by spamming wrong addresses. Backends
	// MUST persist the field verbatim.
	LastSendAttemptAt time.Time
}

// EmailOTPStore is the substore for pending email-OTP challenges. Like
// [TOTPStore] it is transactional in spirit (every verify rewrites the
// record) but the library accesses it through a non-transactional handle
// because the writes are localised to a single row and do not need to
// be atomic with token issuance.
// Backends MUST NOT log or audit CodeHash / CodeSalt: those values
// reduce to the 6-digit plaintext under brute force without the OP's
// rate-limit counters.
type EmailOTPStore interface {
	// Get returns the pending challenge for subject. It MUST return
	// [ErrNotFound] when no challenge exists or when the record's
	// [EmailOTPRecord.RetainUntil] has passed (falling back to
	// [EmailOTPRecord.ExpiresAt] when RetainUntil is zero). Get MUST NOT
	// drop a record merely because its code ExpiresAt elapsed while
	// RetainUntil is still in the future: the rate-limit / brute-force
	// counters on the record must survive the code so the caller re-reads
	// them (the code itself is separately rejected by Verify / Consume).
	// Any other non-nil error indicates a backend fault.
	Get(ctx context.Context, subject string) (*EmailOTPRecord, error)

	// Put creates or replaces the pending challenge for r.Subject.
	// Backends implement upsert semantics. The library uses Put only
	// for explicit setup/migration paths; authentication transitions
	// use CompareAndSwap or Consume so a stale snapshot cannot overwrite
	// a newer challenge or a successful redemption.
	Put(ctx context.Context, r *EmailOTPRecord) error

	// CompareAndSwap replaces previous with next only when the stored
	// challenge still exactly matches previous. It returns ErrAlreadyConsumed
	// when another verification, failure update, or resend won the race.
	// Authenticators use it for every failure counter update and resend
	// reservation so stale read-modify-write snapshots can never erase a
	// successful Consume or a newer challenge.
	//
	// A nil previous means "insert only if absent" and is how the first
	// send for a subject reserves its record. Backends MUST apply next
	// when no record exists for next.Subject, or when the record that
	// exists has passed its retention horizon (the same condition Get
	// reports as [ErrNotFound]), and MUST return [ErrAlreadyConsumed]
	// otherwise. Treating a nil previous as an unconditional upsert
	// would defeat the reservation: two concurrent first sends would
	// both succeed, and the second would reset the send counter the
	// first had just established — which is the rate limit the
	// reservation exists to hold.
	CompareAndSwap(ctx context.Context, previous, next *EmailOTPRecord) error

	// Consume atomically marks the pending challenge represented by r
	// as consumed. It MUST succeed for at most one caller observing the
	// same unconsumed challenge and MUST return [ErrAlreadyConsumed]
	// when another caller has already consumed it. Backends SHOULD
	// verify that the stored challenge still matches r.CodeSalt /
	// r.CodeHash before stamping ConsumedAt so a stale success cannot
	// consume a newer code issued for the same subject; a mismatch is
	// reported as [ErrAlreadyConsumed] because the code the caller holds
	// has been superseded.
	//
	// A challenge whose [EmailOTPRecord.ExpiresAt] has passed MUST be
	// rejected with [ErrNotFound] even while the record is still
	// retained for its counters: from the redemption path's point of
	// view the code no longer exists.
	Consume(ctx context.Context, r *EmailOTPRecord) error

	// Delete removes the pending challenge for subject. It MUST return
	// [ErrNotFound] if no such challenge exists so callers can
	// distinguish a no-op delete from a successful one. The library
	// invokes Delete on a successful verify to enforce the single-use
	// semantic.
	Delete(ctx context.Context, subject string) error
}

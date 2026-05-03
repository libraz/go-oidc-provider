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
	// being acceptable. Reads after this time return [ErrNotFound] from
	// the inmem reference and SHOULD do the same in production
	// backends; the library re-checks expiry on every verify regardless.
	ExpiresAt time.Time

	// FailedCount is the cumulative number of wrong codes the user has
	// entered within the current 24-hour window. It increments on every
	// verify miss and resets on success or after the rollover. Backends
	// MUST persist the field verbatim; the library updates it through
	// [EmailOTPStore.Put].
	FailedCount int

	// FirstFailureAt is the wall-clock time of the first failed verify
	// in the current window. It anchors the 24-hour rollover (see
	// 02-product-design.md §M.6). A zero value means "no
	// failures recorded yet".
	FirstFailureAt time.Time

	// LockedUntil is the wall-clock time until which verify is rejected
	// outright. The library stamps a 1-hour lock at FailedCount==30 and
	// a 24-hour lock at FailedCount==90. A zero value means "not locked".
	LockedUntil time.Time

	// ConsumedAt is the wall-clock time the code was successfully
	// redeemed. A non-zero value means the record has already been
	// used and any subsequent verify against the same record MUST be
	// rejected. The library stamps the field on a successful Verify
	// and writes the record back through [EmailOTPStore.Put] rather
	// than relying on a Delete call that may fail silently. A zero
	// value means "not yet consumed". Backends MAY sweep records with
	// non-zero ConsumedAt older than a deployment-defined retention
	// window; the library never reads them after the stamp.
	ConsumedAt time.Time

	// SendCount is the number of OTP send events the authenticator
	// has issued for this subject within the current rolling window
	// anchored at SendWindowStart. It is incremented on every send
	// (including sends that hit the unmatched-email branch and skip
	// the mailer). Backends MUST persist the field verbatim; the
	// library updates it through [EmailOTPStore.Put].
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
	// [ErrNotFound] when no challenge exists; any other non-nil error
	// indicates a backend fault.
	Get(ctx context.Context, subject string) (*EmailOTPRecord, error)

	// Put creates or replaces the pending challenge for r.Subject.
	// Backends implement upsert semantics: the library uses Put for
	// the initial issuance, every brute-force counter update, and the
	// post-success counter reset.
	Put(ctx context.Context, r *EmailOTPRecord) error

	// Delete removes the pending challenge for subject. It MUST return
	// [ErrNotFound] if no such challenge exists so callers can
	// distinguish a no-op delete from a successful one. The library
	// invokes Delete on a successful verify to enforce the single-use
	// semantic.
	Delete(ctx context.Context, subject string) error
}

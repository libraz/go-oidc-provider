package totpkit

import (
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Codec is the AES-256-GCM at-rest envelope shared with the verify
// path. The type is an alias of the verify-side [totp.Codec] so an
// embedder can construct one Codec at startup and reuse it for both
// enrolment and login. The aliased type's Seal / Open methods,
// rotation history, and sentinel errors apply unchanged.
type Codec = totp.Codec

// Sentinel errors re-exported from the verify-side codec so embedders
// can dispatch on them through [errors.Is] without importing the
// internal package.
var (
	// ErrInvalidKey is returned by [NewCodec] when a supplied key is
	// not exactly 32 bytes long. AES-256-GCM requires a 256-bit key.
	ErrInvalidKey = totp.ErrInvalidKey

	// ErrDecrypt is returned by [Confirm] when the [Pending] record's
	// SecretCiphertext cannot be authenticated under the supplied
	// codec — typically because the codec key has rotated past the
	// retention window or the pending value was tampered with.
	ErrDecrypt = totp.ErrDecrypt
)

// Configuration sentinels reported by the enrolment helpers. Each
// value is a package-level pointer so callers may dispatch on it via
// [errors.Is].
var (
	// ErrInvalidIssuer is returned by [NewEnrolment] when the issuer
	// argument is empty after trimming surrounding whitespace.
	// Authenticator apps render an unlabelled account when the issuer
	// is missing; the package refuses construction so the operator
	// surfaces the error at registration time rather than confusing
	// the user later.
	ErrInvalidIssuer = errors.New("totpkit: issuer must not be empty")

	// ErrInvalidAccount is returned by [NewEnrolment] when the
	// account argument is empty after trimming surrounding whitespace.
	ErrInvalidAccount = errors.New("totpkit: account must not be empty")

	// ErrInvalidSubject is returned by [NewEnrolment] when the
	// subject argument is empty. The subject is bound into the
	// AES-256-GCM tag as additional authenticated data; an empty AAD
	// would let a row exfiltrated from one user's enrolment row
	// decrypt under any other user. The package refuses to construct
	// such a record.
	ErrInvalidSubject = errors.New("totpkit: subject must not be empty")

	// ErrCodeRejected is returned by [Confirm] when the submitted
	// code does not match the pending secret within the standard
	// skew window. The error is intentionally opaque so callers
	// cannot distinguish "wrong digit" from "outside skew" through
	// the sentinel.
	ErrCodeRejected = errors.New("totpkit: code does not match pending enrolment")

	// ErrPendingNil is returned by [Confirm] when the pending
	// argument is nil. Surfaced as a sentinel so a programming
	// mistake at the controller boundary is distinguishable from a
	// genuine cryptographic failure.
	ErrPendingNil = errors.New("totpkit: pending enrolment is nil")

	// ErrPendingMissingRecord is returned by [Confirm] when
	// pending.Record is nil. Same rationale as [ErrPendingNil].
	ErrPendingMissingRecord = errors.New("totpkit: pending enrolment carries no record")

	// ErrCodecRequired is returned by [NewEnrolment] / [Confirm]
	// when the supplied codec is nil. Both helpers refuse to operate
	// on an unsealed secret.
	ErrCodecRequired = errors.New("totpkit: codec is required")
)

// totpDigits is the RFC 6238 default code length the verify path
// pins. Re-stated here so the [Confirm] guard can reject blanks
// before the cryptographic compare; the verify-side compare uses its
// own copy of the same constant. The two are independent declarations
// of one RFC default, not a shared one.
const totpDigits = 6

// totpStep is the RFC 6238 default time step. The constant is
// re-stated so [Confirm] can compute candidate codes inline; the
// verify-path uses the same value internally.
const totpStep = 30 * time.Second

// confirmSkew is the ±step window [Confirm] accepts. It matches what
// the verify path accepts when the embedder configures no skew of its
// own, so a code an authenticator app produces for the neighbouring
// step is accepted at enrolment time too. Widening this value would
// double the confirm-time brute-force surface.
const confirmSkew = 1

// NewCodec constructs a [Codec] from raw key material. The first
// argument is the active encryption key; subsequent values populate
// the rotation history accepted on decryption. Every key MUST be
// exactly 32 bytes; passing a key of any other length returns
// [ErrInvalidKey].
//
// The returned codec is safe for concurrent use and MAY be shared
// with [op.StepTOTP] (both paths produce and consume the same blob
// shape under the same AAD).
func NewCodec(current []byte, previous ...[]byte) (*Codec, error) {
	return totp.NewCodec(current, previous...)
}

// Pending is the unconfirmed enrolment a caller drives through
// [Confirm]. The struct carries:
//
//   - Record: a [store.TOTPRecord] whose SecretCiphertext is the
//     AES-256-GCM-sealed shared secret with the subject ID bound as
//     additional authenticated data. ConfirmedAt is zero — the
//     library refuses to verify against an unconfirmed record.
//   - OTPAuthURI: the otpauth:// URI an authenticator app consumes
//     when scanning the enrolment QR code. Embedders MAY render this
//     as a QR image of any size; the URI itself is the canonical
//     wire format.
//   - SecretBase32: the raw base32 encoding of the shared secret.
//     Embedders SHOULD render this alongside the QR code so users on
//     desktop authenticator apps can paste it manually.
//
// Pending is the embedder's responsibility to hold for the duration
// of the enrolment session (typically a server-side row keyed by a
// short-lived cookie). The caller MUST NOT persist the Record
// directly — only [Confirm] mutates it into the form a verify path
// will accept.
type Pending struct {
	// Record is the partially-populated [store.TOTPRecord] that
	// becomes the embedder's persisted enrolment after [Confirm]
	// stamps ConfirmedAt and LastAcceptedStep. SecretCiphertext is
	// already sealed under the codec; the subject ID is bound as AAD.
	Record *store.TOTPRecord

	// OTPAuthURI is the otpauth:// provisioning URI rendered as the
	// enrolment QR code. The format follows the Key URI Format
	// convention every major authenticator app accepts.
	OTPAuthURI string

	// SecretBase32 is the unpadded base32 encoding of the shared
	// secret. Surfaced for "manual entry" UX where the user types
	// the secret into their authenticator app instead of scanning a
	// QR code. It MUST NOT be logged or persisted.
	SecretBase32 string
}

// NewEnrolment generates a fresh RFC 6238 secret, seals it under
// codec with subject as additional authenticated data, and returns a
// [Pending] the caller drives through [Confirm].
//
// issuer is the human-readable label the authenticator app shows
// above the account name (typically the OP's display name —
// "Example Identity"). account is the label shown beneath the
// issuer (typically the user's email or preferred_username). subject
// is the OP-internal stable user ID; it becomes both the AAD bound
// into the GCM tag and the [store.TOTPRecord.Subject] field, so the
// resulting record persists under the same key the verify path
// consults.
//
// The returned Pending's Record carries no ConfirmedAt or
// LastAcceptedStep; persisting it before [Confirm] succeeds would
// surface an unconfirmed enrolment to the verify path, which the
// library refuses to accept.
//
// Errors:
//   - [ErrCodecRequired] when codec is nil.
//   - [ErrInvalidIssuer] / [ErrInvalidAccount] / [ErrInvalidSubject]
//     when the corresponding argument is empty after trimming.
//   - Any I/O error surfaced by [crypto/rand]; the package never
//     calls [math/rand].
func NewEnrolment(codec *Codec, subject, issuer, account string) (*Pending, error) {
	if codec == nil {
		return nil, ErrCodecRequired
	}
	if subject == "" {
		return nil, ErrInvalidSubject
	}
	if strings.TrimSpace(issuer) == "" {
		return nil, ErrInvalidIssuer
	}
	if strings.TrimSpace(account) == "" {
		return nil, ErrInvalidAccount
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, err
	}
	blob, err := codec.Seal(secret, []byte(subject))
	if err != nil {
		return nil, err
	}
	return &Pending{
		Record: &store.TOTPRecord{
			Subject:          subject,
			SecretCiphertext: blob,
		},
		OTPAuthURI:   totp.ProvisioningURI(issuer, account, secret),
		SecretBase32: totp.EncodeBase32(secret),
	}, nil
}

// Confirm verifies code against the secret in pending.Record and, on
// success, stamps ConfirmedAt to now and LastAcceptedStep to the
// matched RFC 6238 step counter. The returned [store.TOTPRecord] is
// the value the embedder persists through [store.TOTPStore.Put]; on
// failure the input pending is not mutated and the caller MUST NOT
// persist it.
//
// The acceptance window is the current step plus one step on each
// side (T-1, T, T+1) — identical to the verify-path default so a
// code an authenticator app produces against the neighbouring step
// is accepted at enrolment time too.
//
// The now argument is supplied explicitly so tests can drive the
// helper deterministically. Production callers SHOULD pass
// [timex.SystemClock.Now] (the library's central wall-clock seam).
//
// Errors:
//   - [ErrPendingNil] when pending is nil.
//   - [ErrPendingMissingRecord] when pending.Record is nil.
//   - [ErrCodecRequired] when codec is nil.
//   - [ErrCodeRejected] when the code is blank, malformed, or fails
//     to match within the skew window.
//   - [ErrDecrypt] when the codec cannot open pending.Record's
//     SecretCiphertext (key rotated past retention, blob tampered).
func Confirm(codec *Codec, pending *Pending, code string, now time.Time) (*store.TOTPRecord, error) {
	if pending == nil {
		return nil, ErrPendingNil
	}
	if pending.Record == nil {
		return nil, ErrPendingMissingRecord
	}
	if codec == nil {
		return nil, ErrCodecRequired
	}
	if len(code) != totpDigits {
		return nil, ErrCodeRejected
	}

	rec := pending.Record
	secret, err := codec.Open(rec.SecretCiphertext, []byte(rec.Subject))
	if err != nil {
		return nil, err
	}

	matched, ok := matchStep(secret, code, now)
	if !ok {
		return nil, ErrCodeRejected
	}

	// Replay defence: a Pending whose LastAcceptedStep is already at
	// or above the matched step has been confirmed before. Reject the
	// repeat call so an embedder who accidentally re-submits the same
	// pending value cannot smuggle a fresh ConfirmedAt past the
	// verify-side single-use guard. The check mirrors the verify
	// path's same-step-rejection contract.
	if rec.LastAcceptedStep != 0 && matched <= rec.LastAcceptedStep {
		return nil, ErrCodeRejected
	}

	// Mutate only after the cryptographic compare succeeds so a
	// failed Confirm leaves the pending record untouched and the
	// embedder may retry.
	rec.ConfirmedAt = now
	rec.LastAcceptedStep = matched
	return rec, nil
}

// matchStep reports whether code equals the TOTP value at any step
// within ±confirmSkew of the step containing now, and returns the
// matched step counter on success. The byte-wise compare is
// constant-time per attempt; the loop short-circuits on success
// (which leaks at most one bit of timing about which neighbouring
// step matched, acceptable because the attacker already knows the
// window size).
func matchStep(secret []byte, code string, now time.Time) (int64, bool) {
	codeBytes := []byte(code)
	for i := -confirmSkew; i <= confirmSkew; i++ {
		t := now.Add(time.Duration(i) * totpStep)
		if equalCode(secret, codeBytes, t) {
			return safeStep(stepCounter(t)), true
		}
	}
	return 0, false
}

// stepCounter returns the RFC 6238 step counter (now / 30s) clamped
// to non-negative values. A pre-1970 clock would otherwise wrap into
// a huge unsigned counter; the library never reaches that branch in
// practice but the clamp keeps the function total.
func stepCounter(now time.Time) uint64 {
	const stepSeconds = 30
	secs := now.Unix()
	if secs < 0 {
		return 0
	}
	return uint64(secs) / stepSeconds
}

// safeStep converts the unsigned step counter into the signed form
// stored on [store.TOTPRecord.LastAcceptedStep]. The cast is safe
// for any human-relevant horizon; the explicit clamp keeps the type
// boundary obvious to readers.
func safeStep(s uint64) int64 {
	const cap63 = uint64(1) << 62
	if s > cap63 {
		return int64(cap63)
	}
	return int64(s)
}

// equalCode computes the TOTP value at t and reports whether it
// equals candidate. The compare is constant-time so a partial match
// cannot leak the matching prefix length through timing.
func equalCode(secret, candidate []byte, t time.Time) bool {
	expected := totp.Code(secret, t)
	return subtle.ConstantTimeCompare(candidate, []byte(expected)) == 1
}

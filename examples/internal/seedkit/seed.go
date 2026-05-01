//go:build example

package seedkit

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/totpkit"
)

// Sentinel errors returned by [Seed]. Each is a package-level value
// callers may match through [errors.Is].
var (
	// ErrSeedSubjectRequired is returned by [Seed] when SeedOptions
	// has an empty Subject. The subject is the OP-internal stable
	// user ID and the AAD that binds the TOTP secret; an empty value
	// would silently weaken both invariants.
	ErrSeedSubjectRequired = errors.New("seedkit: SeedOptions.Subject must not be empty")

	// ErrSeedUsernameRequired is returned by [Seed] when SeedOptions
	// has an empty Username. The PrimaryPassword Step looks the user
	// up by username at /authorize; without one, the demo cannot log
	// in.
	ErrSeedUsernameRequired = errors.New("seedkit: SeedOptions.Username must not be empty")

	// ErrSeedPasswordRequired is returned by [Seed] when SeedOptions
	// has an empty Password. The helper refuses to seed an empty
	// password hash so an operator running a demo cannot log in
	// without typing the password they configured.
	ErrSeedPasswordRequired = errors.New("seedkit: SeedOptions.Password must not be empty")

	// ErrSeedStoreRequired is returned by [Seed] when the inmem
	// Store argument is nil.
	ErrSeedStoreRequired = errors.New("seedkit: inmem.Store must not be nil")

	// ErrSeedTOTPCodecRequired is returned by [Seed] when
	// SeedOptions.TOTP is set but TOTP.Codec is nil.
	ErrSeedTOTPCodecRequired = errors.New("seedkit: SeedTOTP.Codec must not be nil")

	// ErrSeedTOTPIssuerRequired is returned by [Seed] when
	// SeedOptions.TOTP is set but TOTP.Issuer is empty.
	ErrSeedTOTPIssuerRequired = errors.New("seedkit: SeedTOTP.Issuer must not be empty")

	// ErrSeedTOTPAccountRequired is returned by [Seed] when
	// SeedOptions.TOTP is set but TOTP.Account is empty.
	ErrSeedTOTPAccountRequired = errors.New("seedkit: SeedTOTP.Account must not be empty")
)

// SeedOptions describes the demo user a [Seed] call materialises.
// All fields except TOTP are required.
type SeedOptions struct {
	// Subject is the OP-internal stable user ID; it becomes the
	// "sub" claim of issued tokens and the primary key of the user,
	// password, and TOTP records.
	Subject string

	// Username is the password identifier the PrimaryPassword Step
	// resolves through [store.UserPasswordStore.FindByUsername].
	Username string

	// Password is the plaintext password the helper hashes via
	// [op.HashPassword] before persisting. The plaintext never leaves
	// memory.
	Password string

	// Claims is the bag of arbitrary id_token / userinfo claims the
	// helper writes onto the [store.User] record. nil is treated as
	// an empty map.
	Claims map[string]any

	// TOTP, if non-nil, enrols a confirmed RFC 6238 factor for the
	// user. "Confirmed" here means the helper pre-stamps ConfirmedAt
	// and LastAcceptedStep on the record — the demo skips the
	// round-trip "user types code back" step that production
	// enrolment requires. Suitable only for a CLI demo.
	TOTP *SeedTOTP
}

// SeedTOTP carries the inputs [Seed] forwards to [totpkit.NewEnrolment]
// when the caller wants to materialise a confirmed TOTP record.
type SeedTOTP struct {
	// Codec is the AES-256-GCM envelope under which the secret is
	// sealed. It MUST be the same codec the OP's verify path
	// ([op.StepTOTP]) consumes; otherwise the seeded record cannot
	// be opened at login time.
	Codec *totpkit.Codec

	// Issuer is the human-readable label the authenticator app
	// displays above the account name (typically the OP's display
	// name, e.g. "Example Identity").
	Issuer string

	// Account is the label shown beneath the issuer (typically the
	// user's email or username).
	Account string

	// Now is the wall-clock time stamped onto the TOTP record's
	// ConfirmedAt and used to derive the LastAcceptedStep counter.
	// The argument is explicit so callers may pin a specific moment
	// in tests; production callers pass time.Now() at startup.
	Now time.Time
}

// SeedResult carries the operator-visible enrolment payload [Seed]
// returns when SeedOptions.TOTP is non-nil. When TOTP is nil the
// helper returns nil for both the result and the error so callers
// can pattern-match on "no TOTP requested" without a sentinel.
type SeedResult struct {
	// OTPAuthURI is the otpauth:// provisioning URI the QR encodes.
	// Embedders MAY hand it to a different QR renderer or print it
	// verbatim for debugging.
	OTPAuthURI string

	// SecretBase32 is the unpadded base32 encoding of the shared
	// secret, suitable for the "manual entry" UX an authenticator
	// app offers when the user cannot scan a QR code.
	SecretBase32 string

	// QRTerm is the terminal-friendly QR rendering produced by
	// [QRTerm]. The string is ready to print to stdout in one go.
	QRTerm string
}

// Seed creates the user, password, and (optionally) TOTP record
// inside st through the inmem.Store substore accessors. It is a
// build-tag gated demo helper — production embedders run TOTP
// enrolment as an interactive flow against [op/totpkit] directly.
//
// The helper validates every required input up front and returns
// the corresponding sentinel from this package on a missing value;
// the substore writes all happen after validation succeeds so a
// rejected call leaves st untouched.
//
// When opts.TOTP is non-nil, Seed:
//
//  1. Calls [totpkit.NewEnrolment] under the supplied codec and
//     subject.
//  2. Stamps Pending.Record.ConfirmedAt to opts.TOTP.Now and
//     LastAcceptedStep to (Now.Unix() / 30) so the verify path
//     accepts the record without a separate user-confirms-the-code
//     round-trip. The demo therefore cannot prove the user actually
//     scanned the QR — that's a deliberate trade-off seedkit makes
//     for CLI ergonomics.
//  3. Persists the record via st.TOTPs().Put.
//  4. Returns a [SeedResult] carrying the otpauth URI, base32
//     secret, and pre-rendered terminal QR.
//
// When opts.TOTP is nil, Seed returns (nil, nil) on success — the
// caller has no enrolment payload to print.
func Seed(ctx context.Context, st *inmem.Store, opts SeedOptions) (*SeedResult, error) {
	if err := validateSeed(st, opts); err != nil {
		return nil, err
	}

	hash, err := op.HashPassword(opts.Password)
	if err != nil {
		return nil, err
	}

	user := &store.User{
		Subject: opts.Subject,
		Claims:  opts.Claims,
	}
	st.PutUserWithPassword(ctx, user, opts.Username, hash)

	if opts.TOTP == nil {
		return nil, nil //nolint:nilnil // both nil signals "no TOTP requested"
	}

	pending, err := totpkit.NewEnrolment(opts.TOTP.Codec, opts.Subject, opts.TOTP.Issuer, opts.TOTP.Account)
	if err != nil {
		return nil, err
	}

	rec := pending.Record
	rec.ConfirmedAt = opts.TOTP.Now
	rec.LastAcceptedStep = stepCounter(opts.TOTP.Now)
	if err := st.TOTPs().Put(ctx, rec); err != nil {
		return nil, err
	}

	qrText, err := QRTerm(pending.OTPAuthURI)
	if err != nil {
		return nil, err
	}
	return &SeedResult{
		OTPAuthURI:   pending.OTPAuthURI,
		SecretBase32: pending.SecretBase32,
		QRTerm:       qrText,
	}, nil
}

// validateSeed walks the SeedOptions guard chain in priority order
// (store → user identity → TOTP sub-fields) and returns the
// matching sentinel for the first violation found. Splitting the
// chain out keeps [Seed] below the project's cognitive-complexity
// budget without losing the per-field error granularity callers
// match through [errors.Is].
func validateSeed(st *inmem.Store, opts SeedOptions) error {
	switch {
	case st == nil:
		return ErrSeedStoreRequired
	case opts.Subject == "":
		return ErrSeedSubjectRequired
	case opts.Username == "":
		return ErrSeedUsernameRequired
	case opts.Password == "":
		return ErrSeedPasswordRequired
	}
	if opts.TOTP == nil {
		return nil
	}
	switch {
	case opts.TOTP.Codec == nil:
		return ErrSeedTOTPCodecRequired
	case strings.TrimSpace(opts.TOTP.Issuer) == "":
		return ErrSeedTOTPIssuerRequired
	case strings.TrimSpace(opts.TOTP.Account) == "":
		return ErrSeedTOTPAccountRequired
	}
	return nil
}

// stepCounter returns the RFC 6238 step counter (seconds since epoch
// divided by the 30-second window) for now, clamped to the non-
// negative range. The demo helper's call site only ever passes a
// post-1970 timestamp; the clamp keeps the function total without a
// panic for pathological inputs.
func stepCounter(now time.Time) int64 {
	const stepSeconds = 30
	secs := now.Unix()
	if secs < 0 {
		return 0
	}
	return secs / stepSeconds
}

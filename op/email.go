package op

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Mailer is the SPI hook the email-OTP factor calls to deliver the
// generated code. The interface is intentionally narrow: the library
// is transport-agnostic, so SMTP / SES / SendGrid / queue dispatch
// are all the embedder's choice.
// Implementations MUST treat [EmailOTPMessage.Code] as
// plaintext-equivalent material — never log, audit, or persist it.
// A non-nil error stops the authenticator chain (the user is shown
// a generic delivery failure rather than the verify prompt) so
// embedders that need at-least-once semantics SHOULD push delivery
// onto a queue and return nil here.
type Mailer interface {
	Send(ctx context.Context, msg EmailOTPMessage) error
}

// MailerFunc lets a plain function satisfy [Mailer]. Convenient for
// tests and for embedders that wrap an existing transport without
// implementing the full struct.
type MailerFunc func(ctx context.Context, msg EmailOTPMessage) error

// Send implements [Mailer].
func (f MailerFunc) Send(ctx context.Context, msg EmailOTPMessage) error { return f(ctx, msg) }

// EmailOTPMessage is the payload the email-OTP authenticator hands
// to a [Mailer]. Localised subject / body templates live in the
// embedder; the library passes only the data fields the template
// needs.
type EmailOTPMessage struct {
	// To is the destination address (the subject's bound "email"
	// claim, resolved through [store.UserStore]).
	To string

	// Code is the plaintext 6-digit OTP. Implementations MUST NOT
	// log this field.
	Code string

	// IssuedAt is the wall-clock time the authenticator generated
	// the code.
	IssuedAt time.Time

	// ExpiresAt is the wall-clock time the code stops being
	// acceptable. Mailers SHOULD include it in the rendered
	// template so users see a countdown matching the SPA verify
	// prompt.
	ExpiresAt time.Time

	// Subject is the OP-internal subject identifier. Provided for
	// audit binding only; mailers MUST NOT include it in the
	// rendered email.
	Subject string

	// ClientID is the OAuth client_id of the relying party that
	// initiated the authorize request. Mailers MAY surface it in
	// the rendered template (e.g. "Your code for ${app_name}");
	// the embedder is responsible for resolving the human name.
	ClientID string
}

// EmailOTPConfig bundles the dependencies
// [NewEmailOTPAuthenticator] requires. Mailer / Store / Users are
// required; missing values surface as a configuration error rather
// than a runtime panic on the first authenticator call.
type EmailOTPConfig struct {
	// Mailer is the delivery hook. Required.
	Mailer Mailer

	// Store is the [store.EmailOTPStore] persisting pending
	// challenges. Required. The reference implementation lives in
	// [github.com/libraz/go-oidc-provider/op/storeadapter/inmem.Store.EmailOTPs];
	// production deployments wire a backing database table.
	Store store.EmailOTPStore

	// Users is the read-only [store.UserStore] the authenticator
	// reads to resolve the subject's bound "email" claim. Required.
	// In v1.0 the email-OTP factor runs as a 2nd factor only — the
	// orchestrator pre-binds [BeginInput.Subject] from the previous
	// factor's [interaction.Result] — so [store.UserStore] is the
	// authoritative source of the destination address.
	Users store.UserStore

	// Clock supplies the wall-clock reading the authenticator and its
	// verifier consult — the code TTL, the resend window, and the
	// per-record lockout stamp all read it. Nil pins
	// [timex.SystemClock] for the lifetime of the returned
	// authenticator.
	//
	// The fall-back is the system clock and not the [Provider]'s: this
	// constructor runs before [New], so there is no Provider to inherit
	// from, and the value returned here is already built by the time one
	// exists. A deployment that pins a clock through [WithClock] — a
	// test harness pins one to make the code TTL deterministic — MUST
	// pass the same [Clock] here, or this factor keeps reading real time
	// while the rest of the OP reads the pinned one. Scheduling the
	// factor as a [StepEmailOTP] inside [WithLoginFlow] instead needs no
	// second wiring: that path is compiled inside [New] and is handed
	// the Provider's clock.
	Clock Clock

	// CodeTTL is the acceptance window from issuance to verify.
	// Zero falls back to [DefaultEmailOTPCodeTTL].
	CodeTTL time.Duration

	// LockoutStore wires the cross-factor brute-force counter, the
	// same one [WithAuthnLockoutStore] attaches to the built-in
	// [StepEmailOTP]. Supply it whenever the deployment sets that
	// option: a directly constructed authenticator is otherwise
	// outside the shared budget, and an attacker who has burned
	// their TOTP allowance can pivot to email OTP for a fresh one.
	//
	// Nil leaves only the per-record FailedCount on the challenge,
	// which budgets email OTP alone. Pass the same
	// [store.AuthnLockoutStore] handed to [WithAuthnLockoutStore] so
	// both paths count against one record.
	LockoutStore store.AuthnLockoutStore
}

// DefaultEmailOTPCodeTTL is the acceptance window applied when
// [EmailOTPConfig.CodeTTL] is zero. Five minutes is long enough for
// a user to fetch the code from an inbox while staying short enough
// that a leaked record window is small.
const DefaultEmailOTPCodeTTL = emailotp.DefaultCodeTTL

// NewEmailOTPAuthenticator constructs the [Authenticator] for the
// [FactorEmailOTP] factor.
// Behaviour highlights:
//   - Two-screen UX: "auth.email_otp.send" collects the address;
//     "auth.email_otp.verify" collects the 6-digit code.
//   - Constant shape: the verify prompt is emitted regardless of
//     whether the user-typed address matches the bound claim, so
//     enumeration-by-prompt-shape is not possible.
//   - Bound destination: the code is always delivered to the
//     subject's "email" claim resolved through [store.UserStore];
//     the user-typed address is a UX confirmation only.
//   - Brute-force counter: 30 wrong codes inside a 24-hour rolling
//     window stamp a 1-hour lock; 90 wrong codes stamp a 24-hour
//     lock and force the user through the recovery flow.
//   - Single-use: a successful verify stamps the persisted record
//     consumed rather than deleting it, so a replay of the code (e.g.,
//     from a leaked SPA log) is rejected on the next attempt. The
//     record is retained past the code's own expiry because it also
//     carries the resend cap and the failure counter; deleting it at
//     verify — or at expiry — would hand an attacker a fresh budget for
//     both.
//   - Cross-factor budget: set [EmailOTPConfig.LockoutStore] and the
//     factor shares the per-subject counter every other built-in
//     second factor consults, so guesses cannot be reset by pivoting
//     between factors.
//
// Deprecated: use StepEmailOTP in a LoginFlow.
func NewEmailOTPAuthenticator(cfg EmailOTPConfig) (Authenticator, error) { //nolint:ireturn,nolintlint // returns the public Authenticator interface so the result carries no concrete-type leak.
	// The internal constructor compares with == nil, which a typed nil
	// passes, and it never sees the Mailer bare: emailMailerAdapter
	// wraps it. Check every dependency here, returning the sentinel an
	// internal-side miss would produce.
	switch {
	case nilcheck.IsNil(cfg.Mailer):
		return nil, emailotp.ErrMailerRequired
	case nilcheck.IsNil(cfg.Store):
		return nil, emailotp.ErrStoreRequired
	case nilcheck.IsNil(cfg.Users):
		return nil, emailotp.ErrUsersRequired
	case cfg.Clock != nil && nilcheck.IsNil(cfg.Clock):
		return nil, newConfigurationError("EmailOTPConfig.Clock holds a typed-nil Clock", nil)
	}
	clk := cfg.Clock
	counter, err := emailOTPLockout(cfg.LockoutStore, clk)
	if err != nil {
		return nil, err
	}
	auth, err := emailotp.NewAuthenticator(emailotp.Config{
		Mailer:  emailMailerAdapter{m: cfg.Mailer},
		Store:   cfg.Store,
		Users:   cfg.Users,
		Clock:   clk,
		CodeTTL: cfg.CodeTTL,
	})
	if err != nil {
		return nil, err
	}
	if counter == nil {
		return auth, nil
	}
	return auth.WithLockout(counter), nil
}

// emailOTPLockout builds the cross-factor counter for a directly
// constructed authenticator. An unset store leaves the factor on its
// per-record counter alone; a typed-nil store is a configuration
// mistake rather than an opt-out, and is refused here instead of
// silently disabling the gate at the first guess.
//
// The counter is built without an audit emitter: this constructor runs
// before any [Provider] exists, so there is no OP audit chain to attach
// to and [op.AuditLockoutStalled] cannot fire from it. Wiring the store
// through [WithAuthnLockoutStore] instead builds the counter inside
// op.New, where the emitter is available and the event does fire.
func emailOTPLockout(lockoutStore store.AuthnLockoutStore, clk timex.Clock) (*lockout.Counter, error) {
	if lockoutStore == nil {
		return nil, nil //nolint:nilnil // documented "no cross-factor counter" signal
	}
	if nilcheck.IsNil(lockoutStore) {
		return nil, newConfigurationError("EmailOTPConfig.LockoutStore holds a typed-nil AuthnLockoutStore", nil)
	}
	counter, err := lockout.New(lockoutStore, clk)
	if err != nil {
		return nil, newConfigurationError("EmailOTPConfig.LockoutStore rejected by the cross-factor counter", err)
	}
	return counter, nil
}

// emailMailerAdapter bridges the public [Mailer] surface to the
// internal [emailotp.Mailer]. The adapter copies fields one-for-one
// so the public type stays free of the internal package import that
// would otherwise leak through the [EmailOTPMessage] struct tag.
type emailMailerAdapter struct{ m Mailer }

// Send implements [emailotp.Mailer].
func (a emailMailerAdapter) Send(ctx context.Context, msg emailotp.Message) error {
	if a.m == nil {
		return emailotp.ErrMailerRequired
	}
	return a.m.Send(ctx, EmailOTPMessage{
		To:        msg.To,
		Code:      msg.Code,
		IssuedAt:  msg.IssuedAt,
		ExpiresAt: msg.ExpiresAt,
		Subject:   msg.Subject,
		ClientID:  msg.ClientID,
	})
}

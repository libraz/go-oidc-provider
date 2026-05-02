package op

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
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

	// Clock supplies the wall-clock reading the authenticator and
	// its verifier consult. Nil falls back to the [Provider]'s
	// clock (or [timex.SystemClock] when called outside one).
	Clock Clock

	// CodeTTL is the acceptance window from issuance to verify.
	// Zero falls back to [DefaultEmailOTPCodeTTL].
	CodeTTL time.Duration
}

// DefaultEmailOTPCodeTTL is the acceptance window applied when
// [EmailOTPConfig.CodeTTL] is zero. Five minutes is long enough for
// a user to fetch the code from an inbox while staying short enough
// that a leaked record window is small.
const DefaultEmailOTPCodeTTL = emailotp.DefaultCodeTTL

// NewEmailOTPAuthenticator constructs the [Authenticator] for the
// [FactorEmailOTP] factor. Embedders register the returned value
// through [WithAuthenticators] alongside any other factors they
// support.
// Behaviour highlights (full design in
// 02-product-design.md §E.2):
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
//   - Single-use: the persisted record is deleted on a successful
//     verify so a replay of the code (e.g., from a leaked SPA log)
//     is rejected on the next attempt.
func NewEmailOTPAuthenticator(cfg EmailOTPConfig) (Authenticator, error) { //nolint:ireturn,nolintlint // returns the public Authenticator interface so embedders can pass the result to WithAuthenticators without a concrete-type leak.
	// The internal NewAuthenticator nil-checks its own Mailer, but
	// the public Mailer is wrapped through emailMailerAdapter — a
	// non-nil struct value with a nil internal field — so the
	// internal nil-check would not fire. Surface the error here so
	// the caller sees the same emailotp.ErrMailerRequired sentinel
	// that an internal-side miss would produce.
	if cfg.Mailer == nil {
		return nil, emailotp.ErrMailerRequired
	}
	clk := emailOTPClock(cfg.Clock)
	return emailotp.NewAuthenticator(emailotp.Config{
		Mailer:  emailMailerAdapter{m: cfg.Mailer},
		Store:   cfg.Store,
		Users:   cfg.Users,
		Clock:   clk,
		CodeTTL: cfg.CodeTTL,
	})
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

// emailOTPClock resolves the clock the [emailotp.Authenticator]
// consumes. The public [Clock] interface is structurally compatible
// with [timex.Clock]; nil falls through to the timex default.
func emailOTPClock(c Clock) timex.Clock {
	if c == nil {
		return nil
	}
	return clockAdapter{c: c}
}

// clockAdapter bridges [Clock] to [timex.Clock]. The two interfaces
// share the same single Now method but live in different packages,
// so a one-line wrapper keeps the dependency direction clean.
type clockAdapter struct{ c Clock }

// Now implements [timex.Clock].
func (a clockAdapter) Now() time.Time { return a.c.Now() }

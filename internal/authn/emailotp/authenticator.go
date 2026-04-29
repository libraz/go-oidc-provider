package emailotp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Prompt-type identifiers and form-field names. Exported so
// embedders and SPA tests reference the canonical strings without a
// stringly-typed copy. The values are part of the orchestrator's
// stable wire surface and treated as a freeze point.
const (
	// PromptTypeSend is [interaction.Prompt.Type] for the first
	// screen (collect email).
	PromptTypeSend = "auth.email_otp.send"

	// PromptTypeVerify is [interaction.Prompt.Type] for the second
	// screen (collect code).
	PromptTypeVerify = "auth.email_otp.verify"

	// EmailFieldName is the [interaction.FieldSpec.Name] for the
	// email input on the send screen.
	EmailFieldName = "email"

	// CodeFieldName is the [interaction.FieldSpec.Name] for the
	// code input on the verify screen.
	CodeFieldName = "code"
)

const (
	// emailMaxLen is the byte cap the orchestrator enforces on the
	// email field. RFC 5321 §4.5.3.1.3 limits SMTP path length to
	// 256 octets; 254 is the conventional usable cap and matches
	// the constraint major MTAs apply.
	emailMaxLen = 254

	// codeLen is both the minimum and maximum byte length the
	// verify field accepts. The orchestrator rejects submissions
	// outside the bound before the authenticator runs, so a wrong-
	// length field never reaches [Verifier.Verify].
	codeLen = codeDigits
)

// scratchVerify is the [interaction.Step.Scratch] payload set on the
// verify-prompt step. The orchestrator round-trips Scratch through
// state without inspection; the authenticator uses it as a step
// discriminator (so a malicious SPA cannot skip the send step by
// posting a code field straight to a fresh chain).
//
//nolint:gochecknoglobals // sentinel marker; declared once to avoid per-call allocations.
var scratchVerify = []byte{0x01}

// Sentinel construction errors.
var (
	ErrSubjectRequired = errors.New("emailotp: subject is required")
	ErrEmailMissing    = errors.New("emailotp: email field is missing")
	ErrCodeMissing     = errors.New("emailotp: code field is missing")
	ErrEmailNotBound   = errors.New("emailotp: subject has no bound email claim")
	ErrMailerRequired  = errors.New("emailotp: mailer is required")
	ErrStoreRequired   = errors.New("emailotp: store is required")
	ErrUsersRequired   = errors.New("emailotp: user store is required")
)

// Mailer is the SPI hook the [Authenticator] calls to deliver the
// OTP code. Implementations MUST treat [Message.Code] as
// plaintext-equivalent material — never log, audit, or persist it.
//
// Send is invoked synchronously from the authenticator. Embedders
// that need queue-based delivery wrap a queue producer behind this
// interface; the only contract is that a non-nil error stops the
// chain (the user is shown a generic failure rather than the verify
// prompt).
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// MailerFunc lets a plain function satisfy [Mailer]. Convenient for
// tests and for embedders that wrap an existing transport without
// implementing the full struct.
type MailerFunc func(ctx context.Context, msg Message) error

// Send implements [Mailer].
func (f MailerFunc) Send(ctx context.Context, msg Message) error { return f(ctx, msg) }

// Message is the payload [Authenticator] hands to a [Mailer]. The
// struct is deliberately minimal: localised subject / body templates
// live in the embedder, not in the library, so the OP can stay
// transport-agnostic.
type Message struct {
	// To is the destination address (the subject's bound email
	// claim).
	To string

	// Code is the plaintext 6-digit OTP. It MUST NOT be logged.
	Code string

	// IssuedAt is the wall-clock time the authenticator generated
	// the code.
	IssuedAt time.Time

	// ExpiresAt is the wall-clock time the code stops being
	// acceptable. Mailer implementations include this in the
	// rendered template so users see a countdown matching the
	// SPA's [interaction.EmailOTPVerifyPromptData.ExpiresAt].
	ExpiresAt time.Time

	// Subject is the OP-internal subject identifier. Provided for
	// audit binding only; mailers MUST NOT include it in the
	// rendered email.
	Subject string

	// ClientID is the OAuth client_id of the relying party that
	// initiated the authorize request. Mailers MAY surface it in
	// the rendered template (e.g., "Your code for ${app_name}");
	// the embedder is responsible for resolving the human name.
	ClientID string
}

// Authenticator is the [op.Authenticator] adapter for the email-OTP
// factor. Construct through [NewAuthenticator]; the zero value is
// not usable.
type Authenticator struct {
	mailer   Mailer
	store    store.EmailOTPStore
	users    store.UserStore
	verifier *Verifier
	clock    timex.Clock
	codeTTL  time.Duration
}

// Config bundles the dependencies [NewAuthenticator] requires.
type Config struct {
	// Mailer is the delivery hook. Required.
	Mailer Mailer

	// Store is the [store.EmailOTPStore] persisting pending
	// challenges. Required.
	Store store.EmailOTPStore

	// Users is the read-only [store.UserStore] the authenticator
	// reads to resolve the subject's bound email claim. Required.
	Users store.UserStore

	// Clock supplies the wall-clock reading. Nil falls back to
	// [timex.SystemClock].
	Clock timex.Clock

	// CodeTTL is the acceptance window from issuance. Zero falls
	// back to [DefaultCodeTTL].
	CodeTTL time.Duration
}

// NewAuthenticator constructs an [Authenticator]. Mailer / Store /
// Users are required; missing values surface as a configuration
// error rather than a runtime panic on the first Begin / Continue.
func NewAuthenticator(cfg Config) (*Authenticator, error) {
	if cfg.Mailer == nil {
		return nil, ErrMailerRequired
	}
	if cfg.Store == nil {
		return nil, ErrStoreRequired
	}
	if cfg.Users == nil {
		return nil, ErrUsersRequired
	}
	clock := cfg.Clock
	if clock == nil {
		clock = timex.SystemClock
	}
	ttl := cfg.CodeTTL
	if ttl <= 0 {
		ttl = DefaultCodeTTL
	}
	return &Authenticator{
		mailer:   cfg.Mailer,
		store:    cfg.Store,
		users:    cfg.Users,
		verifier: &Verifier{Clock: clock},
		clock:    clock,
		codeTTL:  ttl,
	}, nil
}

// Type implements [op.Authenticator]. Always returns
// [authn.FactorEmailOTP].
func (*Authenticator) Type() authn.FactorType { return authn.FactorEmailOTP }

// AAL implements [op.Authenticator]. Email OTP contributes AAL2
// (002 §E.3).
func (*Authenticator) AAL() authn.AAL { return authn.AAL2 }

// AMR implements [op.Authenticator]. Maps to RFC 8176 §2 "otp" — the
// transport (email) is not distinguished by the registry.
func (*Authenticator) AMR() string { return "otp" }

// Prompts implements [op.Authenticator]. Both prompt types are
// declared so a [interaction.Driver] can validate its routing table
// at startup.
func (*Authenticator) Prompts() []string {
	return []string{PromptTypeSend, PromptTypeVerify}
}

// Begin implements [op.Authenticator]. It emits the send prompt
// unconditionally; the actual code generation happens on the first
// Continue. Subject is required because email OTP is a 2nd factor
// in v1.0; the orchestrator pre-binds it from the previous factor's
// Result.
func (a *Authenticator) Begin(_ context.Context, in authn.BeginInput) (interaction.Step, error) {
	if in.Subject == "" {
		return interaction.Step{}, ErrSubjectRequired
	}
	return interaction.Step{Prompt: a.sendPrompt()}, nil
}

// Continue implements [op.Authenticator]. The function dispatches on
// in.Scratch:
//
//   - empty / missing — first submission, expecting an email field.
//     The authenticator looks up the bound user, generates a code,
//     calls the [Mailer], persists the hashed record, and emits the
//     verify prompt with Scratch set so the next call routes to the
//     verify branch.
//   - [scratchVerify] — second submission, expecting a code field.
//     The authenticator reads the persisted record, runs the
//     [Verifier], and emits Result on success or the verify prompt
//     on a recoverable miss.
func (a *Authenticator) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	if in.Subject == "" {
		return interaction.Step{}, ErrSubjectRequired
	}
	if len(in.Scratch) == 0 {
		return a.handleSend(ctx, in)
	}
	return a.handleVerify(ctx, in)
}

func (a *Authenticator) handleSend(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	email, ok := in.Submission.Values[EmailFieldName]
	if !ok || email == "" {
		return interaction.Step{}, ErrEmailMissing
	}
	user, err := a.users.FindBySubject(ctx, in.Subject)
	if err != nil {
		return interaction.Step{}, fmt.Errorf("emailotp: load user: %w", err)
	}
	bound := claimEmail(user)
	if bound == "" {
		return interaction.Step{}, ErrEmailNotBound
	}
	now := a.clock.Now()
	expiresAt := now.Add(a.codeTTL)
	code, err := generateCode()
	if err != nil {
		return interaction.Step{}, err
	}
	salt, err := generateSalt()
	if err != nil {
		return interaction.Step{}, err
	}
	rec := &store.EmailOTPRecord{
		Subject:   in.Subject,
		CodeSalt:  salt,
		CodeHash:  hashCode(salt, in.Subject, code),
		ExpiresAt: expiresAt,
	}
	if constantTimeEqualEmails(email, bound) {
		if err := a.mailer.Send(ctx, Message{
			To:        bound,
			Code:      code,
			IssuedAt:  now,
			ExpiresAt: expiresAt,
			Subject:   in.Subject,
			ClientID:  in.ClientID,
		}); err != nil {
			return interaction.Step{}, fmt.Errorf("emailotp: deliver code: %w", err)
		}
		rec.SentAt = now
	}
	if err := a.store.Put(ctx, rec); err != nil {
		return interaction.Step{}, fmt.Errorf("emailotp: persist record: %w", err)
	}
	return interaction.Step{
		Prompt:  a.verifyPrompt(bound, expiresAt),
		Scratch: scratchVerify,
	}, nil
}

func (a *Authenticator) handleVerify(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	code, ok := in.Submission.Values[CodeFieldName]
	if !ok || code == "" {
		return interaction.Step{}, ErrCodeMissing
	}
	rec, err := a.store.Get(ctx, in.Subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return interaction.Step{}, ErrExpired
		}
		return interaction.Step{}, fmt.Errorf("emailotp: load record: %w", err)
	}
	res, verr := a.verifier.Verify(ctx, rec, code)
	if res != nil && res.Record != nil && res.Outcome != OutcomeLocked && res.Outcome != OutcomeExpired && res.Outcome != OutcomeConsumed {
		// Locked / expired / consumed branches leave the record
		// unchanged (verifier short-circuits before mutating
		// counters); every other branch — including OutcomeSuccess,
		// where ConsumedAt is now stamped — needs persisting so the
		// single-use invariant survives a transient backend failure.
		if perr := a.store.Put(ctx, res.Record); perr != nil {
			return interaction.Step{}, fmt.Errorf("emailotp: persist record: %w", perr)
		}
	}
	switch {
	case verr == nil:
		// Single-use semantics: the verifier has stamped ConsumedAt
		// on the record and the Put above persisted it. A replay of
		// the same code (e.g. from a leaked SPA log) hits the
		// ConsumedAt guard on the next Verify and is rejected as
		// ErrConsumed. Delete is intentionally NOT called: a
		// transient Delete failure must not leave a re-redeemable
		// record behind.
		return interaction.Step{Result: &interaction.Result{Subject: in.Subject, AuthTime: in.AuthTime}}, nil
	case errors.Is(verr, ErrWrongCode):
		return interaction.Step{
			Prompt:  a.verifyPromptFromRecord(ctx, rec),
			Scratch: scratchVerify,
		}, nil
	case errors.Is(verr, ErrConsumed):
		// Treat a replay attempt as a generic expiry from the SPA's
		// perspective so the response shape stays constant with the
		// "code never existed" branch. The orchestrator sees the
		// underlying error verbatim through the wrapped chain.
		return interaction.Step{}, ErrExpired
	default:
		// Locked / expired / reset-required flow through verbatim
		// so the orchestrator can dispatch.
		return interaction.Step{}, verr
	}
}

func (a *Authenticator) sendPrompt() *interaction.Prompt {
	return &interaction.Prompt{
		Type: PromptTypeSend,
		Data: interaction.EmailOTPSendPromptData{},
		Inputs: []interaction.FieldSpec{{
			Name:     EmailFieldName,
			Kind:     interaction.FieldEmail,
			Label:    "auth.email_otp.email",
			Required: true,
			MaxLen:   emailMaxLen,
		}},
	}
}

func (a *Authenticator) verifyPrompt(boundEmail string, expiresAt time.Time) *interaction.Prompt {
	return &interaction.Prompt{
		Type: PromptTypeVerify,
		Data: interaction.EmailOTPVerifyPromptData{
			MaskedEmail: maskEmail(boundEmail),
			ExpiresAt:   expiresAt,
		},
		Inputs: []interaction.FieldSpec{{
			Name:     CodeFieldName,
			Kind:     interaction.FieldOTPCode,
			Label:    "auth.email_otp.code",
			Required: true,
			MinLen:   codeLen,
			MaxLen:   codeLen,
		}},
	}
}

func (a *Authenticator) verifyPromptFromRecord(ctx context.Context, rec *store.EmailOTPRecord) *interaction.Prompt {
	bound := ""
	if user, err := a.users.FindBySubject(ctx, rec.Subject); err == nil {
		bound = claimEmail(user)
	}
	return a.verifyPrompt(bound, rec.ExpiresAt)
}

// claimEmail extracts the "email" claim from a [store.User]. The
// helper tolerates a nil user pointer (returns "") so callers can
// short-circuit without an extra nil-check.
func claimEmail(u *store.User) string {
	if u == nil {
		return ""
	}
	v, _ := u.Claims["email"].(string)
	return v
}

// Compile-time confirmation that *Authenticator satisfies the
// public interface. The receiver is a pointer because the mailer /
// store / users fields are reference-typed.
var _ authn.Authenticator = (*Authenticator)(nil)

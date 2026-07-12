package op

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/authn/password"
	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// CaptchaSubmissionFieldName is the [interaction.FieldSpec.Name] a
// [StepCaptcha] expects in the SPA submission. The SPA renders the
// upstream provider's challenge widget (Cloudflare Turnstile, Google
// reCAPTCHA, hCaptcha, …) and submits the resulting token under this
// key. The constant is exported so SPA documentation references the
// canonical wire name without a stringly-typed copy.
// The [StepCaptcha] path is independent of the legacy after-N-failures
// captcha gate: a [LoginFlow] without a registered StepCaptcha still
// emits the orchestrator's built-in captcha prompt when
// [State.LastFailures] crosses the threshold (and a
// [WithCaptchaVerifier] is wired). StepCaptcha lets embedders schedule
// captcha through the rule list (e.g., always before TOTP, or only for
// high-risk requests) instead of relying on the threshold gate alone.
const CaptchaSubmissionFieldName = "captcha_token"

// captchaSubmissionMaxLen caps the token bytes the captcha step accepts
// in the submission. Provider tokens (Turnstile / reCAPTCHA / hCaptcha)
// are <= ~2 KiB; 4 KiB is comfortably above the realistic upper bound
// while keeping the parser away from pathological inputs.
const captchaSubmissionMaxLen = 4 * 1024

// errCaptchaTokenMissing surfaces when the SPA omits the captcha token
// field. The orchestrator's [interaction.FieldSpec] validation should
// already have caught this; the adapter re-checks at the trust boundary.
var errCaptchaTokenMissing = errors.New("op: captcha_token field is missing")

// errCaptchaVerifierNil surfaces when [StepCaptcha.Verifier] is nil at
// the time the orchestrator dispatches Continue. The compile path
// rejects a nil verifier at op.New time, so reaching this branch means
// the compiled flow was mutated after compilation — defensive.
var errCaptchaVerifierNil = errors.New("op: StepCaptcha.Verifier is nil")

// captchaStepAdapter wraps a [CaptchaVerifier] as an
// [authn.Authenticator] so the [LoginFlow] orchestrator can drive
// captcha challenges through the same Begin / Continue dispatch path
// as factor-shaped Steps. The wrapper is internal; embedders compose
// captcha through [StepCaptcha].
// The adapter reports an inert [FactorType] / [authn.AAL0] / empty
// AMR so any leak into the factor pipeline is harmless. The orchestrator
// filters captcha-shaped Steps out of [State.Factors] via the compile
// path's IsCaptcha flag, so these values are never aggregated into the
// session AAL or amr_history.
type captchaStepAdapter struct {
	verifier CaptchaVerifier
}

// Type implements [authn.Authenticator]. Returns an inert sentinel
// that is never recorded in [State.Factors] (the LoginFlow compile
// path tags captcha-shaped Steps so [recordLoginFlowResult] skips
// [appendFactor]).
func (captchaStepAdapter) Type() authn.FactorType { return "captcha" }

// AAL implements [authn.Authenticator]. Returns [authn.AAL0]: a
// captcha solve does not raise the session assurance level. The
// LoginFlow orchestrator skips AAL aggregation for captcha-shaped
// Steps anyway; AAL0 is defence-in-depth.
func (captchaStepAdapter) AAL() authn.AAL { return authn.AAL0 }

// AMR implements [authn.Authenticator]. Captcha is not an
// authentication method; the wrapper returns "" so even an accidental
// inclusion in amr_history surfaces as an empty value the orchestrator
// drops on validation.
func (captchaStepAdapter) AMR() string { return "" }

// Prompts implements [authn.Authenticator]. The adapter emits a single
// prompt type matching the orchestrator's legacy captcha prompt so SPAs
// can route both surfaces through one renderer.
func (captchaStepAdapter) Prompts() []string { return []string{"captcha"} }

// Begin implements [authn.Authenticator]. Returns the captcha prompt
// with a single hidden submission field for the upstream provider's
// token. The prompt shape mirrors the orchestrator's legacy
// [emitCaptchaPrompt] so a SPA written for one path renders the other
// without modification.
func (captchaStepAdapter) Begin(_ context.Context, _ authn.BeginInput) (interaction.Step, error) {
	prompt := &interaction.Prompt{
		Type: "captcha",
		Data: interaction.CaptchaPromptData{},
		Inputs: []interaction.FieldSpec{{
			Name:     CaptchaSubmissionFieldName,
			Kind:     interaction.FieldHidden,
			Label:    "auth.captcha.token",
			Required: true,
			MaxLen:   captchaSubmissionMaxLen,
		}},
	}
	return interaction.Step{Prompt: prompt}, nil
}

// Continue implements [authn.Authenticator]. It extracts the captcha
// token from the SPA submission, calls [CaptchaVerifier.Verify], and
// returns a populated [interaction.Result] on success or the verifier
// error on failure. The error never carries the upstream reason — the
// orchestrator surfaces a generic challenge_required so the SPA cannot
// enumerate provider-side rejection codes.
func (a captchaStepAdapter) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	if a.verifier == nil {
		return interaction.Step{}, errCaptchaVerifierNil
	}
	token, ok := in.Submission.Values[CaptchaSubmissionFieldName]
	if !ok || token == "" {
		return interaction.Step{}, errCaptchaTokenMissing
	}
	if err := a.verifier.Verify(ctx, CaptchaInput{Token: token}); err != nil {
		return interaction.Step{}, err
	}
	return interaction.Step{Result: &interaction.Result{
		Subject:  in.Subject,
		AuthTime: in.AuthTime,
	}}, nil
}

// buildPrimaryPassword constructs the internal [password.Authenticator]
// that drives the [PrimaryPassword] step. The builder validates the
// store dependency up-front so a misconfigured PrimaryPassword
// surfaces at op.New time rather than at the first authorize request.
func buildPrimaryPassword(s PrimaryPassword) (authn.Authenticator, error) { //nolint:ireturn,nolintlint // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
	if s.Store == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "PrimaryPassword.Store is nil",
		}
	}
	return password.NewAuthenticator(s.Store)
}

// buildPrimaryPasskey constructs the internal [passkey.Verifier] +
// [passkey.Authenticator] that drives the [PrimaryPasskey] step. The
// builder validates RP-side configuration up-front so a misconfigured
// PrimaryPasskey surfaces at op.New time rather than at the first
// authorize request.
func buildPrimaryPasskey(s PrimaryPasskey, clock timex.Clock) (authn.Authenticator, error) { //nolint:ireturn,nolintlint // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
	if s.Store == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "PrimaryPasskey.Store is nil",
		}
	}
	v, err := passkey.New(passkey.Config{
		RPID:                     s.RPID,
		RPDisplayName:            s.RPDisplayName,
		RPOrigins:                s.RPOrigins,
		SessionTTL:               s.SessionTTL,
		AAGUIDAllowlist:          s.AAGUIDAllowlist,
		AAGUIDReCheckOnAssertion: s.AAGUIDReCheckOnAssertion,
	})
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "PrimaryPasskey rejected by parser",
			Cause:       err,
		}
	}
	// Share the embedder-supplied clock so the WebAuthn session /
	// challenge expiry window uses the same instant as the rest of the
	// flow (WithClock contract). The Clock field lives on the Verifier,
	// not Config; a nil clock leaves the Verifier's SystemClock fallback.
	if v != nil && clock != nil {
		v.Clock = clock
	}
	auth, err := passkey.NewAuthenticator(v, s.Store)
	if err != nil {
		return nil, err
	}
	if s.CloneDetectionHandler != nil {
		// Wrap the public hook so the internal package consumes
		// only the deterministic credential identifier + sign
		// counter. The full *Credential remains internal so
		// embedders cannot pivot off the unparsed COSE_Key bytes
		// the upstream library exposes through it (H-E5).
		hook := s.CloneDetectionHandler
		auth = auth.WithCloneDetectionHandler(passkey.CloneDetectionHandlerFunc(func(ctx context.Context, subject string, cred *passkey.Credential) error {
			if cred == nil {
				return nil
			}
			return hook.HandleCloneDetected(ctx, subject, cred.ID, cred.Authenticator.SignCount)
		}))
	}
	return auth, nil
}

// buildStepTOTP constructs the internal [totp.Codec] + [totp.Verifier]
// + [totp.Authenticator] that drives the [StepTOTP] step. The codec is
// built from the public [StepTOTP.EncryptionKey] and rotation history,
// or — when those fields are empty — from the Provider-level fallback
// configured through [WithMFAEncryptionKeys].
// A non-empty per-step key always wins (more-specific-wins). The
// library never retains the bytes beyond the codec instance.
//
// The authenticator inherits the cross-factor brute-force counter
// (M-AUTHN-1) when one has been wired through [WithAuthnLockoutStore];
// the call-site reads the counter off the [config] before invoking
// the builder so the function signature remains stable across
// deployments that opt out of the cross-factor defence.
func buildStepTOTP(s StepTOTP, fallbackCurrent []byte, fallbackPrev [][]byte, clock timex.Clock) (authn.Authenticator, error) { //nolint:ireturn,nolintlint // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
	if s.Store == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepTOTP.Store is nil",
		}
	}
	current, prev := selectTOTPKeys(s, fallbackCurrent, fallbackPrev)
	if len(current) == 0 {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepTOTP.EncryptionKey is required (or configure WithMFAEncryptionKeys at the Provider level)",
		}
	}
	codec, err := totp.NewCodec(current, prev...)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepTOTP rejected by parser",
			Cause:       err,
		}
	}
	// Share the embedder-supplied clock so the TOTP step window and the
	// per-record lockout stamp read the same instant as the cross-factor
	// counter and the rest of the flow (WithClock contract). Nil falls
	// back to SystemClock.
	verifier := &totp.Verifier{Codec: codec, Clock: clock}
	return totp.NewAuthenticator(verifier, s.Store)
}

// attachLockoutCounter returns auth wrapped with the cross-factor
// lockout counter when one has been wired on the [config] through
// [WithAuthnLockoutStore] (M-AUTHN-1). When the option is not set the
// wrapper is a no-op and auth is returned as-is. The function is
// internal to the op package and consumed by the orchestrator wiring
// layer when a built-in second-factor [Step] is compiled into its
// authenticator. Embedders constructing factors directly through
// [ExternalStep] reach the same invariant by wrapping their
// authenticator with the per-package WithLockout helper before
// passing it to [ExternalStep.Authenticator].
//
// The [Clock] interface in op/ is structurally identical to
// [internal/timex.Clock]; the [clockShim] adapter forwards the
// embedder-supplied clock through so the lockout helper observes the
// same instant the rest of the library uses for token TTLs and audit
// timestamps. A nil [config.clock] passes nil through and the helper
// falls back to [timex.SystemClock].
func attachLockoutCounter(auth authn.Authenticator, c *config) authn.Authenticator { //nolint:ireturn,nolintlint // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
	if c == nil || c.authnLockoutStore == nil {
		return auth
	}
	counter, err := lockout.New(c.authnLockoutStore, clockShimOrNil(c.clock))
	if err != nil || counter == nil {
		return auth
	}
	switch t := auth.(type) {
	case *totp.Authenticator:
		return t.WithLockout(counter)
	case *emailotp.Authenticator:
		return t.WithLockout(counter)
	case *recovery.Authenticator:
		return t.WithLockout(counter)
	default:
		// Primary credential factors (password / passkey) and custom
		// ExternalStep authenticators are intentionally excluded from the
		// cross-factor counter (see WithAuthnLockoutStore godoc): their
		// brute-force defence is owned by the embedder's user store or the
		// wrapped custom factor, not this shared 2FA gate.
		return auth
	}
}

// clockShim adapts an [op.Clock] value to the [internal/timex.Clock]
// interface required by the lockout helper. The two interfaces are
// structurally identical (single Now() time.Time method); the shim
// exists solely because Go does not implicitly convert between named
// interface types.
type clockShim struct {
	inner Clock
}

func (s clockShim) Now() time.Time {
	if s.inner == nil {
		return time.Time{}
	}
	return s.inner.Now()
}

// clockShimOrNil returns a [timex.Clock]-compatible wrapper around c
// when c is non-nil, or nil otherwise. The lockout helper falls back
// to [timex.SystemClock] on a nil clock so production code paths that
// did not configure [WithClock] still see a valid wall-clock reading.
func clockShimOrNil(c Clock) timex.Clock { //nolint:ireturn,nolintlint // timex.Clock is the helper's contract; nil is the documented "use SystemClock" signal.
	if c == nil {
		return nil
	}
	return clockShim{inner: c}
}

// selectTOTPKeys resolves the per-step versus Provider-level encryption
// keys for a [StepTOTP]. A non-empty [StepTOTP.EncryptionKey] always
// wins (more-specific-wins); the rotation slot follows the same rule
// independently so an embedder can override only the active key while
// keeping the global rotation history.
func selectTOTPKeys(s StepTOTP, fallbackCurrent []byte, fallbackPrev [][]byte) ([]byte, [][]byte) {
	current := s.EncryptionKey
	if len(current) == 0 {
		current = fallbackCurrent
	}
	prev := s.EncryptionKeyPrev
	if len(prev) == 0 {
		prev = fallbackPrev
	}
	return current, prev
}

// buildStepEmailOTP constructs the internal [emailotp.Authenticator]
// that drives the [StepEmailOTP] step. The public [EmailDelivery]
// adapter is wrapped in a thin [emailotp.Mailer] shim so the internal
// package retains its narrow interface and the public API stays free
// of the [emailotp.Message] payload type.
//
//nolint:ireturn // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
func buildStepEmailOTP(s StepEmailOTP, clock timex.Clock) (authn.Authenticator, error) {
	if s.Store == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepEmailOTP.Store is nil",
		}
	}
	if s.Sender == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepEmailOTP.Sender is nil",
		}
	}
	if s.Users == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepEmailOTP.Users is nil",
		}
	}
	mailer := emailotp.MailerFunc(func(ctx context.Context, msg emailotp.Message) error {
		return s.Sender.Send(ctx, msg.To, msg.Code)
	})
	return emailotp.NewAuthenticator(emailotp.Config{
		Mailer:         mailer,
		Store:          s.Store,
		Users:          s.Users,
		CodeTTL:        s.CodeTTL,
		SendLatencyPad: s.SendLatencyPad,
		// Share the embedder-supplied clock so the code TTL, resend
		// window, and per-record lockout stamp read the same instant as
		// the rest of the flow (WithClock contract). Nil -> SystemClock.
		Clock: clock,
	})
}

// buildStepRecoveryCode constructs the internal [recovery.Verifier] +
// [recovery.Authenticator] that drives the [StepRecoveryCode] step.
// The verifier carries no construction-time configuration today; the
// argon2id parameters and lockout policy are pinned by
// [internal/authn/recovery].
//
//nolint:ireturn // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
func buildStepRecoveryCode(s StepRecoveryCode, clock timex.Clock) (authn.Authenticator, error) {
	if s.Store == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepRecoveryCode.Store is nil",
		}
	}
	// Share the embedder-supplied clock so the recovery-code lockout
	// stamp reads the same instant as the rest of the flow (WithClock
	// contract). Nil falls back to SystemClock.
	verifier := &recovery.Verifier{Clock: clock}
	return recovery.NewAuthenticator(verifier, s.Store)
}

// buildStepCaptcha wraps the [CaptchaVerifier] into the package's
// [captchaStepAdapter] so the LoginFlow orchestrator can drive captcha
// challenges through the same Begin / Continue dispatch path as
// factor-shaped Steps.
//
//nolint:ireturn // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
func buildStepCaptcha(s StepCaptcha) (authn.Authenticator, error) {
	if s.Verifier == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepCaptcha.Verifier is nil",
		}
	}
	return captchaStepAdapter{verifier: s.Verifier}, nil
}

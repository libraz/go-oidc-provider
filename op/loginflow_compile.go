package op

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/authn/password"
	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// CaptchaSubmissionFieldName is the [interaction.FieldSpec.Name] a
// [StepCaptcha] expects in the SPA submission. The SPA renders the
// upstream provider's challenge widget (Cloudflare Turnstile, Google
// reCAPTCHA, hCaptcha, …) and submits the resulting token under this
// key. The constant is exported so SPA documentation references the
// canonical wire name without a stringly-typed copy.
// [StepCaptcha] is the only captcha path: a [LoginFlow] schedules it
// through the rule list, e.g. [RuleAfterFailedAttempts] for an
// after-N-failures challenge.
const CaptchaSubmissionFieldName = authn.CaptchaTokenField

// captchaSubmissionMaxLen caps the token bytes the captcha step accepts
// in the submission. Provider tokens (Turnstile / reCAPTCHA / hCaptcha)
// are <= ~2 KiB; 4 KiB is comfortably above the realistic upper bound
// while keeping the parser away from pathological inputs.
const captchaSubmissionMaxLen = 4 * 1024

// errCaptchaTokenMissing surfaces when the SPA omits the captcha token
// field. The orchestrator's [interaction.FieldSpec] validation should
// already have caught this; the adapter re-checks at the trust boundary.
// Like a rejected token it wraps [authn.ErrFactorRetry], so the challenge
// is re-issued rather than failing the request.
var errCaptchaTokenMissing = fmt.Errorf("op: captcha_token field is missing: %w", authn.ErrFactorRetry)

// errCaptchaRejected wraps a [CaptchaVerifier] refusal in
// [authn.ErrFactorRetry]: the orchestrator re-issues the challenge until
// its failure budget runs out, exactly as on the threshold captcha path.
var errCaptchaRejected = fmt.Errorf("op: captcha token rejected: %w", authn.ErrFactorRetry)

// errCaptchaVerifierNil surfaces when [StepCaptcha.Verifier] is nil at
// the time the orchestrator dispatches Continue. The compile path
// rejects a nil verifier at op.New time, so reaching this branch means
// the compiled flow was mutated after compilation — defensive.
var errCaptchaVerifierNil = errors.New("op: StepCaptcha.Verifier is nil")

// validateLoginFlowDependencies checks every interface-valued dependency
// carried inside a [LoginFlow] without invoking it. config.validate calls this
// before Provider construction performs externally visible work (metrics
// registration and static-client reconciliation), so typed-nil values surface
// as field-specific configuration errors instead of a later method-call panic.
// It also refuses a Primary that cannot run on a fresh login: Primary is what
// binds the subject, and the built-in steps that assert for a known subject
// need one already bound.
func validateLoginFlowDependencies(flow LoginFlow) error {
	if err := validatePrimaryPosition(flow.Primary); err != nil {
		return err
	}
	if flow.Decider != nil && nilcheck.IsNil(flow.Decider) {
		return loginFlowDependencyError("LoginFlow.Decider")
	}
	if flow.Risk != nil && nilcheck.IsNil(flow.Risk) {
		return loginFlowDependencyError("LoginFlow.Risk")
	}
	if err := validateStepDependencies("Primary", flow.Primary); err != nil {
		return err
	}
	if flow.Registration != nil {
		if err := validateStepDependencies("Registration", flow.Registration); err != nil {
			return err
		}
		if err := validateRegistrationShape(flow.Registration); err != nil {
			return err
		}
	}
	for i, rule := range flow.Rules {
		where := "Rules[" + strconv.Itoa(i) + "].Then"
		if err := validateStepDependencies(where, rule.Then); err != nil {
			return err
		}
	}
	return nil
}

// validatePrimaryPosition refuses a Primary, or a step of a [StepOneOf]
// placed there, that cannot run before a subject is bound. Nil steps are
// left to the dependency checks.
func validatePrimaryPosition(step Step) error {
	oneOf, ok := step.(StepOneOf)
	if !ok {
		return validatePrimaryCapable("Primary", step, false)
	}
	if oneOf.IfNoneEnrolled == UnenrolledSkip {
		return newConfigurationError("WithLoginFlow: Primary StepOneOf must not use UnenrolledSkip — "+
			"no subject is bound yet, so there is no enrollment to check", nil)
	}
	for i, inner := range oneOf.Steps {
		if nilcheck.IsNil(inner) {
			continue
		}
		if err := validatePrimaryCapable("Primary.StepOneOf.Steps["+strconv.Itoa(i)+"]", inner, true); err != nil {
			return err
		}
	}
	return nil
}

// validatePrimaryCapable checks one step at the Primary position. A step
// of a Primary [StepOneOf] must be one that can stand first; Primary
// itself leaves other shapes to the compiler.
func validatePrimaryCapable(where string, step Step, inOneOf bool) error {
	switch s := step.(type) {
	case PrimaryPassword:
		return nil
	case PrimaryPasskey:
		if !s.RequireUserVerification {
			return newConfigurationError("WithLoginFlow: "+where+": a passkey that stands alone must verify the user;"+
				" set PrimaryPasskey.RequireUserVerification or move the passkey to a Rule", nil)
		}
		return nil
	case ExternalStep:
		if s.CountFailures {
			return newConfigurationError("WithLoginFlow: "+where+": ExternalStep.CountFailures needs a bound subject to"+
				" count against and none is bound at Primary; leave guessing limits to the remote verifier", nil)
		}
		return nil
	}
	if name := subjectBoundStepName(step); name != "" {
		return newConfigurationError("WithLoginFlow: "+where+" must not be "+name+" — the step needs a subject a previous"+
			" step bound; use PrimaryPassword or an ExternalStep as Primary and "+name+" in a Rule", nil)
	}
	if inOneOf {
		return newConfigurationError("WithLoginFlow: "+where+" must be PrimaryPassword, PrimaryPasskey or ExternalStep"+
			" — a StepOneOf at Primary offers only steps that can bind the subject", nil)
	}
	return nil
}

// validateRegistrationShape refuses a [LoginFlow.Registration] that is
// not an [ExternalStep], or one that counts failures: a built-in step
// matches an existing account rather than creating one, and no subject
// is bound yet to count against.
func validateRegistrationShape(step Step) error {
	ext, ok := step.(ExternalStep)
	if !ok {
		return newConfigurationError("WithLoginFlow: Registration must be an ExternalStep — a built-in Step or a"+
			" StepOneOf signs an existing account in rather than creating one", nil)
	}
	if ext.CountFailures {
		return newConfigurationError("WithLoginFlow: Registration: ExternalStep.CountFailures needs a bound subject to"+
			" count against and none is bound before Registration", nil)
	}
	return nil
}

// subjectBoundStepName names a built-in [Step] that can only run for a
// subject an earlier step bound, or returns "" for any other Step.
func subjectBoundStepName(step Step) string {
	switch step.(type) {
	case StepTOTP:
		return "StepTOTP"
	case StepEmailOTP:
		return "StepEmailOTP"
	case StepRecoveryCode:
		return "StepRecoveryCode"
	}
	return ""
}

// validateStepDependencies validates the public dependencies owned by one
// built-in or external Step. Optional interfaces distinguish an absent nil
// interface from an explicitly supplied typed nil: absence keeps the documented
// default, while typed nil is a configuration mistake.
func validateStepDependencies(where string, step Step) error {
	if nilcheck.IsNil(step) {
		return loginFlowDependencyError(where)
	}
	switch s := step.(type) {
	case PrimaryPassword:
		return validatePrimaryPasswordDependencies(where, s)
	case PrimaryPasskey:
		return validatePrimaryPasskeyDependencies(where, s)
	case StepTOTP:
		return validateTOTPDependencies(where, s)
	case StepEmailOTP:
		return validateEmailOTPDependencies(where, s)
	case StepRecoveryCode:
		return validateRecoveryCodeDependencies(where, s)
	case StepCaptcha:
		return validateCaptchaDependencies(where, s)
	case ExternalStep:
		return validateExternalStepDependencies(where, s)
	case StepOneOf:
		return validateOneOfDependencies(where, s)
	}
	return nil
}

// validateOneOfDependencies checks every step of a [StepOneOf]. Nesting,
// captcha steps, kind collisions and the policy range are checked by the
// compiler, which sees the whole flow.
func validateOneOfDependencies(where string, step StepOneOf) error {
	if len(step.Steps) == 0 {
		return newConfigurationError("WithLoginFlow: "+where+".StepOneOf.Steps must not be empty", nil)
	}
	for i, inner := range step.Steps {
		innerWhere := where + ".StepOneOf.Steps[" + strconv.Itoa(i) + "]"
		if err := validateStepDependencies(innerWhere, inner); err != nil {
			return err
		}
		if ext, ok := inner.(ExternalStep); ok {
			if err := checkExternalStepKind(innerWhere, ext); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePrimaryPasswordDependencies(where string, step PrimaryPassword) error {
	if nilcheck.IsNil(step.Store) {
		return loginFlowDependencyError(where + ".PrimaryPassword.Store")
	}
	for i, scheme := range step.LegacySchemes {
		if nilcheck.IsNil(scheme) {
			return loginFlowDependencyError(where + ".PrimaryPassword.LegacySchemes[" + strconv.Itoa(i) + "]")
		}
	}
	return nil
}

func validatePrimaryPasskeyDependencies(where string, step PrimaryPasskey) error {
	if nilcheck.IsNil(step.Store) {
		return loginFlowDependencyError(where + ".PrimaryPasskey.Store")
	}
	if step.CloneDetectionHandler != nil && nilcheck.IsNil(step.CloneDetectionHandler) {
		return loginFlowDependencyError(where + ".PrimaryPasskey.CloneDetectionHandler")
	}
	for i, root := range step.AttestationRoots {
		if root == nil {
			return loginFlowDependencyError(where + ".PrimaryPasskey.AttestationRoots[" + strconv.Itoa(i) + "]")
		}
	}
	if len(step.AAGUIDAllowlist) > 0 && len(step.AttestationRoots) == 0 {
		return newConfigurationError("WithLoginFlow: "+where+".PrimaryPasskey.AAGUIDAllowlist requires AttestationRoots", nil)
	}
	return nil
}

func validateTOTPDependencies(where string, step StepTOTP) error {
	if nilcheck.IsNil(step.Store) {
		return loginFlowDependencyError(where + ".StepTOTP.Store")
	}
	return nil
}

func validateEmailOTPDependencies(where string, step StepEmailOTP) error {
	if nilcheck.IsNil(step.Store) {
		return loginFlowDependencyError(where + ".StepEmailOTP.Store")
	}
	if nilcheck.IsNil(step.Sender) {
		return loginFlowDependencyError(where + ".StepEmailOTP.Sender")
	}
	if nilcheck.IsNil(step.Users) {
		return loginFlowDependencyError(where + ".StepEmailOTP.Users")
	}
	return nil
}

func validateRecoveryCodeDependencies(where string, step StepRecoveryCode) error {
	if nilcheck.IsNil(step.Store) {
		return loginFlowDependencyError(where + ".StepRecoveryCode.Store")
	}
	return nil
}

func validateCaptchaDependencies(where string, step StepCaptcha) error {
	if nilcheck.IsNil(step.Verifier) {
		return loginFlowDependencyError(where + ".StepCaptcha.Verifier")
	}
	return nil
}

func validateExternalStepDependencies(where string, step ExternalStep) error {
	if nilcheck.IsNil(step.Authenticator) {
		return loginFlowDependencyError(where + ".ExternalStep.Authenticator")
	}
	return nil
}

func loginFlowDependencyError(field string) error {
	return newConfigurationError("WithLoginFlow: "+field+" is nil", nil)
}

// captchaFactorName is the inert factor type and the prompt type the
// captcha adapter reports.
const captchaFactorName = "captcha"

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
func (captchaStepAdapter) Type() authn.FactorType { return captchaFactorName }

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
// "captcha" prompt type.
func (captchaStepAdapter) Prompts() []string { return []string{captchaFactorName} }

// Begin implements [authn.Authenticator]. Returns the captcha prompt
// with a single hidden submission field for the upstream provider's
// token.
func (a captchaStepAdapter) Begin(_ context.Context, _ authn.BeginInput) (interaction.Step, error) {
	provider, siteKey := authn.CaptchaWidgetFor(a.verifier)
	prompt := &interaction.Prompt{
		Type: captchaFactorName,
		Data: interaction.CaptchaPromptData{Provider: provider, SiteKey: siteKey},
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
// returns a populated [interaction.Result] on success or
// [errCaptchaRejected] on failure. The upstream reason stays in the
// wrapped error for the log; the SPA only sees a fresh challenge, so it
// cannot enumerate provider-side rejection codes.
func (a captchaStepAdapter) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	if nilcheck.IsNil(a.verifier) {
		return interaction.Step{}, errCaptchaVerifierNil
	}
	token, ok := in.Submission.Values[CaptchaSubmissionFieldName]
	if !ok || token == "" {
		return interaction.Step{}, errCaptchaTokenMissing
	}
	if err := a.verifier.Verify(ctx, CaptchaInput{
		Token:    token,
		RemoteIP: in.RemoteIP,
	}); err != nil {
		return interaction.Step{}, fmt.Errorf("%w: %w", errCaptchaRejected, err)
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
// The legacy schemes, the store's optional hash updater and the provider
// logger ride the authenticator's config.
func buildPrimaryPassword(s PrimaryPassword, cfg *config) (authn.Authenticator, error) { //nolint:ireturn,nolintlint // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
	auth, err := password.NewAuthenticator(s.Store)
	if err != nil {
		return nil, err
	}
	var updater store.UserPasswordHashUpdater
	if u, ok := s.Store.(store.UserPasswordHashUpdater); ok {
		updater = u
	}
	return auth.WithConfig(password.Config{
		LegacySchemes: append([]PasswordHashScheme(nil), s.LegacySchemes...),
		HashUpdater:   updater,
		Logger:        cfg.logger,
	}), nil
}

// buildPrimaryPasskey constructs the internal [passkey.Verifier] +
// [passkey.Authenticator] that drives the [PrimaryPasskey] step. The
// builder validates RP-side configuration up-front so a misconfigured
// PrimaryPasskey surfaces at op.New time rather than at the first
// authorize request. discoverable enables the passwordless ceremony the
// Primary position runs.
func buildPrimaryPasskey(s PrimaryPasskey, clock timex.Clock, discoverable bool) (authn.Authenticator, error) { //nolint:ireturn,nolintlint // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
	// The ceremony configuration is derived through the shared helper the
	// enrolment facade also calls, so every policy axis the two ceremonies
	// must agree on — user verification, conveyance preference — is
	// computed once. A credential registered under a policy the login side
	// reads differently is a credential the user can never sign in with.
	ceremony := passkey.ConfigFrom(passkey.StepPolicy{
		RPID:                     s.RPID,
		RPDisplayName:            s.RPDisplayName,
		RPOrigins:                s.RPOrigins,
		SessionTTL:               s.SessionTTL,
		RequireUserVerification:  s.RequireUserVerification,
		AAGUIDAllowlist:          s.AAGUIDAllowlist,
		AttestationRoots:         s.AttestationRoots,
		AAGUIDReCheckOnAssertion: s.AAGUIDReCheckOnAssertion,
	})
	ceremony.AllowDiscoverable = discoverable
	v, err := passkey.New(ceremony)
	if err != nil {
		return nil, newConfigurationError("PrimaryPasskey rejected by parser", err)
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
		// the upstream library exposes through it.
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
// when one has been wired through [WithAuthnLockoutStore]; the
// call-site reads the counter off the [config] before invoking the
// builder so the function signature remains stable across deployments
// that opt out of the cross-factor defence.
func buildStepTOTP(s StepTOTP, fallbackCurrent []byte, fallbackPrev [][]byte, clock timex.Clock) (authn.Authenticator, error) { //nolint:ireturn,nolintlint // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
	current, prev := selectTOTPKeys(s, fallbackCurrent, fallbackPrev)
	if len(current) == 0 {
		return nil, newConfigurationError("StepTOTP.EncryptionKey is required (or configure WithMFAEncryptionKeys at the Provider level)", nil)
	}
	codec, err := totp.NewCodec(current, prev...)
	if err != nil {
		return nil, newConfigurationError("StepTOTP rejected by parser", err)
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
// [WithAuthnLockoutStore]. When the option is not set the wrapper is
// a no-op and auth is returned as-is. The function is internal to the
// op package and consumed by the orchestrator wiring layer when a
// built-in second-factor [Step] is compiled into its authenticator.
// An [ExternalStep] opts in through [ExternalStep.CountFailures], which
// wraps its authenticator with the same counter (see
// [projectExternalStep]).
func attachLockoutCounter(auth authn.Authenticator, c *config) authn.Authenticator { //nolint:ireturn,nolintlint // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
	counter := newLockoutCounter(c)
	if counter == nil {
		return auth
	}
	switch t := auth.(type) {
	case *password.Authenticator:
		return t.WithLockout(counter)
	case *totp.Authenticator:
		return t.WithLockout(counter)
	case *emailotp.Authenticator:
		return t.WithLockout(counter)
	case *recovery.Authenticator:
		return t.WithLockout(counter)
	default:
		// A passkey assertion is not a guessable secret, so it is not
		// counted; ExternalStep opts in through CountFailures.
		return auth
	}
}

// newLockoutCounter returns the cross-factor lockout counter over the
// store [resolveAuthnLockoutStore] picks, or nil when none resolves.
//
// The embedder-supplied [Clock] is passed through, so the lockout
// helper observes the same instant the rest of the library uses for
// token TTLs and audit timestamps. A nil clock falls back to the system
// clock inside the helper.
func newLockoutCounter(c *config) *lockout.Counter {
	lockoutStore := resolveAuthnLockoutStore(c)
	if lockoutStore == nil {
		return nil
	}
	counter, err := lockout.New(lockoutStore, c.clock)
	if err != nil || counter == nil {
		return nil
	}
	return counter.WithEmitter(c.effectiveAuditEmitter())
}

// resolveAuthnLockoutStore is the single source of the cross-factor
// counter's store: an explicit [WithAuthnLockoutStore] wins, otherwise
// the [WithStore] value is probed for an AuthnLockouts accessor whose
// result is non-nil, otherwise nil (the counter is off).
func resolveAuthnLockoutStore(c *config) store.AuthnLockoutStore { //nolint:ireturn,nolintlint // store.AuthnLockoutStore is the substore contract.
	if c == nil {
		return nil
	}
	if !nilcheck.IsNil(c.authnLockoutStore) {
		return c.authnLockoutStore
	}
	if p, ok := c.store.(interface {
		AuthnLockouts() store.AuthnLockoutStore
	}); ok {
		if s := p.AuthnLockouts(); !nilcheck.IsNil(s) {
			return s
		}
	}
	return nil
}

// warnWithoutLockoutStore logs once that brute-force limiting is off
// when the login flow schedules a counter-consuming step but no
// lockout store resolves.
func (c *config) warnWithoutLockoutStore() {
	if c.logger == nil || resolveAuthnLockoutStore(c) != nil {
		return
	}
	for _, step := range c.loginFlowSteps() {
		if !countsFailures(step) {
			continue
		}
		c.logger.Warn(
			"the login flow has a password or second-factor step but no "+
				"authn lockout store is available, so per-subject brute-force "+
				"limiting is disabled; use a WithStore value that exposes "+
				"AuthnLockouts() or configure WithAuthnLockoutStore",
			"option", "WithAuthnLockoutStore",
		)
		return
	}
}

// countsFailures reports whether step feeds the cross-factor lockout
// counter. A passkey assertion is not a guessable secret and a captcha is
// not a credential, so neither is counted.
func countsFailures(step Step) bool {
	switch s := step.(type) {
	case PrimaryPassword, StepTOTP, StepEmailOTP, StepRecoveryCode:
		return true
	case ExternalStep:
		return s.CountFailures
	default:
		return false
	}
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
// The verifier takes no construction-time configuration: the argon2id
// parameters and the lockout policy are pinned by the recovery-code
// authenticator itself rather than being embedder-tunable, so a
// deployment cannot weaken them by misconfiguration.
//
//nolint:ireturn // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
func buildStepRecoveryCode(s StepRecoveryCode, clock timex.Clock) (authn.Authenticator, error) {
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
	return captchaStepAdapter{verifier: s.Verifier}, nil
}

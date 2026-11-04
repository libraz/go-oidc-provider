package op

import (
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/authn"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// errExternalStepAuthenticatorNil reports an [ExternalStep] with no wrapped [Authenticator].
var errExternalStepAuthenticatorNil = errors.New("op: ExternalStep.Authenticator is nil")

// errStepBuiltinNotCompiled is returned by a built-in [Step] when its
// Begin / Continue method is invoked outside of an
// [authn.CompiledLoginFlow] context. Built-in Steps are configuration
// descriptors whose underlying [Authenticator] machinery (TOTP codec,
// passkey verifier, recovery hash, …) requires construction-time
// dependencies that only the orchestrator's compile path supplies. The
// production path always routes Begin / Continue through the
// orchestrator-synthesised Authenticator, so a direct call to
// PrimaryPassword.Begin is a programming error rather than a supported
// API surface.
//
// [ExternalStep] is the supported seam for embedders who need to drive
// a [Step] outside of [LoginFlow] composition: ExternalStep adapts an
// already-constructed [Authenticator] into the [Step] interface, and
// its Begin / Continue forward verbatim with no additional dependency
// requirement.
var errStepBuiltinNotCompiled = errors.New("op: built-in Step requires LoginFlow compilation; use ExternalStep for direct dispatch")

// EmailDelivery is the dispatcher [StepEmailOTP] uses to deliver a
// numeric one-time code to the user's e-mail address. Implementations
// integrate with the embedder's outbound mail provider (SMTP, SES,
// SendGrid, ...) and return nil once the provider has accepted the
// message for delivery.
//
// The library never retains the delivered code: after dispatch only
// the salted hash persists in [store.EmailOTPRecord]. Implementations
// MUST treat the code argument as one-shot material — a structured
// log entry containing the code is a credential leak.
//
// Implementations MUST be safe for concurrent use by multiple
// goroutines.
type EmailDelivery interface {
	// Send delivers code to address. The recipient address is the
	// verbatim string the user supplied; implementations are
	// responsible for any provider-side validation. Returning a
	// non-nil error causes the orchestrator to surface a generic
	// "delivery failed" prompt without leaking provider detail.
	Send(ctx context.Context, address, code string) error
}

// Step is the embedder-facing unit of authentication a [LoginFlow]
// composes; it is not the [interaction.Step] a UI driver renders.
// The interface mirrors [Authenticator]'s Begin / Continue
// shape so the orchestrator's Step → Authenticator wrapper is a
// trivial adapter, but a Step additionally carries a [StepKind] used
// by the orchestrator for completed-step deduplication and by rule
// predicates inspecting [LoginContext.CompletedSteps].
//
// Built-in implementations (see [PrimaryPassword], [PrimaryPasskey],
// [StepTOTP], [StepEmailOTP], [StepCaptcha], [StepRecoveryCode]) cover
// the common factors. Embedders with proprietary factors continue to
// implement [Authenticator] directly; LoginFlow does not displace that
// surface.
//
// Implementations MUST be safe for concurrent use by multiple
// goroutines.
type Step interface {
	// Begin starts the ceremony. The returned [interaction.Step]
	// carries either a Prompt (multi-step factor) or a populated
	// Result (single-step factor that completes immediately).
	Begin(ctx context.Context, in BeginInput) (interaction.Step, error)

	// Continue advances the ceremony with the SPA's submission. A
	// [interaction.Step] carrying neither Prompt nor Result is
	// invalid and rejected by the orchestrator.
	Continue(ctx context.Context, in ContinueInput) (interaction.Step, error)

	// Kind returns the [StepKind] discriminator used for completed-
	// step deduplication and rule-predicate inspection. Two
	// registered Steps MUST NOT share a Kind on the same [LoginFlow].
	Kind() StepKind
}

// StepKind is the typed identifier a [Step] reports through
// [Step.Kind]. The string values are stable: they appear in
// [LoginContext.CompletedSteps] read by rule predicates and in
// orchestrator audit logs.
type StepKind string

// StepKind values. The constants enumerate the built-in [Step]
// implementations the library ships. Embedder-defined steps SHOULD
// use a dotted prefix matching the org identifier ("myorg.sms_otp")
// to avoid colliding with future built-ins.
const (
	// StepKindPassword identifies [PrimaryPassword].
	StepKindPassword StepKind = "password"

	// StepKindPasskey identifies [PrimaryPasskey].
	StepKindPasskey StepKind = "passkey"

	// StepKindTOTP identifies [StepTOTP].
	StepKindTOTP StepKind = "totp"

	// StepKindEmailOTP identifies [StepEmailOTP].
	StepKindEmailOTP StepKind = "email_otp"

	// StepKindCaptcha identifies [StepCaptcha].
	StepKindCaptcha StepKind = "captcha"

	// StepKindRecoveryCode identifies [StepRecoveryCode].
	StepKindRecoveryCode StepKind = "recovery_code"
)

// String returns the underlying identifier.
func (k StepKind) String() string { return string(k) }

// IsBuiltin reports whether k is one of the [StepKind] constants
// declared by the library. Built-in identifiers are reserved: a user
// extension MUST NOT match any of them, and the [LoginFlow] compiler
// rejects collisions at construction time.
func (k StepKind) IsBuiltin() bool {
	switch k {
	case StepKindPassword, StepKindPasskey, StepKindTOTP,
		StepKindEmailOTP, StepKindCaptcha, StepKindRecoveryCode:
		return true
	default:
		return false
	}
}

// IsUserDefined reports whether k is a non-empty user extension. The
// rule mirrors [FactorType.IsUserDefined]: a dotted prefix segregates
// user extensions from the bare built-in identifiers, so that
// [ExternalStep] authors do not need to consult a separate registry to
// verify their chosen name is safe.
func (k StepKind) IsUserDefined() bool {
	if k == "" || k.IsBuiltin() {
		return false
	}
	return strings.Contains(string(k), ".")
}

// PrimaryPassword is the built-in primary-credential [Step] backed by
// a [store.UserPasswordStore]. It is the most common first factor: the
// embedder supplies a store that resolves usernames to subjects and
// returns the encoded password hash, and the library drives prompt
// rendering and constant-time Argon2id verification.
//
// The library verifies password hashes in PHC argon2id encoding
// (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`) natively. A user
// table carried over from another system keeps working through
// [PrimaryPassword.LegacySchemes]: a stored hash that is not argon2id is
// verified by the first scheme that recognizes it, and on success it is
// rewritten as argon2id when Store implements
// [store.UserPasswordHashUpdater]. A hash no scheme recognizes is treated
// like a wrong password, and the first one met is logged as a warning
// that names no user and no hash.
type PrimaryPassword struct {
	// Store is the user-account store the password is verified
	// against. MUST be non-nil; the orchestrator rejects a flow with
	// a nil Store at construction time.
	Store store.UserPasswordStore

	// LegacySchemes verifies stored hashes that are not argon2id, in
	// declaration order; the first scheme whose Recognizes reports true
	// decides. Nil or empty accepts argon2id only. A nil element is
	// rejected by [New].
	//
	// After a successful legacy verification the password is re-encoded
	// as argon2id and written back through
	// [store.UserPasswordHashUpdater] when Store implements it. A failed
	// write is logged and the login still succeeds; the rewrite is
	// retried on the next login. A store without the interface, or one
	// that answers [store.ErrPasswordHashUpdateUnsupported], keeps the
	// legacy hash. Lockout and the unknown-user dummy verification apply
	// to legacy hashes as they do to argon2id ones.
	//
	// Stable since v1.5.
	LegacySchemes []PasswordHashScheme
}

// Begin implements [Step]. PrimaryPassword is a configuration
// descriptor: the orchestrator's [LoginFlow] compiler resolves it to an
// internal [Authenticator] that performs the password ceremony at
// runtime. A direct call to Begin returns
// [errStepBuiltinNotCompiled] because the standalone path lacks the
// argon2id verifier and user-store wiring the compiled path injects.
func (PrimaryPassword) Begin(_ context.Context, _ BeginInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Continue implements [Step]. See [PrimaryPassword.Begin].
func (PrimaryPassword) Continue(_ context.Context, _ ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Kind implements [Step]. Returns [StepKindPassword].
func (PrimaryPassword) Kind() StepKind { return StepKindPassword }

// PrimaryPasskey is the built-in passkey [Step] backed by a
// [store.PasskeyStore]. Its behaviour follows its position:
//
//   - As a [Rule] step it asserts against the credentials of the subject
//     an earlier step bound.
//   - As [LoginFlow.Primary], or inside a [StepOneOf] there, it runs a
//     passwordless ceremony with discoverable credentials: the browser
//     picks a resident credential, the credential's record names the
//     subject, and the assertion's user handle must match it. There the
//     step must set [PrimaryPasskey.RequireUserVerification]; [New]
//     rejects it otherwise, because a passkey that stands alone is the
//     only factor of the login. Such a login reaches AAL2 with amr
//     ["hwk"].
//
// An unknown credential and a user handle that does not match the
// credential's subject are both answered with the same fresh challenge,
// so the response does not reveal which credentials exist.
type PrimaryPasskey struct {
	// Store is the passkey credential store. MUST be non-nil.
	Store store.PasskeyStore

	// RPID is the WebAuthn Relying Party Identifier — typically the
	// OP's effective domain ("id.example.com", never a URL or port).
	// It is bound into the credential at registration time and matched
	// at assertion time; changing it invalidates every previously-
	// registered credential. MUST be non-empty.
	RPID string

	// RPDisplayName is the human-readable Relying Party label shown by
	// the user agent during the ceremony ("Example Identity"). It has
	// no security effect but spec-compliant authenticators require it.
	// MUST be non-empty.
	RPDisplayName string

	// RPOrigins is the list of fully-qualified origins permitted to
	// initiate ceremonies ("https://id.example.com"). Cross-origin
	// iframe flows MAY require additional entries; embedders SHOULD
	// enumerate every public-facing origin they terminate TLS on.
	// MUST be non-empty.
	RPOrigins []string

	// SessionTTL is the absolute lifetime stamped on the per-ceremony
	// challenge session. A zero value falls back to five minutes.
	// Embedders MAY shorten the value to tighten the replay window but
	// SHOULD NOT lengthen it past a few minutes.
	SessionTTL time.Duration

	// CloneDetectionHandler is the optional embedder hook the adapter
	// invokes when the WebAuthn library reports a credential clone
	// (sign counter did not strictly increase, W3C WebAuthn L3 §7.2
	// step 17). Embedders use the hook to disable the affected
	// credential in their account-management UI so the user does not
	// loop on the "suspicious activity detected" surface.
	//
	// The hook is best-effort: a non-nil error is dropped, the
	// orchestrator still surfaces the clone signal to the chain
	// through the standard error path. Implementations MUST be safe
	// for concurrent use.
	CloneDetectionHandler PasskeyCloneDetectionHandler

	// AAGUIDAllowlist is the optional set of authenticator-model
	// identifiers (16-byte AAGUIDs encoded as canonical UUID
	// strings) the registration ceremony will accept. Empty disables
	// the registration-time check; a non-empty slice rejects any
	// registration whose authenticator is not in the set. The
	// allowlist also drives the [AAGUIDReCheckOnAssertion] gate.
	//
	// Setting this switches the ceremony to "direct" attestation
	// conveyance, because an AAGUID reported without attestation is
	// self-asserted and could name any model. A signed attestation only
	// vouches for the model when its certificate chain verifies up to
	// one of [AttestationRoots], which a non-empty allowlist therefore
	// requires; a registration whose chain does not verify, or that
	// carries none (self-attested, unattested), is refused rather than
	// matched against the list. Expect a user-agent attestation prompt
	// on registration, and leave the field empty if that disclosure is
	// not wanted.
	AAGUIDAllowlist []string

	// AttestationRoots are the trust anchors for [AAGUIDAllowlist]: a
	// registration is admitted only when its attestation certificate
	// chain (x5c) verifies up to one of them. The OP does not fetch
	// FIDO MDS, so the embedder supplies the roots, for example
	// extracted from FIDO MDS3 metadata statements. [New] refuses a
	// non-empty allowlist with no roots, and a nil entry. Ignored when
	// the allowlist is empty.
	AttestationRoots []*x509.Certificate

	// RequireUserVerification makes every ceremony demand the WebAuthn
	// user-verification gesture (PIN, biometric) instead of merely
	// preferring it. The default (false) lets an authenticator answer
	// with a presence-only assertion, which proves possession of the
	// private key and nothing else: that is a single factor, so the
	// login is reported at AAL1 and its acr is the AAL1 URI. Setting the
	// field refuses an assertion whose UV flag is clear, so every
	// successful passkey login counts as two factors and reaches AAL2.
	//
	// Deployments that gate a scope or an acr on two-factor
	// authentication SHOULD set it; the cost is that authenticators
	// without a PIN or biometric can no longer be used to log in.
	RequireUserVerification bool

	// AAGUIDReCheckOnAssertion makes the verifier re-check the matched
	// credential's AAGUID against [AAGUIDAllowlist] at assertion time,
	// so an embedder that narrows the allowlist after registration can
	// revoke credentials whose authenticator model has fallen out of
	// policy. The default (false) enforces the AAGUID at registration
	// only.
	AAGUIDReCheckOnAssertion bool
}

// PasskeyCloneDetectionHandler is the embedder hook
// [PrimaryPasskey.CloneDetectionHandler] uses to receive clone-warning
// signals. Implementations decide the policy: disable the
// credential, page the SOC, force a re-enrolment. The hook is
// invoked with the persisted [store.PasskeyRecord]'s public fields so
// the embedder can correlate the credential against the row in the
// account-management UI.
//
// Implementations MUST be safe for concurrent use.
type PasskeyCloneDetectionHandler interface {
	// HandleCloneDetected is invoked once per clone-warning. The
	// credentialID is the WebAuthn credential identifier that
	// triggered the warning; signCount is the counter the
	// authenticator reported (which did not strictly increase); the
	// returned error is dropped — the wire response stays a chain-
	// fatal failure regardless of whether the embedder's disable hook
	// succeeds. Embedders that want to observe failures SHOULD log
	// internally.
	HandleCloneDetected(ctx context.Context, subject string, credentialID []byte, signCount uint32) error
}

// PasskeyCloneDetectionHandlerFunc adapts a plain function to the
// [PasskeyCloneDetectionHandler] interface.
type PasskeyCloneDetectionHandlerFunc func(ctx context.Context, subject string, credentialID []byte, signCount uint32) error

// HandleCloneDetected implements [PasskeyCloneDetectionHandler].
func (f PasskeyCloneDetectionHandlerFunc) HandleCloneDetected(ctx context.Context, subject string, credentialID []byte, signCount uint32) error {
	return f(ctx, subject, credentialID, signCount)
}

// Begin implements [Step]. The built-in Step is a configuration
// descriptor; direct dispatch returns [errStepBuiltinNotCompiled]
// because the underlying primitive (TOTP codec, passkey verifier, …)
// is constructed only inside the [LoginFlow] compile path. Wrap your
// own [Authenticator] in [ExternalStep] for direct dispatch.
func (PrimaryPasskey) Begin(_ context.Context, _ BeginInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Continue implements [Step]. See the matching Begin for the
// errStepBuiltinNotCompiled rationale.
func (PrimaryPasskey) Continue(_ context.Context, _ ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Kind implements [Step]. Returns [StepKindPasskey].
func (PrimaryPasskey) Kind() StepKind { return StepKindPasskey }

// StepTOTP is the built-in second-factor [Step] backed by a
// [store.TOTPStore]. Typically attached through a rule that fires when
// risk or scope policy demands an OTP factor.
type StepTOTP struct {
	// Store is the TOTP secret store. MUST be non-nil.
	Store store.TOTPStore

	// EncryptionKey is the AES-256-GCM key used to seal the shared
	// secret at rest. When non-empty, MUST be exactly 32 bytes; an
	// empty value falls back to [WithMFAEncryptionKeys] configured on
	// the Provider. The library
	// binds the subject identifier as additional authenticated data,
	// so a blob exfiltrated from one row fails to decrypt under a
	// different subject.
	EncryptionKey []byte

	// EncryptionKeyPrev is the rotation history accepted on
	// decryption. Each entry MUST be exactly 32 bytes. The current
	// key is tried first; on failure each previous key is tried in
	// order. An empty value falls back to the rotation slot
	// configured through [WithMFAEncryptionKeys] on the Provider.
	// Retain previous keys until every persisted record has been
	// re-sealed under the active key.
	EncryptionKeyPrev [][]byte
}

// Begin implements [Step]. The built-in Step is a configuration
// descriptor; direct dispatch returns [errStepBuiltinNotCompiled]
// because the underlying primitive (TOTP codec, passkey verifier, …)
// is constructed only inside the [LoginFlow] compile path. Wrap your
// own [Authenticator] in [ExternalStep] for direct dispatch.
func (StepTOTP) Begin(_ context.Context, _ BeginInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Continue implements [Step]. See the matching Begin for the
// errStepBuiltinNotCompiled rationale.
func (StepTOTP) Continue(_ context.Context, _ ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Kind implements [Step]. Returns [StepKindTOTP].
func (StepTOTP) Kind() StepKind { return StepKindTOTP }

// StepEmailOTP is the built-in second-factor [Step] that delivers a
// numeric code to the user's e-mail address. The factor emits two
// prompts: send (collect destination, dispatch code) and verify
// (collect code, validate).
type StepEmailOTP struct {
	// Store is the per-attempt OTP record store. MUST be non-nil.
	Store store.EmailOTPStore

	// Sender is the e-mail delivery adapter. MUST be non-nil.
	Sender EmailDelivery

	// Users is the read-only [store.UserStore] the step queries to
	// resolve the subject's bound "email" claim. The submitted address
	// is matched against the bound value in constant time; only on a
	// match does the dispatcher run. MUST be non-nil.
	Users store.UserStore

	// CodeTTL is the acceptance window from issuance. A zero value
	// falls back to the library default (five minutes).
	CodeTTL time.Duration

	// SendLatencyPad is the minimum wall-clock duration the send step
	// waits before returning regardless of whether the supplied email
	// matched the subject's bound address. The pad closes the user-
	// enumeration timing channel: the matched and unmatched
	// branches both return after the same floor so an attacker cannot
	// infer registration state from the response time. A zero value
	// falls back to the library's default (currently 750 ms — long
	// enough to swallow a typical SMTP submission round trip without
	// inflating happy-path latency); a negative value disables the
	// pad entirely (intended for tests only — production deployments
	// MUST keep the pad on).
	SendLatencyPad time.Duration
}

// Begin implements [Step]. The built-in Step is a configuration
// descriptor; direct dispatch returns [errStepBuiltinNotCompiled]
// because the underlying primitive (TOTP codec, passkey verifier, …)
// is constructed only inside the [LoginFlow] compile path. Wrap your
// own [Authenticator] in [ExternalStep] for direct dispatch.
func (StepEmailOTP) Begin(_ context.Context, _ BeginInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Continue implements [Step]. See the matching Begin for the
// errStepBuiltinNotCompiled rationale.
func (StepEmailOTP) Continue(_ context.Context, _ ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Kind implements [Step]. Returns [StepKindEmailOTP].
func (StepEmailOTP) Kind() StepKind { return StepKindEmailOTP }

// StepCaptcha is the built-in challenge [Step] that asks the user to
// solve an upstream provider's captcha (Cloudflare Turnstile, Google
// reCAPTCHA, hCaptcha, ...). The factor is most often attached
// through [RuleAfterFailedAttempts] to gate retry storms.
type StepCaptcha struct {
	// Verifier is the upstream captcha-token verifier. MUST be
	// non-nil; the orchestrator rejects a flow with a nil Verifier at
	// construction time.
	Verifier CaptchaVerifier
}

// Begin implements [Step]. The built-in Step is a configuration
// descriptor; direct dispatch returns [errStepBuiltinNotCompiled]
// because the underlying primitive (TOTP codec, passkey verifier, …)
// is constructed only inside the [LoginFlow] compile path. Wrap your
// own [Authenticator] in [ExternalStep] for direct dispatch.
func (StepCaptcha) Begin(_ context.Context, _ BeginInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Continue implements [Step]. See the matching Begin for the
// errStepBuiltinNotCompiled rationale.
func (StepCaptcha) Continue(_ context.Context, _ ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Kind implements [Step]. Returns [StepKindCaptcha].
func (StepCaptcha) Kind() StepKind { return StepKindCaptcha }

// StepRecoveryCode is the built-in fallback [Step] that consumes one
// of the user's pre-issued recovery codes. The factor is typically
// surfaced when a stronger second factor (TOTP, passkey) is
// unavailable.
type StepRecoveryCode struct {
	// Store is the recovery-batch store. MUST be non-nil.
	Store store.RecoveryStore
}

// Begin implements [Step]. The built-in Step is a configuration
// descriptor; direct dispatch returns [errStepBuiltinNotCompiled]
// because the underlying primitive (TOTP codec, passkey verifier, …)
// is constructed only inside the [LoginFlow] compile path. Wrap your
// own [Authenticator] in [ExternalStep] for direct dispatch.
func (StepRecoveryCode) Begin(_ context.Context, _ BeginInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Continue implements [Step]. See the matching Begin for the
// errStepBuiltinNotCompiled rationale.
func (StepRecoveryCode) Continue(_ context.Context, _ ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Kind implements [Step]. Returns [StepKindRecoveryCode].
func (StepRecoveryCode) Kind() StepKind { return StepKindRecoveryCode }

// ExternalStep adapts an existing [Authenticator] into a [Step] so an
// embedder's hardware-factor / proprietary-WebAuthn implementation
// composes inside a [LoginFlow] without rewriting it as a built-in
// Step. Begin / Continue forward verbatim — the wrapper adds nothing
// and strips nothing. The wrapped Authenticator's Type, AAL, AMR, and
// Prompts surface unchanged through the orchestrator's audit and
// aggregate pipeline.
//
// KindLabel returns the embedder-supplied [StepKind] so the
// orchestrator's completed-step deduplication (CompletedStepKinds in
// [LoginContext.CompletedSteps]) keeps a unique discriminator per
// step. KindLabel MUST satisfy [StepKind.IsUserDefined] (a dotted
// prefix matching the org identifier, e.g. "myorg.hardware_token") so
// it cannot collide with the built-in identifiers; the [LoginFlow]
// compiler rejects bare or built-in labels at construction time.
//
// ExternalStep is the recommended seam for embedders who already
// implement [Authenticator] for an existing factor. Adopting it
// preserves their verifier code while allowing them to express
// step-up policies through [Rule] and [Decider].
//
// An ExternalStep authenticator may implement [EnrollmentChecker]; a
// [StepOneOf] then offers it only to subjects it reports enrolled.
// Without it the step counts as enrolled for every subject.
type ExternalStep struct {
	// Authenticator is the embedder-supplied factor implementation.
	// MUST be non-nil; the [LoginFlow] compiler rejects an
	// ExternalStep with a nil Authenticator at construction time.
	Authenticator Authenticator

	// KindLabel is the [StepKind] discriminator the wrapper reports
	// through [Step.Kind]. MUST satisfy [StepKind.IsUserDefined] so
	// the value cannot collide with a built-in [StepKind]. The
	// [LoginFlow] compiler rejects bare or built-in labels at
	// construction time.
	KindLabel StepKind

	// CountFailures puts the step under the cross-factor lockout
	// counter the built-in factors share (see [WithAuthnLockoutStore]):
	// a locked subject is refused before Begin with the same 4xx as a
	// built-in second factor, a Continue that returns [ErrFactorRetry]
	// counts one failure (a retry carrying a re-prompt included), and a
	// Continue that completes resets the count.
	//
	// Leave it false for a factor whose secret cannot be guessed, such
	// as a hardware key, so a user fumbling the device is not locked
	// out. Setting it requires a subject to count against, so [New]
	// rejects it on [LoginFlow.Primary] and inside a StepOneOf placed
	// there. An ExternalStep at Primary — a directory bind, say — has no
	// library lockout; the remote verifier's own policy (a directory's
	// password lockout) is what limits guessing there.
	//
	// Stable since v1.5.
	CountFailures bool
}

// Begin implements [Step] by forwarding verbatim to the wrapped
// [Authenticator.Begin]. The wrapper performs no transformation: the
// returned [interaction.Step] is the embedder's value unchanged.
func (e ExternalStep) Begin(ctx context.Context, in BeginInput) (interaction.Step, error) {
	if nilcheck.IsNil(e.Authenticator) {
		return interaction.Step{}, errExternalStepAuthenticatorNil
	}
	return e.Authenticator.Begin(ctx, in)
}

// Continue implements [Step] by forwarding verbatim to the wrapped
// [Authenticator.Continue]. The wrapper performs no transformation:
// the returned [interaction.Step] is the embedder's value unchanged.
func (e ExternalStep) Continue(ctx context.Context, in ContinueInput) (interaction.Step, error) {
	if nilcheck.IsNil(e.Authenticator) {
		return interaction.Step{}, errExternalStepAuthenticatorNil
	}
	return e.Authenticator.Continue(ctx, in)
}

// Kind implements [Step]. Returns the embedder-supplied [KindLabel]
// verbatim; the wrapper does not derive a label from the wrapped
// [Authenticator.Type] because the same Authenticator may legitimately
// participate in a flow under different orchestration kinds (e.g.,
// "myorg.totp_first" and "myorg.totp_step_up" reusing one TOTP
// implementation).
func (e ExternalStep) Kind() StepKind { return e.KindLabel }

// StepOneOf is a [Step] the user completes with exactly one of Steps:
// "one of the second factors this user has registered". How it runs
// depends on its position:
//
//   - In a [Rule], the subject is known, so only the steps the subject
//     is enrolled in are candidates. Two or more are offered through the
//     factor-choice prompt ([interaction.PromptTypeChooseFactor], answered
//     under [interaction.FactorChoiceField]); one is begun directly; none
//     follows IfNoneEnrolled.
//   - As [LoginFlow.Primary] no subject is known yet, so every step is
//     offered without an enrollment check. Each must be able to stand
//     first: [PrimaryPassword], [PrimaryPasskey] with
//     RequireUserVerification, or [ExternalStep] without CountFailures.
//     IfNoneEnrolled must stay [UnenrolledDeny] there.
//
// A choice outside the offered kinds is refused like a stale state_ref.
// Once a factor is chosen the attempt stays on it; restarting the login
// offers the choice again. On completion both the chosen step's kind and
// the StepOneOf's kind are recorded in [LoginContext.CompletedSteps], so
// another rule naming the same step does not run it twice.
//
// Enrollment is read through [EnrollmentChecker]: the built-in second
// factors report it from their stores, an [ExternalStep] whose
// authenticator implements it reports its own, and any other step counts
// as enrolled. A check that fails ends the attempt rather than guessing.
//
// On a reused session the step counts as done when the session's amr
// shows any of its steps ran; see [LoginContext.CompletedSteps]. A step
// skipped under [UnenrolledSkip] leaves no trace in the session, so the
// next authorization checks enrollment again, and a subject still
// enrolled in none of the steps is not stopped by it, prompt=none
// included.
//
// [New] rejects an empty Steps, a nil element, a nested StepOneOf, a
// [StepCaptcha] element, a kind used twice anywhere in the flow, and an
// IfNoneEnrolled outside the declared values.
//
// Stable since v1.5.
type StepOneOf struct {
	// Steps are the alternatives, in display order. MUST be non-empty.
	Steps []Step

	// IfNoneEnrolled decides what happens when the subject is enrolled
	// in none of Steps. The zero value is [UnenrolledDeny].
	IfNoneEnrolled UnenrolledPolicy
}

// Begin implements [Step]. StepOneOf is a configuration descriptor the
// [LoginFlow] compiler resolves; direct dispatch returns
// [errStepBuiltinNotCompiled].
func (StepOneOf) Begin(_ context.Context, _ BeginInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Continue implements [Step]. See [StepOneOf.Begin].
func (StepOneOf) Continue(_ context.Context, _ ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, errStepBuiltinNotCompiled
}

// Kind implements [Step]. Returns "one_of(" followed by the kinds of
// Steps sorted and joined with ",", then ")" — "one_of(passkey,totp)" —
// so the value does not depend on display order.
func (s StepOneOf) Kind() StepKind {
	kinds := make([]string, 0, len(s.Steps))
	for _, step := range s.Steps {
		if nilcheck.IsNil(step) {
			kinds = append(kinds, "")
			continue
		}
		kinds = append(kinds, string(step.Kind()))
	}
	slices.Sort(kinds)
	return StepKind("one_of(" + strings.Join(kinds, ",") + ")")
}

// UnenrolledPolicy is what a [StepOneOf] does when the subject is
// enrolled in none of its steps.
//
// Stable since v1.5.
type UnenrolledPolicy = authn.UnenrolledPolicy

const (
	// UnenrolledDeny ends the attempt with a 4xx. It is the zero value,
	// so a step a deployment declared is never silently left out.
	//
	// Stable since v1.5.
	UnenrolledDeny = authn.UnenrolledDeny

	// UnenrolledSkip passes over the step without completing it: the
	// login continues at the level the other steps reach, and the step
	// adds no amr. The skip is reported as the audit event
	// [AuditStepBeginFailed] with reason "not_enrolled_skipped".
	//
	// Stable since v1.5.
	UnenrolledSkip = authn.UnenrolledSkip
)

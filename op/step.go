package op

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

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
// composes. The interface mirrors [Authenticator]'s Begin / Continue
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
// The library accepts password hashes in PHC argon2id encoding
// (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`). Embedders with
// legacy encodings (bcrypt, scrypt, custom) wrap their own
// [Authenticator] in [ExternalStep] until a hash-migration surface
// lands; v0.x intentionally omits it so the verifier path stays
// branch-free and the library never inspects unfamiliar encodings.
type PrimaryPassword struct {
	// Store is the user-account store the password is verified
	// against. MUST be non-nil; the orchestrator rejects a flow with
	// a nil Store at construction time.
	Store store.UserPasswordStore
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

// PrimaryPasskey is the built-in primary-credential [Step] backed by a
// [store.PasskeyStore]. The factor performs a WebAuthn assertion as
// the first authentication step; a successful assertion binds the
// subject without requiring a prior password entry.
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
	// loop on the "suspicious activity detected" surface (H-E5).
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
	// self-asserted and could name any model. Registrations whose
	// attestation does not vouch for the model — self-attested or
	// unattested — are refused rather than matched against the list.
	// Expect a user-agent attestation prompt on registration, and
	// leave the field empty if that disclosure is not wanted.
	AAGUIDAllowlist []string

	// AAGUIDReCheckOnAssertion enables M-AUTHN-2: the verifier
	// re-checks the matched credential's AAGUID against
	// [AAGUIDAllowlist] at assertion time so an embedder that
	// narrows the allowlist after registration can revoke
	// credentials whose authenticator model has fallen out of
	// policy. The default (false) preserves the v0.x posture where
	// AAGUID was enforced only at registration.
	AAGUIDReCheckOnAssertion bool
}

// PasskeyCloneDetectionHandler is the embedder hook
// [PrimaryPasskey.CloneDetectionHandler] uses to receive clone-warning
// signals (H-E5). Implementations decide the policy: disable the
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
	// enumeration timing channel (H-E3): the matched and unmatched
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
}

// Begin implements [Step] by forwarding verbatim to the wrapped
// [Authenticator.Begin]. The wrapper performs no transformation: the
// returned [interaction.Step] is the embedder's value unchanged.
func (e ExternalStep) Begin(ctx context.Context, in BeginInput) (interaction.Step, error) {
	if isNilLike(e.Authenticator) {
		return interaction.Step{}, errors.New("op: ExternalStep.Authenticator is nil")
	}
	return e.Authenticator.Begin(ctx, in)
}

// Continue implements [Step] by forwarding verbatim to the wrapped
// [Authenticator.Continue]. The wrapper performs no transformation:
// the returned [interaction.Step] is the embedder's value unchanged.
func (e ExternalStep) Continue(ctx context.Context, in ContinueInput) (interaction.Step, error) {
	if isNilLike(e.Authenticator) {
		return interaction.Step{}, errors.New("op: ExternalStep.Authenticator is nil")
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

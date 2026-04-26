package op

import "time"

// PromptData is the sealed interface implemented by every concrete
// prompt-data type the library exposes. The set is closed by design
// (docs/plans/002-product-design.md §E.2): the orchestrator must be
// able to enumerate which fields can leak to the SPA, and an open
// `map[string]any` escape hatch would forbid that audit. New
// PromptData shapes ship with the library; user-extension factors and
// interactions consume one of the existing shapes (most often a
// [FieldSpec]-driven Inputs slice on a built-in PromptData) or, when
// they truly need new state, contribute a typed shape upstream.
//
// Sealing pattern: the interface declares an unexported
// isPromptData() method that only types in this package can satisfy.
// The following will not compile in user code because the method is
// unexported:
//
//	type ForeignPromptData struct{}
//	func (ForeignPromptData) isPromptData() {} // cannot — method is unexported in op
//	var _ op.PromptData = ForeignPromptData{}  // compile error
type PromptData interface {
	isPromptData()
}

// PasswordPromptData backs Prompt.Type "auth.password".
type PasswordPromptData struct {
	// UsernameHint is the login_hint passthrough; "" when not
	// provided. The SPA pre-fills the username field from it.
	UsernameHint string
}

func (PasswordPromptData) isPromptData() {}

// TOTPPromptData backs Prompt.Type "auth.totp".
type TOTPPromptData struct {
	// AttemptsRemaining is the number of failed submissions left
	// before the orchestrator locks the factor for this attempt.
	AttemptsRemaining int
}

func (TOTPPromptData) isPromptData() {}

// EmailOTPSendPromptData backs Prompt.Type "auth.email_otp.send".
// The struct carries no public fields; the email address is collected
// through [Prompt.Inputs] so the SPA renders an opaque text field.
type EmailOTPSendPromptData struct{}

func (EmailOTPSendPromptData) isPromptData() {}

// EmailOTPVerifyPromptData backs Prompt.Type "auth.email_otp.verify".
type EmailOTPVerifyPromptData struct {
	// MaskedEmail is the destination address with privacy-preserving
	// masking applied (e.g., "a***@e***"). The full address never
	// leaves the orchestrator.
	MaskedEmail string

	// ExpiresAt is the wall-clock time at which the issued code
	// stops being acceptable. The SPA renders a countdown.
	ExpiresAt time.Time
}

func (EmailOTPVerifyPromptData) isPromptData() {}

// PasskeyPromptData backs Prompt.Type "auth.passkey".
//
// Challenge and AllowCredentials must be exposed to the SPA verbatim
// because WebAuthn (§E.4) consumes them in the browser. The orchestrator
// guarantees Challenge is freshly generated per attempt with at least
// 256 bits of crypto/rand entropy, which is what makes verbatim
// exposure safe.
type PasskeyPromptData struct {
	// Challenge is the WebAuthn challenge bytes. Each authorize
	// attempt MUST receive an independent value.
	Challenge []byte

	// AllowCredentials is the WebAuthn allowCredentials list. Empty
	// means "discoverable credentials": the browser will choose a
	// resident credential without a username hint.
	AllowCredentials []PasskeyCredentialDescriptor
}

func (PasskeyPromptData) isPromptData() {}

// PasskeyCredentialDescriptor mirrors the WebAuthn
// PublicKeyCredentialDescriptor structure exposed to navigator.credentials.
//
// The shape is dictated by the WebAuthn Level 3 specification and is
// therefore copied verbatim from the browser API: any divergence would
// force the SPA into a translation step the orchestrator already does.
type PasskeyCredentialDescriptor struct {
	// ID is the credential identifier as raw bytes.
	ID []byte

	// Type is the WebAuthn credential type. Currently always
	// "public-key"; the WebAuthn spec keeps the field for forward
	// compatibility with future credential kinds.
	Type string

	// Transports lists the WebAuthn transports the browser may use
	// for this credential ("usb", "nfc", "ble", "internal", "hybrid").
	Transports []string
}

// RecoveryCodePromptData backs Prompt.Type "auth.recovery_code".
type RecoveryCodePromptData struct {
	// AttemptsRemaining is the number of failed submissions left
	// before the orchestrator locks the factor for this attempt.
	AttemptsRemaining int
}

func (RecoveryCodePromptData) isPromptData() {}

// CaptchaPromptData backs Prompt.Type "captcha". The orchestrator
// emits this prompt when [RiskAssessor] or the brute-force counter
// require human verification (§M.6.1).
type CaptchaPromptData struct {
	// Provider is the upstream captcha service identifier.
	// Stable values: "turnstile", "hcaptcha", "recaptcha_v3".
	Provider string

	// SiteKey is the public site key registered with the upstream
	// provider. SPA passes it to the provider's client SDK.
	SiteKey string
}

func (CaptchaPromptData) isPromptData() {}

// ConsentScopePromptData backs Prompt.Type "consent.scope". The shape
// reuses [Scope] from §A.5 so the SPA renders the same metadata that
// flows through discovery and account management.
type ConsentScopePromptData struct {
	// Scopes is the list of scopes the user is being asked to grant.
	// Order matches the orchestrator's display order.
	Scopes []Scope
}

func (ConsentScopePromptData) isPromptData() {}

// FieldKind enumerates the input kinds a [FieldSpec] may declare.
// The set is intentionally small: the orchestrator validates length /
// charset / count limits per kind, and adding a new kind is a v1.x
// extension rather than an embedder concern.
type FieldKind int

// FieldKind values. The mapping to HTML <input type="..."> is the
// SPA's responsibility; the orchestrator enforces only the server-
// side constraints.
const (
	// FieldText is a free-form short text field (login hints,
	// usernames, recovery code letters).
	FieldText FieldKind = iota

	// FieldPassword is a secret-bearing field. The orchestrator
	// strips it from any audit log automatically.
	FieldPassword

	// FieldOTPCode is a numeric one-time code (TOTP, email OTP).
	FieldOTPCode

	// FieldEmail is an email address.
	FieldEmail

	// FieldHidden is a server-rendered field returned verbatim by
	// the SPA (state continuation, CSRF token).
	FieldHidden
)

// FieldSpec describes a form input the SPA should render. Validation
// constraints are declarative; the orchestrator enforces length /
// charset / count limits so the SPA cannot bypass them by handing the
// field to a custom widget.
type FieldSpec struct {
	// Name is the form key the SPA submits in [FormSubmission.Values].
	Name string

	// Kind selects the server-side validation profile. See
	// [FieldKind].
	Kind FieldKind

	// Label is the i18n key the SPA resolves through its locale
	// table. The library does not interpret the value beyond echoing
	// it.
	Label string

	// MaxLen is the maximum byte length the orchestrator accepts
	// for this field. Zero means "use the FieldKind default".
	MaxLen int

	// MinLen is the minimum byte length the orchestrator accepts
	// for this field. Zero means "no minimum".
	MinLen int

	// Required marks fields the SPA must include in its submission.
	Required bool

	// Pattern is an optional regex the orchestrator validates the
	// value against before passing it to [Authenticator.Continue].
	// Empty means "no pattern check beyond Kind validation".
	Pattern string
}

// Prompt is the unit of UI an [Authenticator] or [Interaction]
// returns. The SPA reads Prompt verbatim; the [PromptData] type
// projection determines which concrete fields are safe to expose.
//
// Prompt.Type follows the namespace rules in §E.2.3:
//
//   - "auth.*"        — Authenticator-emitted prompts ("auth.password",
//     "auth.totp", "auth.email_otp.send", "auth.email_otp.verify",
//     "auth.passkey", "auth.recovery_code", "auth.<myorg>.<factor>.*").
//   - "consent.*"     — consent screens ("consent.scope").
//   - "captcha"       — bot-detection prompt (§M.6.1).
//   - "interaction.*" — orchestrator-driven non-authn prompts
//     (select_account etc.).
//   - "<myorg>.*"     — user-extension prompts. The first dotted token
//     MUST be the org identifier so library-reserved names do not
//     collide.
//
// The OIDC `prompt` request parameter ("none" / "login" / "consent" /
// "select_account") lives in a different namespace; the prefix rule
// keeps the two from colliding when a custom factor is added.
type Prompt struct {
	// Type is the prompt identifier. See the namespace rules above.
	Type string

	// Data is the typed payload for this prompt. The concrete type
	// is fixed by Prompt.Type per §E.2 schema.
	Data PromptData

	// Inputs is the form fields the SPA renders. Empty means the
	// prompt is informational (e.g., a captcha that completes via
	// the upstream JS SDK without an explicit form submission).
	Inputs []FieldSpec

	// StateRef is an opaque continuation token the SPA echoes back
	// in the next [FormSubmission]. The orchestrator binds it to:
	//
	//   - the interaction uid (cross-uid replay rejected),
	//   - the [Authenticator] / [Interaction] instance (cross-factor
	//     reuse rejected),
	//   - a short TTL (default 10 minutes; expiry restarts the
	//     factor),
	//   - single-use semantics (a successful Continue invalidates
	//     it).
	//
	// StateRef MUST NOT carry plaintext secrets (OTP codes, TOTP
	// shared secrets, recovery codes, email OTP codes) — the rule
	// applies even when the value is HMAC-signed. See §E.2.1 for
	// the security requirements.
	StateRef string
}

// Step is the discriminated union an [Authenticator] / [Interaction]
// returns from Begin / Continue. Exactly one of Prompt or Result is
// populated; an empty Step is invalid and the orchestrator rejects it.
type Step struct {
	// Prompt, when non-nil, instructs the orchestrator to render
	// another screen and await the SPA's submission.
	Prompt *Prompt

	// Result, when non-nil, signals the factor (or interaction) is
	// complete.
	Result *Result
}

// Result reports a successful factor or interaction completion. For
// [Interaction], Subject is the empty string because the subject is
// already bound by the time the interaction runs.
type Result struct {
	// Subject is the OP-internal identifier the factor authenticated.
	// Empty for [Interaction] returns.
	Subject string

	// AuthTime is the wall-clock time at which the factor confirmed
	// the user. Implementations read it from [BeginInput.AuthTime]
	// or the orchestrator [Clock]; direct [time.Now] calls are
	// forbidden by depguard.
	AuthTime time.Time
}

// FormSubmission is the SPA's reply to a [Prompt]. The orchestrator
// validates Values against [FieldSpec] before dispatching to
// [Authenticator.Continue]; in particular the orchestrator caps the
// total Values size, the per-field byte length, and the field count
// to prevent denial-of-service through oversized submissions.
type FormSubmission struct {
	// StateRef is the [Prompt.StateRef] from the prompt that
	// produced this submission. The orchestrator validates it
	// matches the active factor's continuation token.
	StateRef string

	// Values are the SPA-supplied form values keyed by
	// [FieldSpec.Name]. The orchestrator enforces size limits;
	// callers MUST treat the map as read-only.
	Values map[string]string
}

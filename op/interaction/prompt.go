package interaction

import "time"

// PromptData is the sealed interface implemented by every concrete
// prompt-data type the library exposes. The set is closed by design
// : the orchestrator must be
// able to enumerate which fields can leak to the SPA, and an open
// `map[string]any` escape hatch would forbid that audit. New
// PromptData shapes ship with the library; user-extension factors and
// interactions consume one of the existing shapes (most often a
// [FieldSpec]-driven Inputs slice on a built-in PromptData) or, when
// they truly need new state, contribute a typed shape upstream.
// Sealing pattern: the interface declares an unexported
// isPromptData method that only types in this package can satisfy.
// The following will not compile in user code because the method is
// unexported:
//
//	type ForeignPromptData struct{}
//	func (ForeignPromptData) isPromptData() {} // cannot — method is unexported in interaction
//	var _ interaction.PromptData = ForeignPromptData{}  // compile error
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

// ConsentScope is the slim view of an OAuth scope the consent screen
// renders. The struct is intentionally a flat copy of the §A.5
// scope-catalog entry: keeping it in [interaction] avoids an import
// cycle through [op.Scope] (the catalog type) while preserving the
// fields the SPA needs to render a consent dialogue.
type ConsentScope struct {
	// Name is the scope identifier (e.g. "openid", "profile").
	Name string

	// Description is the human-readable summary the SPA shows to
	// the user. The library does not interpret the value beyond
	// echoing it; localisation is the embedder's responsibility.
	Description string

	// Required reports whether the scope cannot be deselected by
	// the user (typically "openid" itself or scopes the client
	// declared as required at registration).
	Required bool
}

// ConsentScopePromptData backs Prompt.Type "consent.scope". The
// shape mirrors §A.5 of the product design — the SPA renders one
// row per [ConsentScope] in display order.
type ConsentScopePromptData struct {
	// Scopes is the list of scopes the user is being asked to grant.
	// Order matches the orchestrator's display order.
	Scopes []ConsentScope
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
	// value against before passing it to [op.Authenticator.Continue].
	// Empty means "no pattern check beyond Kind validation".
	Pattern string
}

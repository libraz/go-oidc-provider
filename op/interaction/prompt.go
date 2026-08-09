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
// because WebAuthn consumes them in the browser. The orchestrator
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
// require human verification.
type CaptchaPromptData struct {
	// Provider is the upstream captcha service identifier.
	// Stable values: "turnstile", "hcaptcha", "recaptcha_v3".
	Provider string

	// SiteKey is the public site key registered with the upstream
	// provider. SPA passes it to the provider's client SDK.
	SiteKey string
}

func (CaptchaPromptData) isPromptData() {}

// ClientView is the read-only projection of the requesting client
// the consent template surface receives. It exposes only the fields a
// consent or chooser screen needs to render a recognisable
// affordance, and intentionally omits every secret-bearing or
// otherwise unrelated field of the underlying registration record:
//
//   - client_secret / hashed secret — never exposed
//   - JWKS (raw keys / jwks_uri) — never exposed
//   - contacts / sector_identifier_uri — never exposed
//   - token_endpoint_auth_method, response_types, grant_types,
//     scopes, redirect_uris — irrelevant to consent rendering
//
// Adding a field here widens the template trust boundary: whatever is
// added becomes readable by every consent template an embedder ships,
// including ones rendering attacker-influenced client metadata. Treat
// it as a security decision, not a convenience one.
type ClientView struct {
	// ClientID is the registered client_id (RFC 7591 §2).
	ClientID string

	// Name is the human-friendly label (RFC 7591 client_name). May
	// be empty; templates fall back to ClientID in that case.
	Name string

	// LogoURL is the RFC 7591 logo_uri. May be empty.
	LogoURL string

	// ClientURI is the RFC 7591 client_uri (homepage). May be empty.
	ClientURI string

	// PolicyURI is the RFC 7591 policy_uri (privacy policy). May be
	// empty.
	PolicyURI string

	// TosURI is the RFC 7591 tos_uri (terms of service). May be
	// empty.
	TosURI string
}

// ConsentScope is the slim view of an OAuth scope the consent screen
// renders. The struct is intentionally a flat copy of the
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

// ConsentScopePromptData backs Prompt.Type "consent.scope". The SPA
// renders one row per [ConsentScope] in display order.
//
// The serialised payload carries the client projection alongside the
// scope rows: the six [ClientView] fields appear nested under
// "Client". Embedders pinning the JSON envelope through golden tests
// must cover them as well as the scope list.
type ConsentScopePromptData struct {
	// Scopes is the list of scopes the user is being asked to grant.
	// Order matches the orchestrator's display order.
	Scopes []ConsentScope

	// Client is the read-only projection of the requesting client.
	// The built-in consent template overlay reads this field; SPAs
	// may also surface the client_name without a separate discovery
	// call.
	Client ClientView
}

func (ConsentScopePromptData) isPromptData() {}

// ConsentTemplateData is the data context [TemplateOverlayDriver]
// passes to ConsentTemplate.Execute. Templates reference fields
// via the standard [text/template] dot-notation, e.g.
// {{.Client.Name}} or {{range .Scopes}}{{.Name}}{{end}}.
type ConsentTemplateData struct {
	// Client is the projection of the requesting client_id.
	Client ClientView

	// Scopes is the list of scopes the user is being asked to grant.
	// Order matches the orchestrator's display order.
	Scopes []ConsentScope

	// StateRef is the orchestrator's interaction state token. The
	// template MUST echo it as a hidden form field so the POST
	// round-trips through the same /oidc/interaction/{uid} path.
	StateRef string

	// CSRFToken is the per-request CSRF token. The template MUST
	// echo it as a hidden form field; the orchestrator rejects
	// submissions whose token does not match.
	CSRFToken string

	// ApprovedScopesField is the form field name the SPA submits
	// the approved scopes under. Always equal to
	// [ConsentApprovedScopesField] ("approved_scopes"); exposed as a
	// field so templates do not hard-code the literal.
	ApprovedScopesField string

	// SubmitMethod is the HTTP method the form must POST with.
	// Always "POST".
	SubmitMethod string

	// SubmitAction is the URL the form must POST to. The
	// orchestrator computes it relative to the current
	// /oidc/interaction/{uid} request.
	SubmitAction string
}

// ChooserAccount is a single row in the account chooser screen.
// The struct intentionally exposes only the fields a chooser UI
// can render without leaking session-internal state: the SessionID
// is opaque to the SPA and round-trips through [FormSubmission]
// verbatim, while Subject / DisplayName / AuthTime are the
// read-only labels the user picks among.
type ChooserAccount struct {
	// SessionID is the opaque identifier the SPA echoes back in
	// the submission's "session_id" field. Treat as a write-once
	// token: the orchestrator validates it belongs to the active
	// chooser group before honouring the switch.
	SessionID string

	// Subject is the OP-internal subject identifier for this
	// account row. The SPA may render it directly (e.g.,
	// "user_017fa3...") or use it to call /userinfo for a
	// richer display.
	Subject string

	// DisplayName is the human-friendly label the chooser screen
	// shows. Empty when no display name is available; SPAs fall
	// back to Subject in that case.
	DisplayName string

	// AuthTime is when the account last authenticated. SPAs
	// typically render it as a relative timestamp ("2 hours ago").
	AuthTime time.Time
}

// ChooserPromptData backs Prompt.Type "interaction.chooser". The
// SPA renders one row per [ChooserAccount] and POSTs back the
// chosen [ChooserAccount.SessionID] in the submission's
// "session_id" form field.
type ChooserPromptData struct {
	// Accounts is the live chooser-group membership in
	// orchestrator-defined display order (most-recently-used
	// first). An empty slice indicates no live accounts; the
	// chooser screen typically renders an "add account" CTA
	// only.
	Accounts []ChooserAccount

	// AddAccountURL is the URL the SPA navigates to when the user
	// clicks "Add another account". Typically the same /authorize
	// request with prompt=login appended; populated by the
	// orchestrator at render time.
	AddAccountURL string
}

func (ChooserPromptData) isPromptData() {}

// ChooserTemplateData is the data context [TemplateOverlayDriver]
// passes to ChooserTemplate.Execute. Templates reference fields via
// the standard [text/template] dot-notation, e.g.
// {{range .Accounts}}{{.Subject}}{{end}}.
type ChooserTemplateData struct {
	// Accounts is the live chooser-group membership in
	// orchestrator-defined display order (most-recently-used
	// first). An empty slice indicates no live accounts; the
	// template typically renders an "add account" CTA only.
	Accounts []ChooserAccount

	// AddAccountURL is the URL the template renders for the
	// "Add another account" link. Typically the same /authorize
	// request with prompt=login appended.
	AddAccountURL string

	// StateRef is the orchestrator's interaction state token. The
	// template MUST echo it as a hidden form field.
	StateRef string

	// CSRFToken is the per-request CSRF token. The template MUST
	// echo it as a hidden form field.
	CSRFToken string

	// SessionIDField is the form field name the SPA submits the
	// chosen session under. Always equal to
	// [ChooserSessionIDField] ("session_id"); exposed as a field so
	// templates do not hard-code the literal.
	SessionIDField string

	// SubmitMethod is the HTTP method the form must POST with.
	// Always "POST".
	SubmitMethod string

	// SubmitAction is the URL the form must POST to.
	SubmitAction string
}

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

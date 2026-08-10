package op

import (
	"html/template"
	"os"
	"strconv"
	"strings"

	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// WithInteractionDriver registers the [interaction.Driver] that bridges
// the OP state machine to the user-facing UI. If unset, the [Provider]
// boots into [interaction.HTMLDriver], a working server-rendered HTML
// login surface — unless [WithSPAUI] is configured, in which case the
// default falls away and the embedder's SPA owns rendering over the JSON
// state endpoints. SSR or framework-specific Drivers replace it.
// Stable since v1.0.
func WithInteractionDriver(d interaction.Driver) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(d) {
			return newConfigurationError("WithInteractionDriver received nil Driver", nil)
		}
		c.interactionD = d
		return nil
	})
}

// WithCookieKeys registers the AES-256-GCM keys used for cookie encryption.
// The first key is the active encryption key; remaining keys are accepted on
// decryption only, supporting graceful rotation. Every key MUST be 32 bytes;
// an empty list is rejected so the misconfiguration surfaces at startup.
// Each call replaces any keys configured by a previous WithCookieKeys
// call. Pass every active and rotated key (single key in the typical
// case) in a single call.
// Stable since v1.0.
func WithCookieKeys(keys ...[]byte) Option {
	return optionFunc(func(c *config) error {
		if len(keys) == 0 {
			return newConfigurationError("WithCookieKeys requires at least one key", nil)
		}
		// Defensive copy so a later mutation of the caller's slice does
		// not silently change the OP's keys at runtime.
		cp := make([][]byte, len(keys))
		for i, k := range keys {
			b := make([]byte, len(k))
			copy(b, k)
			cp[i] = b
		}
		c.cookieKeys = cp
		return nil
	})
}

// WithMFAEncryptionKeys registers the AES-256-GCM keys used to seal
// per-user TOTP shared secrets at rest. The first key is the active
// encryption key; remaining keys are accepted on decryption only,
// supporting graceful rotation. Every key MUST be 32 bytes; an empty
// list is rejected so the misconfiguration surfaces at startup.
//
// Each call replaces any keys configured by a previous
// WithMFAEncryptionKeys call. Pass every active and rotated key (a
// single key in the typical case) in a single call.
//
// The keys back every [StepTOTP] whose own EncryptionKey is empty;
// a per-step EncryptionKey overrides the global value when present
// (more-specific-wins). Retain previous keys until every persisted
// TOTP record has been re-sealed under the active key.
// Stable since v1.0.
func WithMFAEncryptionKeys(keys ...[]byte) Option {
	return optionFunc(func(c *config) error {
		if len(keys) == 0 {
			return newConfigurationError("WithMFAEncryptionKeys requires at least one key", nil)
		}
		for i, k := range keys {
			if len(k) != mfaEncryptionKeyLen {
				return newConfigurationError("WithMFAEncryptionKeys: entry "+strconv.Itoa(i)+" is not 32 bytes", nil)
			}
		}
		// Defensive copy so a later mutation of the caller's slice does
		// not silently change the OP's keys at runtime.
		cp := make([][]byte, len(keys))
		for i, k := range keys {
			b := make([]byte, len(k))
			copy(b, k)
			cp[i] = b
		}
		c.mfaEncryptionKeys = cp
		return nil
	})
}

// mfaEncryptionKeyLen mirrors the AES-256-GCM key length the TOTP
// codec accepts. The constant is duplicated here so option-level
// validation can return a stable [*Error] without instantiating the
// codec.
const mfaEncryptionKeyLen = 32

// WithAuthnLockoutStore wires the cross-factor brute-force counter.
// When a non-nil store is supplied, every built-in second-factor
// [Step] (StepTOTP, StepEmailOTP, StepRecoveryCode) consults the same
// per-subject counter so an attacker pivoting between factors cannot
// double their guess budget. The store backs a rolling 24-hour
// window: a 1-hour lockout at 30 cumulative failures, 24-hour at 90.
//
// Scope — the counter attaches ONLY to the built-in possession/recovery
// factors above. It is deliberately NOT attached to the primary
// credential factor (password / passkey) or to [ExternalStep] custom
// factors: the primary credential's brute-force defence is the
// embedder's user store (which owns the password hash, its own attempt
// throttling, and account-lock policy), and a custom factor's guessing
// budget is owned by whatever the embedder wraps behind [ExternalStep].
// An embedder that wants the primary or a custom factor to share this
// cross-factor counter wraps its authenticator with the factor package's
// own WithLockout helper before registering it.
//
// The attachment is to the [Step], not to the factor. An authenticator
// built directly — [NewEmailOTPAuthenticator] with an
// [EmailOTPConfig] — and registered through [WithAuthenticators] does
// NOT inherit the counter from this option, because the option never
// sees it. Set [EmailOTPConfig.LockoutStore] to the same store to close
// that gap. Leaving it nil is a silent hole rather than an error: the
// factor still enforces its own per-record FailedCount, so it looks
// rate-limited under test while an attacker who has exhausted their
// TOTP budget pivots to email OTP for a fresh one.
//
// Backends MUST implement the versioned atomic-transition contract on
// [store.AuthnLockoutStore.CompareAndSwap]. The library uses that one
// primitive for increments, rolling-window rollover, lock stamping, and
// success reset so none of those paths can overwrite a concurrently
// recorded failure.
//
// Durability follows the backend. The SQL adapter implements
// [store.AuthnLockoutStore] over its own lockout table
// ([sql.Store.AuthnLockouts]), as does the DynamoDB adapter
// ([dynamodb.Store.AuthnLockouts]), so a counter wired to either
// survives a restart and is shared across replicas. The in-memory
// reference ([inmem.Store.AuthnLockouts]) is process-local: it resets
// on restart and gives each replica its own guess budget, which is
// the wrong shape for anything but a single-process demo. An embedder
// on another backend supplies its own implementation.
//
// The default (nil store, option unset) preserves the per-factor
// counters the TOTP and email-OTP authenticators keep on their own,
// each budgeting its own factor; embedders who want defence-in-depth
// against pivot attacks set this option and route the supplied store
// to a backend every replica shares.
//
// At most one store may be registered; a second [WithAuthnLockoutStore]
// call fails [New] with a structured configuration error.
//
// Stable since v1.0.
func WithAuthnLockoutStore(s store.AuthnLockoutStore) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(s) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAuthnLockoutStore received nil AuthnLockoutStore",
			}
		}
		if c.authnLockoutStore != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAuthnLockoutStore may be called at most once",
			}
		}
		c.authnLockoutStore = s
		return nil
	})
}

// WithScope registers metadata for a single OAuth scope. Calling the
// option multiple times accumulates entries; duplicate Name values
// across calls are rejected at [New] construction time.
// Standard OIDC scopes (openid, profile, email, address, phone,
// offline_access) are recognised automatically with built-in defaults
// (Public: true, no UI text). Registering a standard scope through
// [WithScope] overrides the built-in entry — typically to attach
// translations or claim mappings — but registering one with
// Public: false fails [New] so the discovery document never violates
// OpenID Connect Discovery 1.0 §3.
// AllowedClients is enforced at the authorize and token endpoints: a
// non-empty list restricts the scope to the listed client_id values
// and any other client receives invalid_scope per RFC 6749 §5.2.
// Stable since v1.0.
func WithScope(s Scope) Option {
	return optionFunc(func(c *config) error {
		if s.Name == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithScope: Name must not be empty",
			}
		}
		c.scopes = append(c.scopes, s)
		return nil
	})
}

// WithAuthenticators registers one or more [Authenticator] values.
// Order is preserved: the orchestrator presents factors in
// registration order when no [RiskAssessor] overrides the choice.
// Calling WithAuthenticators multiple times appends to the configured
// set; duplicates by [Authenticator.Type] are rejected at [New]
// construction time.
// At least one authenticator is required for an interactive [Provider]
// to mount /authorize. The orchestrator surfaces the empty-set case
// as a construction error at [New] time; this option only stores the
// registered values.
// Experimental: the option name and contract are settled; what MAY
// change in a minor release is per-authenticator semantics, which are
// still accumulating cases from real factor implementations.
func WithAuthenticators(a ...Authenticator) Option {
	return optionFunc(func(c *config) error {
		if len(a) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAuthenticators requires at least one Authenticator",
			}
		}
		for i, item := range a {
			if isNilLike(item) {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithAuthenticators received nil Authenticator at position " + strconv.Itoa(i),
				}
			}
		}
		c.authenticators = append(c.authenticators, a...)
		return nil
	})
}

// WithCaptchaVerifier wires the [CaptchaVerifier] used to validate
// captcha tokens server-side. At most one verifier is permitted; a
// second [WithCaptchaVerifier] call fails [New] with a structured
// configuration error so duplicate registrations surface as
// misconfigurations rather than silently overwriting the earlier
// value.
// Experimental: the verifier contract is settled; the orchestrator
// trigger points around it MAY change in a minor release.
func WithCaptchaVerifier(v CaptchaVerifier) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(v) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCaptchaVerifier received nil CaptchaVerifier",
			}
		}
		if c.captcha != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCaptchaVerifier may be called at most once",
			}
		}
		c.captcha = v
		return nil
	})
}

// WithRiskAssessor wires the [RiskAssessor] consulted at each
// [RiskStage]. At most one assessor is permitted; a second
// [WithRiskAssessor] call fails [New] with a structured configuration
// error.
// Experimental: the assessor contract is settled; the orchestrator
// trigger points around it MAY change in a minor release.
func WithRiskAssessor(a RiskAssessor) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(a) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithRiskAssessor received nil RiskAssessor",
			}
		}
		if c.risk != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithRiskAssessor may be called at most once",
			}
		}
		c.risk = a
		return nil
	})
}

// WithLoginAttemptObserver registers a [LoginAttemptObserver]. Multiple
// observers stack; the orchestrator fans out every [LoginAttempt] to
// each registered observer in registration order. This is the brute-
// force / risk-counter feed; general audit events are emitted by the
// library to slog and observers MUST NOT duplicate them here.
// Experimental: the observer contract is settled; the orchestrator
// emission points around it MAY change in a minor release.
func WithLoginAttemptObserver(o LoginAttemptObserver) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(o) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithLoginAttemptObserver received nil LoginAttemptObserver",
			}
		}
		c.loginObservers = append(c.loginObservers, o)
		return nil
	})
}

// WithInteractions registers non-factor [Interaction] values (T&C,
// KYC, device-trust prompts...). Order is preserved within an
// [InteractionTrigger] bucket; cross-trigger ordering is orchestrator-
// defined. Calling WithInteractions multiple times appends; duplicates
// by [Interaction.Name] are rejected at [New] construction time.
// The library-built-in consent screen is registered automatically by
// the orchestrator; user extensions ship with a unique dotted
// [Interaction.Name] (e.g., "myorg.tos.accept").
// Experimental: the contract is settled; per-interaction semantics MAY
// change in a minor release.
func WithInteractions(i ...Interaction) Option {
	return optionFunc(func(c *config) error {
		if len(i) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithInteractions requires at least one Interaction",
			}
		}
		for idx, item := range i {
			if isNilLike(item) {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithInteractions received nil Interaction at position " + strconv.Itoa(idx),
				}
			}
		}
		c.interactions = append(c.interactions, i...)
		return nil
	})
}

// SPAUI declares the SPA-shell mount point and optional asset root
// the [Provider] should expose so the embedder's React (or framework-
// neutral SPA) frontend can drive the login / consent / RP-Initiated
// Logout flows. The struct is supplied to [WithSPAUI]; the option
// stores it on config and the orchestrator wiring translates
// LoginMount into the shell, JSON state, and asset routes. The scope
// is deliberately limited to login / consent / RP-Initiated Logout:
// front-channel logout and session management iframes are out of
// scope, so [SPAUI] does not carry mounts for those surfaces.
// LoginMount is the only field that affects routing; see the
// deprecation notes on ConsentMount and LogoutMount.
// Experimental: the field set MAY gain optional members in a minor
// release. Embedders SHOULD construct [SPAUI] with named field
// initialisation so future additions remain source-compatible.
type SPAUI struct {
	// LoginMount is the URL path the SPA's login entry HTML lives
	// under (typically "/login"). MUST be non-empty and MUST start
	// with "/"; an empty value rejects [WithSPAUI] at the option
	// site so the misconfiguration surfaces at construction time.
	LoginMount string

	// ConsentMount is the URL path the consent screen renders under.
	//
	// Deprecated: no handler reads this field. The consent ceremony is
	// served through the same LoginMount routes as every other prompt,
	// discriminated by the state envelope's prompt type, whether
	// ConsentMount is set or empty. The value is still validated — when
	// non-empty it MUST start with "/" — but it reserves no route and
	// changes no routing.
	ConsentMount string

	// LogoutMount is the URL path the RP-Initiated Logout confirmation
	// screen renders under.
	//
	// Deprecated: no handler reads this field. The OP renders its
	// built-in logout confirmation whether LogoutMount is set or empty.
	// The value is still validated — when non-empty it MUST start with
	// "/" — but it reserves no route and changes no routing.
	LogoutMount string

	// StaticDir is the on-disk directory the [Provider] serves
	// the SPA's static assets from. Empty means the embedder
	// hosts the assets behind a reverse proxy; when set the path
	// MUST exist at construction time so a typo surfaces at
	// [New] rather than the first request.
	StaticDir string
}

// ConsentUI declares the template the [Provider] uses to render the
// consent screen when the embedder wants to keep the HTML driver but
// override the consent body. Mutually exclusive with [WithSPAUI];
// supplying both fails [New] with a structured configuration error.
// The struct field set is intentionally narrow: the consent ceremony
// has a fixed data model (client metadata + scope list + CSRF token)
// and the embedder supplies an [*template.Template] that consumes it.
// Experimental: the field set MAY gain members in a minor release. A
// Strings field for an i18n bundle is reserved for once the public
// i18n surface stabilises; it is omitted today so embedders are not
// pinned to a placeholder type.
type ConsentUI struct {
	// Template is the [html/template.Template] the consent screen
	// renders. The library passes the canonical consent context
	// (Client, Scopes, CSRFToken) at render time. MUST be non-nil;
	// the option site rejects a nil template so the
	// misconfiguration surfaces at [New].
	Template *template.Template

	// ContentSecurityPolicy is the policy sent with the rendered
	// consent page. Empty keeps the library default, which forbids
	// every subresource: correct for the markup the built-in driver
	// emits, but it silently drops the stylesheet, logo or webfont a
	// branded template loads — the browser blocks them and the OP
	// never sees a failure. Declare the origins the template uses,
	// e.g. "default-src 'none'; style-src 'self'; img-src 'self' data:".
	//
	// [interaction.NormalizeCSP] validates the value at [New] and
	// documents which directives are not the embedder's to relax.
	ContentSecurityPolicy string
}

// ChooserUI declares the template the [Provider] uses to render the
// account chooser screen when prompt=select_account fires for a
// session that already has a chooser group. Composes with [WithSPAUI]
// mode — the chooser template is silently shadowed by the SPA's JSON
// state envelope and [op.New] emits a single structured warning. The
// struct field set is intentionally narrow: the chooser screen has a
// fixed data model (Accounts, AddAccountURL, CSRFToken) and the
// embedder supplies an [*template.Template] that consumes it.
// Experimental: the field set MAY gain members in a minor release — a
// Strings field for an i18n bundle once the public i18n surface
// stabilises.
type ChooserUI struct {
	// Template is the [html/template.Template] the chooser screen
	// renders. The library passes the canonical chooser context
	// (Accounts, AddAccountURL, CSRFToken) at render time. MUST be
	// non-nil; the option site rejects a nil template so the
	// misconfiguration surfaces at [New].
	Template *template.Template

	// ContentSecurityPolicy is the policy sent with the rendered
	// chooser page. It follows the same rules as
	// [ConsentUI.ContentSecurityPolicy] and is declared separately
	// because the two screens are independent templates that need not
	// load from the same origins.
	ContentSecurityPolicy string
}

// WithLoginFlow registers the [LoginFlow] the orchestrator drives.
// The option compiles the flow into an internal runtime structure at
// [New] and routes the authenticator chain through the
// LoginFlow / Rule / Decider evaluation loop.
// Validation:
//   - Primary MUST be non-nil. A flow with a nil Primary is rejected
//     at the option site.
//   - No two [Rule.Then] entries may share a [Step.Kind]; duplicate
//     kinds are rejected so the orchestrator's completed-step
//     deduplication has a unique discriminator per rule.
//   - Decider MAY be nil; the orchestrator treats nil as "always
//     defer to rules".
//   - Repeated [WithLoginFlow] calls are rejected so the
//     misconfiguration surfaces at [New].
//   - WithLoginFlow is mutually exclusive with [WithAuthenticators];
//     combining the two surfaces would silently reorder factors.
//
// Built-in [Step] values (PrimaryPassword, StepTOTP, …) carry
// configuration-time dependencies (TOTP encryption codec, passkey RP
// origin, hash adapter) that are exposed through follow-up options;
// until those land embedders adopt the seam through [ExternalStep],
// which wraps an already-constructed [Authenticator]. Passing a
// built-in Step directly fails [New] with a clear pointer to the
// workaround.
// Experimental: field names and evaluation order MAY change in a
// minor release; see [LoginFlow] for why the seam is not frozen.
func WithLoginFlow(flow LoginFlow) Option {
	return optionFunc(func(c *config) error {
		if c.loginFlowSet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithLoginFlow may be called at most once",
			}
		}
		if isNilLike(flow.Primary) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithLoginFlow: LoginFlow.Primary must not be nil",
			}
		}
		seen := make(map[StepKind]struct{}, len(flow.Rules))
		for i, r := range flow.Rules {
			if isNilLike(r.Then) {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithLoginFlow: Rules[" + strconv.Itoa(i) + "].Then must not be nil",
				}
			}
			k := r.Then.Kind()
			if _, dup := seen[k]; dup {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithLoginFlow: duplicate StepKind " + k.String() + " across Rules",
				}
			}
			seen[k] = struct{}{}
		}
		c.loginFlow = flow
		c.loginFlowSet = true
		return nil
	})
}

// WithSPAUI registers the [SPAUI] mount points the SPA frontend
// hosts. With a SPA shell active the default-driver fallback in
// [config.applyDefaults] short-circuits so the embedder's SPA owns
// rendering; the OP falls back to [interaction.JSONDriver] for the
// /interaction state endpoint. Mutually exclusive with [WithConsentUI];
// supplying both fails [New].
// Validation:
//   - LoginMount MUST be non-empty and MUST start with "/". It is the
//     only mount the router acts on.
//   - ConsentMount and LogoutMount MAY be empty; when set they MUST
//     start with "/". Both are deprecated and affect no route.
//   - StaticDir MAY be empty; when set the directory MUST exist at
//     construction time (an [os.Stat] check) so a typo fails [New]
//     rather than the first request.
func WithSPAUI(ui SPAUI) Option {
	return optionFunc(func(c *config) error {
		if err := checkSPAUIPrecondition(c); err != nil {
			return err
		}
		if err := validateSPAUIMounts(ui); err != nil {
			return err
		}
		if err := validateSPAUIStaticDir(ui.StaticDir); err != nil {
			return err
		}
		c.spaUI = ui
		c.spaUISet = true
		// In SPA mode the SPA owns the chooser surface via the JSON state
		// envelope, so a chooser template configured alongside it is
		// silently ignored. Stash the intent here so applyDefaults can emit
		// a structured warning once the logger is materialised, regardless
		// of the option invocation order.
		if c.chooserUISet {
			c.chooserUIShadowedBySPA = true
		}
		return nil
	})
}

// checkSPAUIPrecondition rejects repeated [WithSPAUI] calls and the
// [WithConsentUI] mutual-exclusion case. Split out so [WithSPAUI]
// stays under the gocognit ceiling now that mount / StaticDir checks
// also live in helpers.
//
// The chooser↔SPA combination is permitted: mode treats the chooser
// HTML template as silently shadowed by the SPA's JSON state
// envelope. [WithSPAUI] / [WithChooserUI] coordinate the
// `chooserUIShadowedBySPA` flag so [config.applyDefaults] can emit a
// single structured warning regardless of option order.
func checkSPAUIPrecondition(c *config) error {
	if c.spaUISet {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithSPAUI may be called at most once",
		}
	}
	if c.consentUISet {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithSPAUI is mutually exclusive with WithConsentUI",
		}
	}
	return nil
}

// validateSPAUIMounts enforces the LoginMount-required and
// "every mount path begins with /" rules. The error message names the
// offending field so an embedder fixes the right line in their boot
// sequence.
func validateSPAUIMounts(ui SPAUI) error {
	if ui.LoginMount == "" {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithSPAUI: LoginMount must not be empty",
		}
	}
	for _, m := range []struct{ name, value string }{
		{"LoginMount", ui.LoginMount},
		{"ConsentMount", ui.ConsentMount},
		{"LogoutMount", ui.LogoutMount},
	} {
		if m.value == "" {
			continue
		}
		if !strings.HasPrefix(m.value, "/") {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithSPAUI: " + m.name + " must start with \"/\"",
			}
		}
	}
	return nil
}

// validateSPAUIStaticDir checks that a non-empty StaticDir refers to
// an accessible directory at construction time. An empty value means
// "let the embedder serve the SPA bundle through their own reverse
// proxy" and is allowed.
func validateSPAUIStaticDir(dir string) error {
	if dir == "" {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithSPAUI: StaticDir " + dir + " not accessible",
			Cause:       err,
		}
	}
	if !info.IsDir() {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithSPAUI: StaticDir " + dir + " is not a directory",
		}
	}
	return nil
}

// WithConsentUI registers the [ConsentUI] template the HTML driver
// uses for the consent screen. Mutually exclusive with [WithSPAUI];
// supplying both fails [New] with a structured configuration error.
// Validation:
//   - Template MUST be non-nil.
//   - ContentSecurityPolicy, when set, MUST pass
//     [interaction.NormalizeCSP].
//   - Repeated [WithConsentUI] calls are rejected.
func WithConsentUI(ui ConsentUI) Option {
	return optionFunc(func(c *config) error {
		if c.consentUISet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithConsentUI may be called at most once",
			}
		}
		if c.spaUISet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithConsentUI is mutually exclusive with WithSPAUI",
			}
		}
		if ui.Template == nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithConsentUI: Template must not be nil",
			}
		}
		policy, err := interaction.NormalizeCSP(ui.ContentSecurityPolicy)
		if err != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithConsentUI: ContentSecurityPolicy rejected",
				Cause:       err,
			}
		}
		ui.ContentSecurityPolicy = policy
		c.consentUI = ui
		c.consentUISet = true
		return nil
	})
}

// WithChooserUI registers the [ChooserUI] template the HTML driver
// uses for the account chooser screen. The option composes with
// [WithSPAUI] mode: when both are configured the chooser template is
// silently shadowed (the SPA's JSON state envelope renders the
// chooser surface) and [op.New] emits a single structured warning.
// The chooser↔consent relationship is unchanged — both can be set
// together, both render through the overlay. Validation:
//   - Template MUST be non-nil.
//   - ContentSecurityPolicy, when set, MUST pass
//     [interaction.NormalizeCSP].
//   - Repeated [WithChooserUI] calls are rejected.
func WithChooserUI(ui ChooserUI) Option {
	return optionFunc(func(c *config) error {
		if c.chooserUISet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithChooserUI may be called at most once",
			}
		}
		if ui.Template == nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithChooserUI: Template must not be nil",
			}
		}
		policy, err := interaction.NormalizeCSP(ui.ContentSecurityPolicy)
		if err != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithChooserUI: ContentSecurityPolicy rejected",
				Cause:       err,
			}
		}
		ui.ContentSecurityPolicy = policy
		c.chooserUI = ui
		c.chooserUISet = true
		// In SPA mode the SPA owns the chooser surface via the JSON state
		// envelope when [WithSPAUI] is also active. Stash the intent for
		// applyDefaults regardless of which option was called first.
		if c.spaUISet {
			c.chooserUIShadowedBySPA = true
		}
		return nil
	})
}

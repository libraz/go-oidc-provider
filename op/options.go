package op

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/proxy"
	"github.com/libraz/go-oidc-provider/internal/redact"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Option configures a [Provider] passed to [New]. Options compose: the order
// in which they appear in the New call determines the order in which they
// are applied. Where two options set the same field, the later one wins.
//
// Implementors of new options should construct an [Option] via the
// unexported optionFunc type below; users of the package do not implement
// the Option interface directly.
type Option interface {
	apply(*config) error
}

type optionFunc func(*config) error

func (f optionFunc) apply(c *config) error { return f(c) }

// config holds the validated configuration of a [Provider]. It is private so
// that callers can only build it through [Option] values, which lets us
// preserve invariants (no zero-value Provider, type-driven enums, etc.).
type config struct {
	issuer        string
	store         store.Store
	clock         Clock
	logger        *slog.Logger
	auditLogger   *slog.Logger
	keyset        Keyset
	defaultLocale Locale
	localeBundles []LocaleBundle
	mountPrefix   string
	endpoints     Endpoints
	grants        []grant.Type
	features      []feature.Flag
	profiles      []profile.Profile
	interactionD  interaction.Driver

	// cookieKeys carries the AES-256-GCM keys used by the Cookie codec.
	// The first entry is the active encryption key; the remainder are
	// rotation slots tried in order on decryption only. Length 32 bytes
	// each; validation runs in [validate].
	cookieKeys [][]byte

	// trustedProxies holds the CIDRs from [WithTrustedProxies]. Empty
	// means "no proxy trusted"; X-Forwarded-* headers are ignored.
	trustedProxies []string

	// corsOrigins holds the explicit cross-origin entries from
	// [WithCORSOrigins]. The full allowlist is the union of these plus
	// every redirect_uri origin registered via the [store.ClientStore].
	corsOrigins []string

	// crossSiteFlow is the §F.3 opt-in for SameSite=None on session
	// cookies. Off by default per the production-grade posture.
	crossSiteFlow bool

	// scopes captures the [Scope] values registered through
	// [WithScope] in the order they were supplied. Order is preserved
	// so a later mutation of the slice does not silently change the
	// registered set, and so applyDefaults can deterministically
	// decide whether to emit a built-in entry for an unregistered
	// standard scope.
	scopes []Scope

	// scopeIndex is the Name → Scope lookup built by [validate]
	// after duplicate detection has run. It is nil before validate
	// returns; consumers MUST go through [config.scopeIndex] only on
	// the post-validate config.
	scopeIndex map[string]Scope

	// dcr carries the [RegistrationOption] supplied through
	// [WithDynamicRegistration]. Nil when the option is absent;
	// non-nil when the feature is configured (defaults populated by
	// [config.applyDefaults]). The library reads dcr to decide
	// whether to mount /register, advertise registration_endpoint in
	// discovery, and accept calls to
	// [Provider.IssueInitialAccessToken].
	dcr *RegistrationOption

	// authenticators carries the [Authenticator] values registered
	// through [WithAuthenticators]. The orchestrator presents factors
	// in this order when [RiskAssessor] does not override the choice.
	// Order is preserved; duplicates by [Authenticator.Type] are
	// rejected at construction time.
	authenticators []Authenticator

	// captcha is the optional [CaptchaVerifier] the orchestrator
	// consults to validate captcha tokens server-side. Nil means
	// "no captcha configured"; at most one verifier may be
	// registered (§M.6.1).
	captcha CaptchaVerifier

	// risk is the optional [RiskAssessor] the orchestrator consults
	// at each [RiskStage]. Nil means "always allow"; at most one
	// assessor may be registered (§M.6.2).
	risk RiskAssessor

	// loginObservers carries the [LoginAttemptObserver] values
	// registered through [WithLoginAttemptObserver]. Multiple
	// observers stack: the orchestrator fans out every
	// [LoginAttempt] to each in registration order (§M.6.3).
	loginObservers []LoginAttemptObserver

	// interactions carries the non-factor [Interaction] values
	// registered through [WithInteractions]. The orchestrator inserts
	// them per [InteractionTrigger]; intra-trigger ordering follows
	// registration order, cross-trigger ordering is orchestrator-
	// defined (§E.9).
	interactions []Interaction

	// backchannelLogoutHTTPClient is the HTTP client the back-channel
	// logout coordinator uses to POST Logout Tokens to RPs. Nil means
	// "use the package default" (a fresh [*http.Client] with the
	// timeout below and a redirect-refusing CheckRedirect, matching
	// the spec posture).
	backchannelLogoutHTTPClient *http.Client

	// backchannelLogoutTimeout is the per-RP request budget. Zero
	// substitutes [backchannel.DefaultTimeout].
	backchannelLogoutTimeout time.Duration
}

// newConfig applies opts in order to a fresh config and returns the result
// or the first option error encountered. After every option has been
// applied, defaults are filled in for fields the caller chose to omit.
func newConfig(opts []Option) (*config, error) {
	c := &config{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt.apply(c); err != nil {
			return nil, err
		}
	}
	c.applyDefaults()
	return c, nil
}

// applyDefaults fills in optional fields with their library defaults.
func (c *config) applyDefaults() {
	if c.clock == nil {
		c.clock = timex.SystemClock
	}
	if c.logger == nil {
		c.logger = slog.New(discardHandler{})
	}
	// auditLogger has no fall-back default: when neither
	// [WithAuditLogger] nor [WithLogger] is set, [effectiveAuditLogger]
	// returns nil and the audit emitter collapses to a no-op. Setting
	// a default here would silently route audit lines into the
	// operational stream — which is the design rationale for keeping
	// the two loggers structurally separate (see 002 §N.1).
	if c.mountPrefix == "" {
		c.mountPrefix = "/oidc"
	}
	defaults := defaultEndpoints()
	c.endpoints = defaults.merge(c.endpoints)
	if c.interactionD == nil {
		c.interactionD = interaction.JSONDriver{}
	}
	if len(c.grants) == 0 {
		c.grants = []grant.Type{grant.AuthorizationCode, grant.RefreshToken}
	}
	c.fillStandardScopes()
	c.applyRegistrationDefaults()
	if c.defaultLocale == "" {
		c.defaultLocale = LocaleEnglish
	}
}

// applyRegistrationDefaults fills in [RegistrationOption] zero-value
// fields with their library defaults. The fill is only performed when
// [WithDynamicRegistration] was invoked; the function is otherwise a
// no-op so that [config.validate] can still distinguish "feature not
// configured" from "feature configured with explicit zero".
func (c *config) applyRegistrationDefaults() {
	if c.dcr == nil {
		return
	}
	if c.dcr.IATTTL == 0 {
		c.dcr.IATTTL = defaultIATTTL
	}
	if c.dcr.IATUses == 0 {
		c.dcr.IATUses = defaultIATUses
	}
	if c.dcr.AllowedGrantTypes == nil {
		c.dcr.AllowedGrantTypes = defaultRegistrationGrantTypes()
	}
	if c.dcr.AllowedResponseTypes == nil {
		c.dcr.AllowedResponseTypes = defaultRegistrationResponseTypes()
	}
}

// fillStandardScopes appends a built-in entry for every OIDC standard
// scope (openid, profile, email, address, phone, offline_access) that
// the caller has not already registered through [WithScope]. The
// built-in entries carry only the Name and Public: true; embedders who
// want translations or icons supply them by calling [WithScope] with a
// matching Name.
func (c *config) fillStandardScopes() {
	registered := make(map[string]struct{}, len(c.scopes))
	for _, s := range c.scopes {
		registered[s.Name] = struct{}{}
	}
	for _, name := range standardScopeNames {
		if _, ok := registered[name]; ok {
			continue
		}
		c.scopes = append(c.scopes, Scope{Name: name, Public: true})
	}
}

// standardScopeNames lists the OIDC standard scope identifiers the
// library always recognises. Order is the canonical OIDC §5.4 listing
// so the discovery document keeps a familiar shape when the embedder
// registers no custom scopes.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var standardScopeNames = []string{
	string(ScopeNameOpenID),
	string(ScopeNameProfile),
	string(ScopeNameEmail),
	string(ScopeNameAddress),
	string(ScopeNamePhone),
	string(ScopeNameOfflineAccess),
}

// isStandardScope reports whether name is one of the OIDC standard
// scope identifiers. Used by [config.validate] to enforce the rule
// that standard scopes cannot be registered with Public: false.
func isStandardScope(name string) bool {
	for _, n := range standardScopeNames {
		if n == name {
			return true
		}
	}
	return false
}

// validate checks that required fields are set and that combinations of
// options are internally consistent. It runs after applyDefaults so that
// "missing required" errors are not masked by a default value.
func (c *config) validate() error {
	if c.issuer == "" {
		return ErrIssuerRequired
	}
	if c.store == nil {
		return ErrStoreRequired
	}
	if len(c.keyset) == 0 {
		return ErrKeysetRequired
	}
	if err := validateKeyset(c.keyset); err != nil {
		return err
	}
	if err := validateCookieKeys(c.cookieKeys); err != nil {
		return err
	}
	if err := validateCookieKeysRequired(c.grants, c.cookieKeys); err != nil {
		return err
	}
	if _, err := proxy.NewTrust(c.trustedProxies); err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithTrustedProxies rejected by parser",
			Cause:       err,
		}
	}
	if _, err := csrf.NewAllowlist(c.corsOrigins); err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithCORSOrigins rejected by parser",
			Cause:       err,
		}
	}
	if err := c.validateScopes(); err != nil {
		return err
	}
	if err := c.validateRegistration(); err != nil {
		return err
	}
	if err := c.validateAuthenticators(); err != nil {
		return err
	}
	if err := c.validateInteractions(); err != nil {
		return err
	}
	if err := c.validateLocales(); err != nil {
		return err
	}
	return nil
}

// validateLocales rejects a [WithDefaultLocale] value that is not
// served by any registered bundle. The seed en / ja bundles are
// always available, so a default of "en" / "ja" never trips the
// check; embedders that override the default to a custom locale
// MUST register the matching bundle through [WithLocale].
func (c *config) validateLocales() error {
	if c.defaultLocale == "" {
		return nil
	}
	for _, b := range c.localeBundles {
		if b.Locale() == c.defaultLocale {
			return nil
		}
	}
	if c.defaultLocale == LocaleEnglish || c.defaultLocale == LocaleJapanese {
		return nil
	}
	return &Error{
		Code:        codeConfiguration,
		Description: "WithDefaultLocale references a locale that is not registered through WithLocale or shipped as a seed bundle",
	}
}

// validateAuthenticators enforces uniqueness of [Authenticator.Type]
// across the registered set. The orchestrator layers further rules on
// top — minimum cardinality, capability checks against the risk
// engine — but the bare uniqueness invariant is owned here so
// duplicate registrations surface at [New] rather than the first
// chain run.
func (c *config) validateAuthenticators() error {
	if len(c.authenticators) == 0 {
		// Zero authenticators is permitted at this layer; the
		// orchestrator surfaces the missing-authenticator
		// construction error when [New] wires the chain runner.
		return nil
	}
	seen := make(map[FactorType]struct{}, len(c.authenticators))
	for _, a := range c.authenticators {
		t := a.Type()
		if _, dup := seen[t]; dup {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAuthenticators: duplicate FactorType " + string(t),
			}
		}
		seen[t] = struct{}{}
	}
	return nil
}

// validateInteractions enforces uniqueness of [Interaction.Name]
// across the registered set. The same rationale as
// [config.validateAuthenticators] applies: surface registration
// mistakes at [New] rather than the first chain run.
func (c *config) validateInteractions() error {
	if len(c.interactions) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(c.interactions))
	for _, ix := range c.interactions {
		name := ix.Name()
		if name == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithInteractions: Interaction.Name must not be empty",
			}
		}
		if _, dup := seen[name]; dup {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithInteractions: duplicate Interaction.Name " + name,
			}
		}
		seen[name] = struct{}{}
	}
	return nil
}

// validateRegistration enforces the cross-cutting invariants between
// [WithDynamicRegistration] and [WithFeature]. The two surfaces MUST
// agree: a non-nil [config.dcr] requires the
// [feature.DynamicRegistration] flag, and the configured store MUST
// expose the IAT and RAT substores. The method also rejects
// [WithDynamicRegistration] without a backing flag (so a caller who
// removed the feature accidentally is told why /register is missing).
func (c *config) validateRegistration() error {
	flagOn := false
	for _, f := range c.features {
		if f == feature.DynamicRegistration {
			flagOn = true
			break
		}
	}
	if c.dcr == nil && !flagOn {
		return nil
	}
	if c.dcr == nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "feature.DynamicRegistration enabled without WithDynamicRegistration",
		}
	}
	if !flagOn {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithDynamicRegistration set without feature.DynamicRegistration enabled",
		}
	}
	if c.store.InitialAccessTokens() == nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "InitialAccessTokens not implemented by store backend",
		}
	}
	if c.store.RegistrationAccessTokens() == nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "RegistrationAccessTokens not implemented by store backend",
		}
	}
	if _, ok := c.store.(store.ClientRegistry); !ok {
		return &Error{
			Code:        codeConfiguration,
			Description: "Store does not implement ClientRegistry; dynamic registration requires write access",
		}
	}
	return nil
}

// validateScopes enforces the [WithScope] invariants and builds
// [config.scopeIndex] for the post-validate config:
//
//   - every registered Scope has a non-empty Name
//   - no two registrations share a Name
//   - no OIDC standard scope is registered with Public: false (the
//     discovery document MUST/SHOULD list them per §3)
//
// The check runs after [config.applyDefaults] so the standard-scope
// fill never produces a duplicate; embedder-registered standard
// scopes always win over the built-in placeholder.
func (c *config) validateScopes() error {
	c.scopeIndex = make(map[string]Scope, len(c.scopes))
	for _, s := range c.scopes {
		if s.Name == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithScope: Name must not be empty",
			}
		}
		if _, dup := c.scopeIndex[s.Name]; dup {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithScope: duplicate scope " + s.Name,
			}
		}
		if isStandardScope(s.Name) && !s.Public {
			return &Error{
				Code:        codeConfiguration,
				Description: "standard OIDC scope " + s.Name + " cannot be registered with Public: false",
			}
		}
		c.scopeIndex[s.Name] = s
	}
	return nil
}

// validateCookieKeys runs the same shape checks as [cookie.NewCodec] but
// without instantiating the codec — startup validation must surface every
// wrong-length key with a stable [*Error] code regardless of order.
func validateCookieKeys(keys [][]byte) error {
	for i, k := range keys {
		if len(k) != cookieKeyLen {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCookieKey/WithCookieKeys: entry " + strconv.Itoa(i) + " is not 32 bytes",
			}
		}
	}
	return nil
}

// cookieKeyLen mirrors the AES-256-GCM key length expected by the cookie
// codec. The value is duplicated here so option-level validation can return
// a stable [*Error] without instantiating the codec.
const cookieKeyLen = 32

// validateCookieKeysRequired enforces the rule that any grant which depends
// on the authorize endpoint setting encrypted cookies (interaction binding,
// session resumption) MUST be paired with at least one cookie key. The
// authorization_code grant is the only one in v0.x that imposes the
// requirement; the rule is centralised here so future grants can opt in by
// adding themselves to the switch.
func validateCookieKeysRequired(grants []grant.Type, keys [][]byte) error {
	if len(keys) > 0 {
		return nil
	}
	for _, g := range grants {
		if g == grant.AuthorizationCode {
			return ErrCookieKeysRequired
		}
	}
	return nil
}

// validateKeyset enforces the v1.0 alg policy: every entry MUST be ECDSA on
// curve P-256 (so the OP can sign ES256). It also rejects empty key IDs
// and duplicates within the same keyset.
func validateKeyset(ks Keyset) error {
	seen := make(map[string]struct{}, len(ks))
	for i, k := range ks {
		if k.KeyID == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "keyset entry " + strconv.Itoa(i) + " is missing KeyID",
			}
		}
		if _, dup := seen[k.KeyID]; dup {
			return &Error{
				Code:        codeConfiguration,
				Description: "duplicate KeyID " + k.KeyID,
			}
		}
		seen[k.KeyID] = struct{}{}
		if k.Signer == nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "keyset entry " + k.KeyID + " has nil Signer",
			}
		}
		pub, ok := k.Signer.Public().(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return &Error{
				Code:        codeConfiguration,
				Description: "keyset entry " + k.KeyID + " is not ECDSA P-256 (ES256 required)",
			}
		}
	}
	return nil
}

// WithIssuer sets the OP issuer URL. The value MUST be an absolute https URL
// with no query or fragment, per OpenID Connect Discovery 1.0 §3. The URL is
// parsed eagerly; malformed values fail [New] rather than the first request.
//
// Stable since v0.1.
func WithIssuer(issuer string) Option {
	return optionFunc(func(c *config) error {
		if issuer == "" {
			return ErrIssuerRequired
		}
		u, err := url.Parse(issuer)
		if err != nil || !u.IsAbs() || u.Scheme != "https" || u.RawQuery != "" || u.Fragment != "" {
			return ErrIssuerInvalid
		}
		c.issuer = issuer
		return nil
	})
}

// WithStore registers the storage backend the [Provider] uses to persist
// authorization codes, refresh tokens, grants, sessions, and other records.
// Callers MUST supply a non-nil [store.Store]; the library does not provide a
// default backend at this layer because the choice of persistence is part of
// the deployment shape rather than the library configuration.
//
// Stable since v0.1.
func WithStore(s store.Store) Option {
	return optionFunc(func(c *config) error {
		if s == nil {
			return ErrStoreRequired
		}
		c.store = s
		return nil
	})
}

// WithKeyset registers the OP signing keys. The first entry is the active
// signer; subsequent entries are kept in JWKS so RPs can verify tokens
// issued under previous keys during a rotation window.
//
// Every entry MUST be ECDSA on curve P-256 (the v1.0 ES256 policy from
// docs/plans/002-product-design.md §J.5 / §K.3). Supplying any other key
// shape causes [New] to fail at construction time.
//
// Stable since v0.1.
func WithKeyset(ks Keyset) Option {
	return optionFunc(func(c *config) error {
		if len(ks) == 0 {
			return ErrKeysetRequired
		}
		c.keyset = ks
		return nil
	})
}

// WithClock injects the wall-clock implementation used for token expiry,
// audit timestamps, and rate-limit windows. If unset, the [Provider] uses a
// real wall clock backed by [time.Now]. Tests SHOULD inject a deterministic
// clock so the whole flow shares the same fake time.
//
// Stable since v0.1.
func WithClock(clock Clock) Option {
	return optionFunc(func(c *config) error {
		c.clock = clock
		return nil
	})
}

// WithLogger injects the [*slog.Logger] the library uses for structured
// diagnostics. If unset, the [Provider] discards every record. Callers
// SHOULD pass a logger backed by their service's slog handler so OP events
// appear in the same stream as the rest of the application.
//
// The supplied logger's handler is wrapped with the library's redaction
// hook (see internal/redact) so attributes named after the canonical
// OAuth/OIDC secrets — access_token, refresh_token, id_token, code,
// code_verifier, client_secret, password, state, nonce, dpop,
// authorization, cookie, set-cookie — are masked before they reach
// the underlying handler. The wrapping is idempotent: passing a
// logger whose handler is already redact-wrapped is a no-op.
//
// Stable since v0.1.
func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *config) error {
		if logger != nil {
			logger = slog.New(redact.WrapHandler(logger.Handler()))
		}
		c.logger = logger
		return nil
	})
}

// effectiveAuditLogger returns the [*slog.Logger] audit events
// should ride on. The dedicated audit logger from [WithAuditLogger]
// wins; otherwise the operational logger from [WithLogger] is used so
// audit records are not silently dropped just because the embedder
// did not split the streams. A nil return collapses the emitter to
// [audit.Discard] — that path is reachable only when neither option
// was supplied.
func (c *config) effectiveAuditLogger() *slog.Logger {
	if c.auditLogger != nil {
		return c.auditLogger
	}
	return c.logger
}

// WithAuditLogger injects the [*slog.Logger] the library routes
// audit events on. Audit records carry the slog attribute
// "audit"="true" so log shippers can split them onto a dedicated
// retention bucket without parsing the [AuditEvent] name; the
// design rationale is in design 002 §N.1.
//
// If unset, the [Provider] uses the operational logger from
// [WithLogger]; if neither is configured, audit records are dropped.
// Embedders SHOULD pass a logger pointed at long-retention storage
// (S3-backed handler, BigQuery sink, ELK index, …) so audit lines
// outlive the operational stream.
//
// The supplied logger's handler is wrapped with the same redaction
// hook as [WithLogger] so a regression that puts a token into an
// [AuditEvent] extras map cannot escape the wire posture.
//
// Stable since v0.1.
func WithAuditLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *config) error {
		if logger != nil {
			logger = slog.New(redact.WrapHandler(logger.Handler()))
		}
		c.auditLogger = logger
		return nil
	})
}

// WithMountPrefix sets the URL prefix under which the [Provider] mounts its
// HTTP endpoints. The default is "/oidc". The discovery document is always
// served under /.well-known regardless of this value (per OpenID Connect
// Discovery 1.0 §4); every other endpoint is routed under prefix.
//
// The supplied prefix MUST start with "/" and MUST NOT end with "/". Empty
// values reject; the empty-prefix case (mounting at root) is supported by
// passing "/" explicitly.
//
// Stable since v0.1.
func WithMountPrefix(prefix string) Option {
	return optionFunc(func(c *config) error {
		if prefix == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithMountPrefix prefix must not be empty (use \"/\" for root)",
			}
		}
		if !strings.HasPrefix(prefix, "/") {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithMountPrefix prefix must start with \"/\"",
			}
		}
		if prefix != "/" && strings.HasSuffix(prefix, "/") {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithMountPrefix prefix must not end with \"/\"",
			}
		}
		c.mountPrefix = prefix
		return nil
	})
}

// WithEndpoints overrides individual endpoint paths. Empty fields in e
// retain the library default; populated fields replace the corresponding
// path. The discovery document reflects every override automatically.
//
// Stable since v0.1.
func WithEndpoints(e Endpoints) Option {
	return optionFunc(func(c *config) error {
		c.endpoints = c.endpoints.merge(e)
		return nil
	})
}

// WithGrants selects the grant_type values the [Provider] accepts at the
// token endpoint. Calling this option replaces the default
// (authorization_code + refresh_token) entirely; pass every grant the
// deployment needs in a single call.
//
// Stable since v0.1.
func WithGrants(grants ...grant.Type) Option {
	return optionFunc(func(c *config) error {
		if len(grants) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithGrants requires at least one grant type",
			}
		}
		seen := make(map[grant.Type]struct{}, len(grants))
		for _, g := range grants {
			if !g.IsValid() {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithGrants received an unknown grant type",
				}
			}
			if _, dup := seen[g]; dup {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithGrants received duplicate grant type " + g.String(),
				}
			}
			seen[g] = struct{}{}
		}
		c.grants = append([]grant.Type(nil), grants...)
		return nil
	})
}

// WithFeature enables an optional protocol extension. The option may be
// repeated; each call adds to the enabled set. Duplicate enables are
// rejected to surface configuration mistakes.
//
// Stable since v0.1.
func WithFeature(f feature.Flag) Option {
	return optionFunc(func(c *config) error {
		if !f.IsValid() {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithFeature received an unknown feature flag",
			}
		}
		for _, existing := range c.features {
			if existing == f {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithFeature received duplicate flag " + f.String(),
				}
			}
		}
		c.features = append(c.features, f)
		return nil
	})
}

// WithProfile activates an industry security profile. Profiles compose
// multiplicatively: enabling FAPI2Baseline implies its underlying features
// and policies. Repeated profiles are rejected.
//
// Stable since v0.1.
func WithProfile(p profile.Profile) Option {
	return optionFunc(func(c *config) error {
		if !p.IsValid() {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithProfile received an unknown profile",
			}
		}
		for _, existing := range c.profiles {
			if existing == p {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithProfile received duplicate profile " + p.String(),
				}
			}
		}
		c.profiles = append(c.profiles, p)
		return nil
	})
}

// WithInteraction registers the [interaction.Driver] that bridges the OP
// state machine to the user-facing UI. If unset, the [Provider] uses
// [interaction.JSONDriver], which speaks JSON over HTTP: every prompt
// is written as a JSON envelope and every submission is decoded from a
// JSON body. SSR or framework-specific Drivers replace it.
//
// Stable since v0.1.
func WithInteraction(d interaction.Driver) Option {
	return optionFunc(func(c *config) error {
		if d == nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithInteraction received nil Driver",
			}
		}
		c.interactionD = d
		return nil
	})
}

// WithCookieKey registers a single AES-256-GCM key (32 bytes) for cookie
// encryption. It is a convenience wrapper over [WithCookieKeys] for the
// common single-key case.
//
// Stable since v0.1.
func WithCookieKey(key []byte) Option {
	return WithCookieKeys(key)
}

// WithCookieKeys registers the AES-256-GCM keys used for cookie encryption.
// The first key is the active encryption key; remaining keys are accepted on
// decryption only, supporting graceful rotation per
// docs/plans/002-product-design.md §F.2. Every key MUST be 32 bytes; an
// empty list is rejected so the misconfiguration surfaces at startup.
//
// Each call replaces any keys configured by a previous WithCookieKeys/
// [WithCookieKey] call. Pass every active and rotated key in a single call.
//
// Stable since v0.1.
func WithCookieKeys(keys ...[]byte) Option {
	return optionFunc(func(c *config) error {
		if len(keys) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCookieKeys requires at least one key",
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
		c.cookieKeys = cp
		return nil
	})
}

// WithTrustedProxies declares the CIDRs from which the [Provider] should
// honour [X-Forwarded-*] headers. When a request arrives from outside these
// ranges the headers are ignored, preventing IP / scheme spoofing
// (docs/plans/002-product-design.md §F.5).
//
// CIDRs may be IPv4 or IPv6; both notations are accepted. Each call
// replaces the previous list — pass every trusted CIDR in a single call.
//
// Stable since v0.1.
func WithTrustedProxies(cidrs ...string) Option {
	return optionFunc(func(c *config) error {
		if len(cidrs) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithTrustedProxies requires at least one CIDR",
			}
		}
		// Validate eagerly so misconfiguration surfaces at New time
		// rather than the first cross-proxy request.
		if _, err := proxy.NewTrust(cidrs); err != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithTrustedProxies CIDR rejected",
				Cause:       err,
			}
		}
		c.trustedProxies = append([]string(nil), cidrs...)
		return nil
	})
}

// WithCORSOrigins adds explicit cross-origin entries to the CORS allowlist.
// The full allowlist is the union of these origins plus every redirect_uri
// origin the [store.ClientStore] returns; this option only handles entries
// that cannot be derived from a registered redirect_uri (admin SPAs,
// management consoles, etc.) per §F.4.
//
// Origins MUST be absolute URLs with non-empty scheme and host. The path,
// query, and fragment are stripped. Each call appends to the configured
// list; duplicates are deduplicated at allowlist build time.
//
// Stable since v0.1.
func WithCORSOrigins(origins ...string) Option {
	return optionFunc(func(c *config) error {
		if len(origins) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCORSOrigins requires at least one origin",
			}
		}
		for _, o := range origins {
			if _, err := csrf.CanonicalOrigin(o); err != nil {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithCORSOrigins origin rejected: " + o,
					Cause:       err,
				}
			}
		}
		c.corsOrigins = append(c.corsOrigins, origins...)
		return nil
	})
}

// WithScope registers metadata for a single OAuth scope. Calling the
// option multiple times accumulates entries; duplicate Name values
// across calls are rejected at [New] construction time.
//
// Standard OIDC scopes (openid, profile, email, address, phone,
// offline_access) are recognised automatically with built-in defaults
// (Public: true, no UI text). Registering a standard scope through
// [WithScope] overrides the built-in entry — typically to attach
// translations or claim mappings — but registering one with
// Public: false fails [New] so the discovery document never violates
// OpenID Connect Discovery 1.0 §3.
//
// AllowedClients is enforced at the authorize and token endpoints: a
// non-empty list restricts the scope to the listed client_id values
// and any other client receives invalid_scope per RFC 6749 §5.2.
//
// Stable since v0.1.
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

// WithCrossSiteFlow opts the [Provider] into [SameSite=None] cookies so the
// authorization endpoint can be embedded across origins (iframe / external
// SPA) per docs/plans/002-product-design.md §F.3. The default is off
// because cross-site cookies have a higher CSRF blast radius; enable only
// when the deployment requires the embedded flow.
//
// Experimental: the flag is wired through configuration but the cross-site
// flow surface is still being designed; the option name and semantics may
// change before v1.0.
//
// [SameSite=None]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite#none
func WithCrossSiteFlow() Option {
	return optionFunc(func(c *config) error {
		c.crossSiteFlow = true
		return nil
	})
}

// WithAuthenticators registers one or more [Authenticator] values.
// Order is preserved: the orchestrator presents factors in
// registration order when no [RiskAssessor] overrides the choice.
// Calling WithAuthenticators multiple times appends to the configured
// set; duplicates by [Authenticator.Type] are rejected at [New]
// construction time.
//
// At least one authenticator is required for an interactive [Provider]
// to mount /authorize. The orchestrator surfaces the empty-set case
// as a construction error at [New] time; this option only stores the
// registered values.
//
// Experimental: the option name and contract are stable but per-
// authenticator semantics may still evolve before v1.0.
func WithAuthenticators(a ...Authenticator) Option {
	return optionFunc(func(c *config) error {
		if len(a) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAuthenticators requires at least one Authenticator",
			}
		}
		for i, item := range a {
			if item == nil {
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
//
// See docs/plans/002-product-design.md §M.6.1.
//
// Experimental: the verifier contract is stable but the orchestrator
// trigger points around it may still evolve before v1.0.
func WithCaptchaVerifier(v CaptchaVerifier) Option {
	return optionFunc(func(c *config) error {
		if v == nil {
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
//
// See docs/plans/002-product-design.md §M.6.2.
//
// Experimental: the assessor contract is stable but the orchestrator
// trigger points around it may still evolve before v1.0.
func WithRiskAssessor(a RiskAssessor) Option {
	return optionFunc(func(c *config) error {
		if a == nil {
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
// library to slog (§N.2) and observers MUST NOT duplicate them here.
//
// See docs/plans/002-product-design.md §M.6.3.
//
// Experimental: the observer contract is stable but the orchestrator
// emission points around it may still evolve before v1.0.
func WithLoginAttemptObserver(o LoginAttemptObserver) Option {
	return optionFunc(func(c *config) error {
		if o == nil {
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
// KYC, device-trust prompts, ...). Order is preserved within an
// [InteractionTrigger] bucket; cross-trigger ordering is orchestrator-
// defined per §E.9. Calling WithInteractions multiple times appends;
// duplicates by [Interaction.Name] are rejected at [New] construction
// time.
//
// The library-built-in consent screen is registered automatically by
// the orchestrator; user extensions ship with a unique dotted
// [Interaction.Name] (e.g., "myorg.tos.accept").
//
// Experimental: the contract is stable but per-interaction semantics
// may still evolve before v1.0.
func WithInteractions(i ...Interaction) Option {
	return optionFunc(func(c *config) error {
		if len(i) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithInteractions requires at least one Interaction",
			}
		}
		for idx, item := range i {
			if item == nil {
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

// WithBackchannelLogoutHTTPClient injects the [*http.Client] the
// back-channel logout coordinator uses when POSTing Logout Tokens to
// relying parties. Most embedders do not need this — the package
// default (a fresh client with [WithBackchannelLogoutTimeout] applied
// and a CheckRedirect that refuses 3xx hops) is correct for the spec
// posture.
//
// Pass a custom client when the deployment already maintains a shared
// outbound transport (instrumentation, proxy resolution, custom
// dialer, …). Embedders that override the client SHOULD preserve a
// CheckRedirect that returns [http.ErrUseLastResponse] so the OP
// continues to refuse redirects on a sensitive POST; the design notes
// in 002 §H.2 explain why.
//
// Stable since v0.1.
func WithBackchannelLogoutHTTPClient(client *http.Client) Option {
	return optionFunc(func(c *config) error {
		c.backchannelLogoutHTTPClient = client
		return nil
	})
}

// WithBackchannelLogoutTimeout caps the time the OP spends waiting
// for a single relying party to acknowledge a Logout Token POST. The
// budget applies per RP; the coordinator dispatches in parallel, so a
// slow RP does not delay deliveries to its peers.
//
// A zero or negative duration substitutes the package default
// (5 seconds). Embedders SHOULD keep the value low — back-channel
// logout is best-effort, and a long timeout merely keeps the OP
// holding state on a likely-broken RP.
//
// Stable since v0.1.
func WithBackchannelLogoutTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) error {
		c.backchannelLogoutTimeout = d
		return nil
	})
}

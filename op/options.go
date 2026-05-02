package op

import (
	"html/template"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/metrics"
	"github.com/libraz/go-oidc-provider/internal/proxy"
	"github.com/libraz/go-oidc-provider/internal/redact"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Option configures a [Provider] passed to [New]. Options compose: the order
// in which they appear in the New call determines the order in which they
// are applied. Where two options set the same field, the later one wins.
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
	issuer               string
	store                store.Store
	clock                Clock
	logger               *slog.Logger
	auditLogger          *slog.Logger
	keyset               Keyset
	defaultLocale        Locale
	localeBundles        []LocaleBundle
	preferredLocaleStore PreferredLocaleStore
	mountPrefix          string
	endpoints            Endpoints
	grants               []grant.Type
	features             []feature.Flag
	profiles             []profile.Profile
	interactionD         interaction.Driver

	// cookieKeys carries the AES-256-GCM keys used by the Cookie codec.
	// The first entry is the active encryption key; the remainder are
	// rotation slots tried in order on decryption only. Length 32 bytes
	// each; validation runs in [validate].
	cookieKeys [][]byte

	// mfaEncryptionKeys carries the AES-256-GCM keys used to seal
	// per-user TOTP shared secrets at rest. The first entry is the
	// active encryption key; the remainder are rotation slots tried
	// in order on decryption only. Each entry is 32 bytes.
	//
	// The slice backs every [StepTOTP] whose own EncryptionKey is
	// empty; a per-step EncryptionKey overrides the global value when
	// present. Defensive-copied at intake so a later mutation of the
	// caller's slice cannot silently change the OP's keys at runtime.
	mfaEncryptionKeys [][]byte

	// trustedProxies holds the CIDRs from [WithTrustedProxies]. Empty
	// means "no proxy trusted"; X-Forwarded-* headers are ignored.
	trustedProxies []string

	// corsOrigins holds the explicit cross-origin entries from
	// [WithCORSOrigins]. The full allowlist is the union of these plus
	// every redirect_uri origin registered via the [store.ClientStore].
	corsOrigins []string

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
	// registered.
	captcha CaptchaVerifier

	// risk is the optional [RiskAssessor] the orchestrator consults
	// at each [RiskStage]. Nil means "always allow"; at most one
	// assessor may be registered.
	risk RiskAssessor

	// loginObservers carries the [LoginAttemptObserver] values
	// registered through [WithLoginAttemptObserver]. Multiple
	// observers stack: the orchestrator fans out every
	// [LoginAttempt] to each in registration order.
	loginObservers []LoginAttemptObserver

	// interactions carries the non-factor [Interaction] values
	// registered through [WithInteractions]. The orchestrator inserts
	// them per [InteractionTrigger]; intra-trigger ordering follows
	// registration order, cross-trigger ordering is orchestrator-
	// defined.
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

	// sessionDurabilityPosture carries the embedder's declaration of
	// how SessionStore writes flow through their persistence tier.
	// Default zero value is [SessionDurabilityVolatile]; embedders
	// who route SessionStore to a durable backend declare the choice
	// via [WithSessionDurabilityPosture]. The flag does not change
	// runtime gates; it threads into the back-channel coordinator's
	// `bcl.no_sessions_for_subject` audit event so SOC tooling can
	// distinguish expected gaps under volatile placement from
	// unexpected gaps under durable placement.
	sessionDurabilityPosture SessionDurabilityPosture

	// accessTokenTTL is the lifetime of issued access tokens. Zero
	// before [config.applyDefaults] runs; the defaults pass populates
	// it with [DefaultAccessTokenTTL] so [config.validate] can compare
	// against the active profile bound without re-deriving the
	// fallback. Negative values are rejected at the option site.
	accessTokenTTL time.Duration

	// refreshTokenTTL is the lifetime of issued refresh tokens. Zero
	// before [config.applyDefaults] runs; the defaults pass populates
	// it with [DefaultRefreshTokenTTL]. Negative values are rejected
	// at the option site.
	refreshTokenTTL time.Duration

	// refreshTokenOfflineTTL overrides the TTL applied to refresh
	// tokens issued under the OIDC Core 1.0 §11 "offline_access" scope.
	// Zero falls back to refreshTokenTTL so an embedder that does not
	// distinguish offline use never sees the second knob. The library
	// uses this bucket only when the granted scope contains
	// "offline_access"; conventional online refresh continues to use
	// refreshTokenTTL. See [WithRefreshTokenOfflineTTL].
	refreshTokenOfflineTTL time.Duration

	// strictOfflineAccess flips the refresh-token issuance gate to the
	// OIDC Core 1.0 §11 strict reading: refresh tokens are issued only
	// when the granted scope contains "offline_access" (in addition to
	// the existing "openid" + GrantTypes contains refresh_token
	// requirement). Default false reflects the lax reading that the
	// library has shipped since v0.1, matching Auth0 / Okta / Keycloak.
	// See [WithStrictOfflineAccess].
	strictOfflineAccess bool

	// refreshGracePeriod stores the [WithRefreshGracePeriod] override.
	// Zero signals "use library default" (a 60-second window matching
	// RFC 9700 §2.2.2). Negative signals "set explicitly to zero" so a
	// caller that wants the strict no-grace posture can express it
	// without colliding with the zero-value sentinel; the option layer
	// normalises a negative value to a true zero before storing.
	refreshGracePeriod       time.Duration
	refreshGracePeriodSet    bool
	refreshGracePeriodIsZero bool

	// dpopNonces is the [DPoPNonceSource] supplied through
	// [WithDPoPNonceSource]. Nil means the RFC 9449 §8 / §9 nonce
	// flow is disabled; the verifier accepts proofs without a nonce
	// claim and the endpoints never emit the use_dpop_nonce
	// challenge. At most one source may be registered.
	dpopNonces DPoPNonceSource

	// allowPrivateNetworkJWKS, when true, suppresses the SSRF
	// deny-list the JAR / JWKS fetcher applies to RP-controlled URIs.
	// The default false rejects loopback / link-local / RFC 1918
	// hosts so an attacker-controlled jwks_uri cannot pivot the OP
	// onto an internal service. Embedders fronting their RPs with
	// private DNS opt in via [WithAllowPrivateNetworkJWKS].
	allowPrivateNetworkJWKS bool

	// allowPrivateNetworkJAR mirrors [allowPrivateNetworkJWKS] for
	// the JAR request_uri fetcher in /authorize. The two gates are
	// kept independent so an embedder can grant private-network
	// access for one fetcher without widening the other.
	allowPrivateNetworkJAR bool

	// allowLocalhostLoopback widens the RFC 8252 §7.3 loopback
	// redirect_uri carve-out to admit the textual "localhost" host
	// in addition to the IP literals 127.0.0.1 and [::1]. The
	// default false keeps the IP-only posture so a DNS-rebinding
	// adversary cannot pivot a registered http://localhost URI onto
	// an attacker-controlled address (RFC 8252 §8.3). Embedders that
	// rely on the textual host (most native-app SDKs default to
	// http://localhost) opt in via [WithAllowLocalhostLoopback].
	allowLocalhostLoopback bool

	// Login flow / UI / static-clients.
	// loginFlow stores the [LoginFlow] supplied through
	// [WithLoginFlow]. The zero value (Primary == nil) signals
	// "not configured"; a non-zero value is staged for the
	// orchestrator wiring and rejected at [config.validate] until
	// that wiring lands.
	loginFlow LoginFlow

	// loginFlowSet records whether [WithLoginFlow] was invoked,
	// independent of whether the supplied flow had a non-nil
	// Primary. The flag is used to reject duplicate registrations
	// without forcing the orchestrator to re-inspect the zero value.
	loginFlowSet bool

	// spaUI stores the [SPAUI] supplied through [WithSPAUI].
	// The zero value signals "no SPA shell"; a non-zero value
	// causes the default-driver fallback in [config.applyDefaults]
	// to short-circuit so the embedder's SPA owns rendering.
	spaUI SPAUI

	// spaUISet records whether [WithSPAUI] was invoked.
	// Distinct from a populated spaUI value because future
	// revisions may permit a partially-populated [SPAUI] zero
	// value (e.g., LoginMount only).
	spaUISet bool

	// consentUI stores the [ConsentUI] supplied through
	// [WithConsentUI]. Mutually exclusive with [config.spaUI];
	// validation runs at the option site so the conflict surfaces
	// at construction time.
	consentUI ConsentUI

	// consentUISet records whether [WithConsentUI] was invoked.
	consentUISet bool

	// chooserUI stores the [ChooserUI] supplied through
	// [WithChooserUI]. Mutually exclusive with [config.spaUI];
	// validation runs at the option site so the conflict surfaces
	// at construction time.
	chooserUI ChooserUI

	// chooserUISet records whether [WithChooserUI] was invoked.
	chooserUISet bool

	// staticClients carries the [store.Client] records produced by
	// every [WithStaticClients] call (in invocation order, in seed
	// order within each call). The slice is the H1-D orchestrator's
	// input; the option layer only validates seeds and aggregates.
	staticClients []store.Client

	// firstPartyClients carries the client_id values supplied
	// through [WithFirstPartyClients]. Validated against
	// [config.staticClients] in [config.validate] so unknown ids
	// fail at construction time.
	firstPartyClients []string

	// claimsParameterSupportedSet records whether
	// [WithClaimsParameterSupported] was invoked. When false the
	// library defaults to true (the parser is always wired). When
	// true the value of [claimsParameterSupportedOff] decides whether
	// the wire is told the OP honours the parameter; the parser still
	// runs server-side either way so a malformed payload is rejected
	// uniformly.
	claimsParameterSupportedSet bool

	// claimsParameterSupportedOff, when true, makes
	// [config.claimsParameterSupported] return false: the discovery
	// document advertises the absence of §5.5 support and the
	// authorize / par parsers ignore any incoming "claims" payload.
	// The boolean is the negative of the option argument so the zero
	// value keeps the library default of "supported".
	claimsParameterSupportedOff bool

	// openIDScopeOptional, when true, lifts the OIDC Core 1.0 §3.1.2.1
	// requirement that every authorization request include the
	// "openid" scope. The flag exists so an embedder running plain
	// OAuth 2.0 authorization_code flows alongside (or instead of)
	// OIDC can do so without forking the validator. Default is false:
	// requests missing "openid" are rejected with the redirect-safe
	// invalid_scope error per the OIDC default. Token issuance stays
	// scope-driven either way — the id_token is minted only when the
	// granted scope actually carries "openid", so flipping this bit
	// never produces a meaningless id_token.
	openIDScopeOptional bool

	// claimsSupported carries the explicit claim-name enumeration the
	// embedder supplied through [WithClaimsSupported]. Nil means the
	// option was not invoked and the discovery document omits the
	// claims_supported field; an empty non-nil slice is preserved
	// verbatim (an embedder who wants to advertise "no extra claims
	// beyond the defaults" supplies an explicit empty list). The
	// stored slice is a defensive copy so a later mutation of the
	// caller's slice does not silently change the wire output.
	claimsSupported []string

	// acrPolicy carries the [ACRPolicy] supplied through
	// [WithACRPolicy]. A nil value means "library default": the
	// authorize endpoint installs [DefaultACRPolicy] which echoes the
	// first satisfiable acr_values entry while preserving the
	// legacy wire shape when the request omits acr_values.
	acrPolicy ACRPolicy

	// promRegistry is the Prometheus registry supplied by the embedder
	// through [WithPrometheus]. Nil disables metrics. The library only
	// registers collectors; the registry's lifecycle is the embedder's.
	promRegistry *prometheus.Registry

	// jwksRotationActive is the predicate the JWKS handler consults on
	// every request to decide whether to advertise the shortened
	// rotation Cache-Control header. Nil leaves the handler in
	// long-cache mode for every response. The predicate runs on the
	// request hot path, so embedders MUST keep it cheap and
	// concurrency-safe; see [WithJWKSRotationActive].
	jwksRotationActive func() bool

	// metricsCollector is the metric-handle bundle the audit bridge
	// updates from the OP's emission chain. It is populated by
	// [op.New] when promRegistry is non-nil; nil otherwise. Stored on
	// the config so the per-mount audit-emitter helper can reach it
	// without growing a separate plumbing path.
	metricsCollector *metrics.Collector

	// accessTokenFormat selects the wire encoding the OP applies to
	// access tokens issued by every grant type (ADR 0024). Default
	// [AccessTokenFormatJWT] (RFC 9068); embedders flip the value via
	// [WithAccessTokenFormat]. The opaque path requires
	// [store.Store.OpaqueAccessTokens] to return a non-nil substore;
	// the construction-time validator enforces that invariant.
	accessTokenFormat store.AccessTokenFormat

	// accessTokenFormatPerAudience binds an access-token format to
	// individual RFC 8707 resource indicators. Nil means "no
	// per-audience override"; tokens then take their format from
	// [accessTokenFormat]. Map keys MUST be canonical resource
	// indicators (lowercase scheme + host, no fragment, RFC 3986
	// normal form); the option site rejects non-canonical keys at
	// construction time.
	accessTokenFormatPerAudience map[string]store.AccessTokenFormat

	// atRevocation selects the JWT access-token revocation strategy
	// the OP applies (ADR 0025). The zero value is
	// [store.RevocationStrategyGrantTombstone], which is the documented
	// default; embedders flip the value via
	// [WithAccessTokenRevocationStrategy]. The opaque AT path
	// (ADR 0024) is unaffected because opaque tokens are intrinsically
	// per-token in storage. Out-of-range values and FAPI-incompatible
	// combinations are rejected at construction time.
	atRevocation store.AccessTokenRevocationStrategy

	// discoveryMetadata carries the static RFC 8414 §2 metadata fields
	// the embedder injected through [WithDiscoveryMetadata]. The zero
	// value (every field empty / nil) is the library default and emits
	// no extra discovery keys; populated values are merged into the
	// document at build time and override-deny-checked at option time.
	discoveryMetadata DiscoveryMetadata

	// discoveryMetadataSet records whether [WithDiscoveryMetadata]
	// was invoked, so a duplicate call can fail at construction time
	// instead of silently overwriting the previous metadata.
	discoveryMetadataSet bool
}

// claimsParameterSupported returns the effective discovery
// advertisement for the OIDC Core 1.0 §5.5 "claims" parameter. The
// library default is true; embedders flip the bit via
// [WithClaimsParameterSupported]. The function is consulted by both
// the discovery builder and the authorize parser so the wire and the
// runtime stay in lock-step.
func (c *config) claimsParameterSupported() bool {
	if !c.claimsParameterSupportedSet {
		return true
	}
	return !c.claimsParameterSupportedOff
}

// formatForAudience returns the access-token format the OP issues for
// a request whose RFC 8707 resource indicator is resource. The lookup
// order is per-audience map first (canonicalised key), then the
// global [config.accessTokenFormat], then the documented default
// [AccessTokenFormatJWT]. The empty resource string flows through to
// the global default; the option-layer validator forbids the empty key
// in the per-audience map specifically so that branch is unambiguous.
func (c *config) formatForAudience(resource string) store.AccessTokenFormat {
	if resource != "" && c.accessTokenFormatPerAudience != nil {
		if f, ok := c.accessTokenFormatPerAudience[resource]; ok {
			return f
		}
	}
	return c.accessTokenFormat
}

// effectiveACRPolicy returns the [ACRPolicy] the wire layer consults.
// The function is the single source of "did the embedder supply a
// policy or are we using the default", so the authorize wiring and
// any future seam (id_token re-resolution at refresh time, custom
// /authorize tests) read the same value.
func (c *config) effectiveACRPolicy() ACRPolicy { //nolint:ireturn // sealed-sum interface return is the contract.
	if c.acrPolicy == nil {
		return DefaultACRPolicy{}
	}
	return c.acrPolicy
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

// WithIssuer sets the OP issuer URL. The value MUST be an absolute URL with a
// non-empty authority (host), no trailing slash, and no query or fragment,
// per OpenID Connect Discovery 1.0 §3 / FAPI 2.0 §5.4. The scheme MUST be
// https; loopback IP literals (127.0.0.0/8 and [::1]) are exempted from the
// https requirement so a development boot can use plain http. The textual
// host "localhost" is intentionally NOT exempted because it can be
// DNS-hijacked (RFC 8252 §7.3 reasoning); a development boot binding
// loopback uses the IP literal directly.
//
// The validation is delegated to [discovery.ValidateIssuer] so the option
// site and the metadata-build pass share a single rule. Malformed values
// fail [New] rather than the first request.
// Stable since v0.1.
func WithIssuer(issuer string) Option {
	return optionFunc(func(c *config) error {
		if issuer == "" {
			return ErrIssuerRequired
		}
		if err := discovery.ValidateIssuer(issuer); err != nil {
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
// Every entry MUST be ECDSA on curve P-256 (the v1.0 ES256 policy).
// Supplying any other key shape causes [New] to fail at construction
// time.
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
// real wall clock backed by [time.Now()]. Tests SHOULD inject a deterministic
// clock so the whole flow shares the same fake time.
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
// The supplied logger's handler is wrapped with the library's redaction
// hook (see internal/redact) so attributes named after the canonical
// OAuth/OIDC secrets — access_token, refresh_token, id_token, code,
// code_verifier, client_secret, password, state, nonce, dpop,
// authorization, cookie, set-cookie — are masked before they reach
// the underlying handler. The wrapping is idempotent: passing a
// logger whose handler is already redact-wrapped is a no-op.
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
// [audit.Discard()] — that path is reachable only when neither option
// was supplied.
func (c *config) effectiveAuditLogger() *slog.Logger {
	if c.auditLogger != nil {
		return c.auditLogger
	}
	return c.logger
}

// effectiveAuditEmitter returns the [audit.Emitter] handler-mount
// sites consume. The base layer is [audit.Slog] over
// [config.effectiveAuditLogger]; when [WithPrometheus] is configured
// the result is wrapped with a [metrics.Bridge] so a single emission
// fires both the slog audit line and the matching counter.
func (c *config) effectiveAuditEmitter() audit.Emitter {
	base := audit.Slog(c.effectiveAuditLogger())
	if c.metricsCollector == nil {
		return base
	}
	return metrics.NewBridge(c.metricsCollector, base)
}

// WithPrometheus registers a curated counter set on registry. The OP
// updates the counters from its audit-event emission chain; the
// embedder remains responsible for the HTTP request lifecycle (e.g.
// per-endpoint duration histograms via promhttp middleware) and for
// exposing the registry over /metrics. Only client_id values present
// in the static-client seed list are emitted as label values; dynamic
// clients are bucketed into the empty label so label cardinality stays
// bounded. PII labels (subject, IP, user-agent) are never emitted.
//
// The registry's lifecycle is the embedder's responsibility — the
// library calls Register but never Unregister.
//
// Stable since v0.1.
func WithPrometheus(registry *prometheus.Registry) Option {
	return optionFunc(func(c *config) error {
		if registry == nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithPrometheus requires a non-nil registry",
			}
		}
		c.promRegistry = registry
		return nil
	})
}

// WithJWKSRotationActive registers a predicate the JWKS endpoint
// consults on every request to decide whether to advertise the
// shortened rotation Cache-Control. When the predicate returns
// true, responses carry "public, max-age=300, must-revalidate";
// otherwise the standard long cache applies.
//
// The predicate runs on the request hot path, so it MUST be cheap
// and concurrency-safe. Passing nil (or omitting the option)
// leaves the handler permanently in long-cache mode.
//
// The option only forwards the embedder's predicate; the rotation
// lifecycle (when to flip from idle to rotating, when to flip back)
// remains the embedder's responsibility.
//
// Repeated calls are last-wins so a supervisor can swap predicates
// without rebuilding earlier option lists.
//
// Stable since v0.x.
func WithJWKSRotationActive(predicate func() bool) Option {
	return optionFunc(func(c *config) error {
		c.jwksRotationActive = predicate
		return nil
	})
}

// WithAuditLogger injects the [*slog.Logger] the library routes
// audit events on. Audit records carry the slog attribute
// "audit"="true" so log shippers can split them onto a dedicated
// retention bucket without parsing the [AuditEvent] name; the
// design rationale is in design 002 §N.1.
// If unset, the [Provider] uses the operational logger from
// [WithLogger]; if neither is configured, audit records are dropped.
// Embedders SHOULD pass a logger pointed at long-retention storage
// (S3-backed handler, BigQuery sink, ELK index, …) so audit lines
// outlive the operational stream.
// The supplied logger's handler is wrapped with the same redaction
// hook as [WithLogger] so a regression that puts a token into an
// [AuditEvent] extras map cannot escape the wire posture.
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
// The supplied prefix MUST start with "/" and MUST NOT end with "/". Empty
// values reject; the empty-prefix case (mounting at root) is supported by
// passing "/" explicitly.
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
// repeated; each call adds to the enabled set.
// Idempotent: enabling a flag that is already present is a silent
// no-op rather than a configuration error. This matches the
// auto-enable contract [WithProfile] introduced so an embedder may write
// `WithProfile(FAPI2Baseline)` plus `WithFeature(feature.PAR)` —
// either order, before or after — without the second call failing
// because the profile already activated the flag.
// Stable since v0.1.
func WithFeature(f feature.Flag) Option {
	return optionFunc(func(c *config) error {
		if !f.IsValid() {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithFeature received an unknown feature flag",
			}
		}
		if featureEnabled(c.features, f) {
			return nil
		}
		c.features = append(c.features, f)
		return nil
	})
}

// WithAccessTokenTTL overrides the lifetime applied to issued access
// tokens. Zero means "use [DefaultAccessTokenTTL]"; a negative value
// is rejected at the option site so the misconfiguration surfaces at
// startup rather than silently expiring tokens at the wrong cadence.
// When [WithProfile] is also configured, the embedder's TTL MUST stay
// at or below the profile's bound (see [profile.MaxAccessTokenTTL] —
// FAPI 2.0 §3.1.9 caps at 10 minutes). Stricter-than-profile values
// are accepted; a value above the bound fails [New].
// Stable since v0.1.
func WithAccessTokenTTL(ttl time.Duration) Option {
	return optionFunc(func(c *config) error {
		if ttl < 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAccessTokenTTL requires a non-negative duration",
			}
		}
		c.accessTokenTTL = ttl
		return nil
	})
}

// WithRefreshTokenTTL overrides the lifetime applied to issued refresh
// tokens. Zero means "use [DefaultRefreshTokenTTL]" (30 days); a
// negative value is rejected at the option site so the
// misconfiguration surfaces at startup rather than silently issuing
// tokens with the wrong cadence.
//
// Refresh tokens are issued only when the granted scope contains
// "openid" AND the client's GrantTypes includes "refresh_token"; the
// library defaults to the lax reading of OIDC Core 1.0 §11 in which
// the "offline_access" scope governs consent UX and the TTL bucket
// (see [WithRefreshTokenOfflineTTL]) but does not gate issuance.
// Embedders who want the strict §11 reading — refresh issued only
// when "offline_access" is granted — pass [WithStrictOfflineAccess].
// To disable refresh tokens entirely, remove "refresh_token" from
// the per-client GrantTypes or from the global [WithGrants] set.
// Stable since v0.2.
func WithRefreshTokenTTL(ttl time.Duration) Option {
	return optionFunc(func(c *config) error {
		if ttl < 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithRefreshTokenTTL requires a non-negative duration",
			}
		}
		c.refreshTokenTTL = ttl
		return nil
	})
}

// WithRefreshTokenOfflineTTL overrides the lifetime applied to
// refresh tokens issued under the OIDC Core 1.0 §11 "offline_access"
// scope. The default zero value defers to [WithRefreshTokenTTL] so
// embedders that do not distinguish offline use see no behaviour
// change. When set to a non-zero value, refresh tokens issued
// alongside an `offline_access`-bearing grant get the offline TTL
// while conventional online refresh continues to use the refresh-
// token TTL.
//
// The split makes the discovery-advertised "offline_access" scope
// operationally observable: under the lax reading it lengthens the
// refresh-token lifetime; under [WithStrictOfflineAccess] it is the
// only path that issues a refresh token at all.
// Stable since v0.x.
func WithRefreshTokenOfflineTTL(ttl time.Duration) Option {
	return optionFunc(func(c *config) error {
		if ttl < 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithRefreshTokenOfflineTTL requires a non-negative duration",
			}
		}
		c.refreshTokenOfflineTTL = ttl
		return nil
	})
}

// WithStrictOfflineAccess flips the refresh-token issuance gate to
// the strict reading of OIDC Core 1.0 §11: refresh tokens are issued
// only when the granted scope contains "offline_access" (in addition
// to the existing "openid" + per-client `refresh_token` grant
// requirement). Authorization-code exchanges that satisfy the other
// conditions but lack `offline_access` succeed with an `access_token`
// + `id_token` and no `refresh_token` field — mirroring today's
// "client lacks refresh_token grant" path.
//
// At /token (grant_type=refresh_token), a refresh request whose
// originating grant did not carry `offline_access` fails with
// `invalid_grant` ("refresh disabled by current policy"). The check
// runs after the underlying refresh-token exchange, so the presented
// token is consumed exactly once even when the policy rejects it —
// embedders flipping this flag mid-deployment must accept that
// pre-flag refresh tokens are invalidated on first use.
//
// The flag is incompatible with [WithOpenIDScopeOptional]: §11 has
// no meaning for non-OIDC requests, so combining the two would
// silently disable every refresh issuance. [op.New] returns
// `op.Error{Code: codeConfiguration}` on the conflict.
//
// Default false. The lax reading (refresh issued whenever
// `refresh_token` grant is registered and scope contains "openid")
// is the historical library posture and matches Auth0 / Okta /
// Keycloak; the strict reading matches panva/node-oidc-provider and
// ory/hydra defaults.
// Stable since v0.x.
func WithStrictOfflineAccess() Option {
	return optionFunc(func(c *config) error {
		c.strictOfflineAccess = true
		return nil
	})
}

// WithAccessTokenFormat selects the global access-token format
// (ADR 0024). Default [AccessTokenFormatJWT]; passing
// [AccessTokenFormatOpaque] switches every issued access token onto
// the opaque-bearer path described in [store.OpaqueAccessToken].
//
// When the opaque format is selected the configured [Store] MUST
// return a non-nil [store.OpaqueAccessTokenStore] from
// [store.Store.OpaqueAccessTokens]; [New] rejects the configuration
// at construction time when the substore is nil so a misconfiguration
// surfaces at startup rather than the first /token request.
//
// If [WithAccessTokenFormatPerAudience] is also set, this option
// supplies the fallback for any RFC 8707 resource indicator absent
// from the map.
//
// Stable since v0.x.
func WithAccessTokenFormat(f store.AccessTokenFormat) Option {
	return optionFunc(func(c *config) error {
		if !f.IsValid() {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAccessTokenFormat received an unknown AccessTokenFormat value",
			}
		}
		c.accessTokenFormat = f
		return nil
	})
}

// WithAccessTokenFormatPerAudience binds an access-token format to
// each RFC 8707 resource indicator (ADR 0024). Tokens minted for a
// request whose resource value matches a key in the map use the
// mapped format; tokens for any other resource (including the empty
// default audience) fall back to [WithAccessTokenFormat] or, if that
// option is also absent, [AccessTokenFormatJWT].
//
// Map keys MUST be canonical resource indicators per RFC 3986 §6:
//   - absolute URI with a non-empty scheme and host;
//   - scheme and host in lowercase form;
//   - no fragment;
//   - empty-string keys are rejected — the global default belongs in
//     [WithAccessTokenFormat].
//
// Non-canonical keys (mixed-case scheme / host, fragment present, …)
// fail at [New] so an embedder cannot ship a typo that silently
// disables the policy. Map values MUST be one of the documented
// constants ([AccessTokenFormatJWT] or [AccessTokenFormatOpaque]);
// unknown values are rejected with the same "fail-fast at
// construction" posture as [WithAccessTokenFormat].
//
// When the map contains any [AccessTokenFormatOpaque] value the
// configured [Store] MUST return a non-nil
// [store.OpaqueAccessTokenStore]; the construction-time validator
// enforces the same rule that [WithAccessTokenFormat] applies.
//
// Calling the option more than once replaces the prior map entirely.
// The supplied map is defensive-copied so a later mutation of the
// caller's map cannot silently change the OP's policy at runtime.
//
// Stable since v0.x.
func WithAccessTokenFormatPerAudience(m map[string]store.AccessTokenFormat) Option {
	return optionFunc(func(c *config) error {
		if len(m) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAccessTokenFormatPerAudience requires at least one entry",
			}
		}
		out := make(map[string]store.AccessTokenFormat, len(m))
		for raw, f := range m {
			if raw == "" {
				return &Error{
					Code: codeConfiguration,
					Description: "WithAccessTokenFormatPerAudience: empty key is " +
						"reserved; use WithAccessTokenFormat for the default audience",
				}
			}
			if !f.IsValid() {
				return &Error{
					Code: codeConfiguration,
					Description: "WithAccessTokenFormatPerAudience[" + raw +
						"]: unknown AccessTokenFormat value",
				}
			}
			if err := validateResourceIndicator(raw); err != nil {
				return err
			}
			out[raw] = f
		}
		c.accessTokenFormatPerAudience = out
		return nil
	})
}

// validateResourceIndicator enforces the canonical-form rules
// [WithAccessTokenFormatPerAudience] applies to its map keys. The
// check runs against the raw string (not the [url.URL] view) because
// the issuance path keys the per-audience map directly off the
// request's verbatim resource parameter; a key whose lowercase /
// fragment-stripped re-rendering differs from the raw bytes would
// silently miss every lookup.
//
// The helper is split out so a future option that consumes resource
// indicators (e.g. a per-audience TTL knob) can reuse the same
// invariants without re-deriving the parse.
func validateResourceIndicator(raw string) error {
	// Reject obvious non-URI / mixed-case forms before url.Parse so
	// the diagnostic points at the actual source bytes rather than
	// the normalised form Go produces.
	if raw != strings.ToLower(raw) && hasUppercaseSchemeOrHost(raw) {
		return &Error{
			Code: codeConfiguration,
			Description: "WithAccessTokenFormatPerAudience[" + raw +
				"]: scheme and host must be lowercase",
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return &Error{
			Code: codeConfiguration,
			Description: "WithAccessTokenFormatPerAudience[" + raw +
				"]: not a valid URI",
			Cause: err,
		}
	}
	if !u.IsAbs() || u.Scheme == "" || u.Host == "" {
		return &Error{
			Code: codeConfiguration,
			Description: "WithAccessTokenFormatPerAudience[" + raw +
				"]: must be an absolute URI with scheme and host",
		}
	}
	if u.Fragment != "" || u.RawFragment != "" || strings.Contains(raw, "#") {
		return &Error{
			Code: codeConfiguration,
			Description: "WithAccessTokenFormatPerAudience[" + raw +
				"]: fragment is not permitted",
		}
	}
	return nil
}

// hasUppercaseSchemeOrHost reports whether raw carries a non-lowercase
// ASCII letter before the start of the path / query / fragment. The
// function is conservative — it triggers on any uppercase byte in the
// scheme + authority — so callers receive a clear diagnostic instead
// of the silent-canonical surprise [url.Parse] produces (Go normalises
// the scheme to lowercase at parse time, hiding caller mistakes from
// a post-parse comparison).
//
// The scan terminates at the first '/' that starts the path component
// (the boundary after "scheme://authority") or the first '?' / '#'
// that starts query / fragment; URI-path bytes can be case-sensitive,
// so they are not inspected, and a fragment-only mismatch surfaces
// through the dedicated fragment check rather than this helper.
func hasUppercaseSchemeOrHost(raw string) bool {
	end := len(raw)
	if idx := strings.Index(raw, "://"); idx >= 0 {
		// raw = "scheme://authority[/path|?query|#fragment]"; scan
		// stops at the first byte that ends the authority component.
		rest := raw[idx+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			end = idx + 3 + j
		}
	} else if j := strings.IndexAny(raw, "/?#"); j >= 0 {
		end = j
	}
	for i := range end {
		c := raw[i]
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// WithClaimsSupported populates the discovery document's
// claims_supported field with the supplied claim names. OIDC Discovery
// 1.0 §3 lists claims_supported as RECOMMENDED — clients consult it to
// decide whether a particular claim is worth requesting via scope or
// via the §5.5 "claims" parameter — but the spec leaves the OP free to
// omit the field when the OP cannot pre-enumerate its claim universe.
//
// The library default is to omit the field. The library's claims
// projector emits OIDC Core 1.0 §5.4 standard claims when the
// configured [op/store.UserStore] returns matching values, and the
// list of which standard claims a particular embedder actually
// surfaces depends entirely on what the user store fills in; rather
// than guess, the library leaves the discovery field blank by default
// so embedders cannot accidentally advertise claims they never emit.
//
// Callers supply the closed list themselves. A typical FAPI 2.0
// deployment that exposes profile / email / phone scopes would call:
//
//	op.WithClaimsSupported(
//	    "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
//	    "name", "given_name", "family_name", "preferred_username",
//	    "email", "email_verified",
//	)
//
// The supplied slice is copied defensively. Passing the option twice
// fails at construction time so the operator notices the duplicate.
// Passing a nil or empty slice records the empty list (the discovery
// document still omits the field — the omitempty JSON tag covers
// both cases) so the option doubles as an "explicitly no claims"
// declaration when an embedder needs that posture.
//
// Stable since v0.x.
func WithClaimsSupported(claims ...string) Option {
	return optionFunc(func(c *config) error {
		if c.claimsSupported != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithClaimsSupported was supplied more than once",
			}
		}
		c.claimsSupported = slices.Clone(claims)
		if c.claimsSupported == nil {
			// slices.Clone(nil) returns nil; record an empty slice so
			// the "option was supplied" signal is preserved without
			// changing the wire output (claims_supported uses
			// omitempty).
			c.claimsSupported = []string{}
		}
		return nil
	})
}

// WithClaimsParameterSupported toggles the OP's handling of the OIDC
// Core 1.0 §5.5 "claims" request parameter. The library default is
// true: the parser is always wired; the discovery document advertises
// claims_parameter_supported: true; the authorize / par endpoints
// honour any incoming payload by persisting it on the originating
// grant; the userinfo and id_token issuance paths project the
// requested claims when the user store has matching values. Passing
// false flips the discovery advertisement off, makes the authorize /
// par parsers silently drop the parameter (no invalid_request), and
// disables the userinfo / id_token projection.
//
// The toggle is provided so an embedder that does not want to expose
// per-claim consent (e.g. a deployment whose RPs already negotiate
// claims out-of-band) can match the ory/hydra posture without losing
// scope-driven release. It does not affect the parser's malformed-
// JSON rejection: a payload that is genuinely malformed is still
// rejected at the wire boundary irrespective of the toggle, because
// the parser also services the FAPI 2.0 conformance flow which
// expects a uniform invalid_request shape.
//
// Stable since v0.x.
func WithClaimsParameterSupported(enabled bool) Option {
	return optionFunc(func(c *config) error {
		c.claimsParameterSupportedSet = true
		c.claimsParameterSupportedOff = !enabled
		return nil
	})
}

// DiscoveryMetadata carries the static RFC 8414 §2 metadata fields an
// embedder injects into the OP's discovery document. The fields are
// values the OP itself does not own — the human-readable URLs and the
// list of UI locales the deployment supports — so they MUST be
// supplied by the embedder rather than guessed by the library.
//
// The four named fields map 1:1 to discovery JSON keys; Extra accepts
// arbitrary additional keys (RFC 8414 §2 explicitly permits unknown
// metadata members). Keys that collide with an OP-controlled field
// name (issuer, authorization_endpoint, response_types_supported, …)
// are rejected at op.New construction time so embedders cannot silently
// shadow protocol-defining values.
type DiscoveryMetadata struct {
	// ServiceDocumentation is the URL of the OP's developer
	// documentation (RFC 8414 §2 "service_documentation"). The empty
	// string omits the field from the wire.
	ServiceDocumentation string

	// OPPolicyURI is the URL of the OP's privacy policy
	// (OpenID Connect Discovery 1.0 §3 / RFC 8414 §2
	// "op_policy_uri"). The empty string omits the field.
	OPPolicyURI string

	// OPTermsOfServiceURI is the URL of the OP's terms-of-service
	// page (OpenID Connect Discovery 1.0 §3 / RFC 8414 §2
	// "op_tos_uri"). The empty string omits the field.
	OPTermsOfServiceURI string

	// UILocalesSupported lists the BCP 47 language tags the OP's
	// human-facing UI supports (OpenID Connect Discovery 1.0 §3 /
	// RFC 8414 §2 "ui_locales_supported"). Nil and empty are
	// equivalent — the field is omitted from the wire.
	UILocalesSupported []string

	// MTLSEndpointAliases publishes alternative URLs at which the OP
	// serves its mTLS-required endpoints (RFC 8705 §5). Keys MUST
	// match discovery endpoint metadata names exactly as they appear
	// on the wire (e.g. "token_endpoint", "introspection_endpoint",
	// "revocation_endpoint", "userinfo_endpoint",
	// "registration_endpoint",
	// "device_authorization_endpoint",
	// "pushed_authorization_request_endpoint"); values are absolute
	// URLs that require client-certificate authentication.
	//
	// The field is structurally feature-gated: it is published only
	// when [feature.MTLS] is enabled. Supplying aliases without the
	// MTLS feature is a no-op so an embedder can keep the option in
	// place across feature toggles without further branching.
	//
	// Deployments that front a single hostname (the canonical
	// *_endpoint values are already mTLS-capable) leave this map nil
	// or empty so the field stays absent from the discovery
	// document — RFC 8705 §5 makes the publication MAY, not MUST.
	//
	// Spec: RFC 8705 §5.
	MTLSEndpointAliases map[string]string

	// Extra carries arbitrary embedder-defined passthrough keys. The
	// values are JSON-marshalled into the discovery document at the
	// top level. Keys MUST be valid RFC 8414 metadata names (lowercase
	// snake_case is conventional but the library does not enforce a
	// shape) and MUST NOT collide with any OP-controlled field name;
	// op.New rejects collisions at construction time so a typo cannot
	// silently shadow a protocol-defining value.
	Extra map[string]any
}

// WithDiscoveryMetadata injects static RFC 8414 §2 metadata fields into
// the OP's discovery document. The OP does not own the URLs or the
// list of UI locales the deployment supports; the embedder supplies
// them through this option, and the library merges them into the
// document at construction time.
//
// The four named [DiscoveryMetadata] fields are typed for safety;
// arbitrary additional metadata keys go into [DiscoveryMetadata.Extra]
// and are passed through verbatim. RFC 8414 §2 explicitly permits
// unknown metadata members, so embedders that publish a custom field
// (e.g. an organisation-specific extension) can do so without the
// library knowing about it.
//
// The option enforces an override-deny invariant: any [Extra] key that
// matches an OP-controlled field name (issuer, authorization_endpoint,
// response_types_supported, jwks_uri, …) is rejected at op.New, and
// the error names the offending key. The deny-list is computed via
// reflection over the discovery document shape, so it stays in sync
// with the library's wire output as new fields land.
//
// The option may be supplied at most once; a duplicate call returns
// a configuration error so an embedder notices the conflict.
//
// Spec: RFC 8414 §2.
//
// Stable since v0.x.
func WithDiscoveryMetadata(meta DiscoveryMetadata) Option {
	return optionFunc(func(c *config) error {
		if c.discoveryMetadataSet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDiscoveryMetadata was supplied more than once",
			}
		}
		if err := validateDiscoveryMetadataExtra(meta.Extra); err != nil {
			return err
		}
		c.discoveryMetadata = cloneDiscoveryMetadata(meta)
		c.discoveryMetadataSet = true
		return nil
	})
}

// validateDiscoveryMetadataExtra rejects empty Extra keys and any key
// that collides with an OP-controlled discovery field. The four named
// fields appearing under Extra are blocked because they already have
// typed slots on [DiscoveryMetadata]; a duplicate would create two
// sources of truth.
func validateDiscoveryMetadataExtra(extra map[string]any) error {
	if len(extra) == 0 {
		return nil
	}
	denied := opControlledKeySet()
	for key := range extra {
		if key == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDiscoveryMetadata: Extra contains an empty key",
			}
		}
		if _, blocked := denied[key]; blocked {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDiscoveryMetadata: Extra key " + key + " collides with an OP-controlled discovery field",
			}
		}
	}
	return nil
}

// cloneDiscoveryMetadata copies meta into a fresh [DiscoveryMetadata]
// so the option does not retain a reference to the embedder's slices /
// maps. The maps are cloned only when populated to keep the wire shape
// (omitempty) stable across nil and empty inputs.
func cloneDiscoveryMetadata(meta DiscoveryMetadata) DiscoveryMetadata {
	out := DiscoveryMetadata{
		ServiceDocumentation: meta.ServiceDocumentation,
		OPPolicyURI:          meta.OPPolicyURI,
		OPTermsOfServiceURI:  meta.OPTermsOfServiceURI,
		UILocalesSupported:   slices.Clone(meta.UILocalesSupported),
	}
	if len(meta.MTLSEndpointAliases) > 0 {
		out.MTLSEndpointAliases = maps.Clone(meta.MTLSEndpointAliases)
	}
	if len(meta.Extra) > 0 {
		out.Extra = maps.Clone(meta.Extra)
	}
	return out
}

// opControlledKeySet returns the set of discovery JSON keys the OP
// itself populates. The set is recomputed on every call from
// [discovery.OPControlledFieldNames]; the override-deny check runs only
// at op.New construction time, so the per-call cost is negligible and
// a package-level cache is unnecessary.
func opControlledKeySet() map[string]struct{} {
	names := discovery.OPControlledFieldNames()
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}

// WithOpenIDScopeOptional lifts the OpenID Connect Core 1.0 §3.1.2.1
// requirement that every authorization request include the "openid"
// scope. With the option set, the OP serves both flavours from the
// same /authorize endpoint: requests carrying "openid" run the OIDC
// path (id_token + userinfo); requests omitting "openid" run as plain
// OAuth 2.0 authorization_code (access token + optional refresh token,
// no id_token). The token endpoint's id_token issuance stays
// scope-driven, so a downgrade to OAuth 2.0 never produces a stray
// id_token.
//
// Use this only when the deployment intentionally serves non-OIDC
// clients. The default posture (option absent) matches OIDC: a request
// missing "openid" is rejected before the redirect with
// invalid_scope. Discovery and userinfo are unchanged — the OP
// remains a fully-capable OIDC OP and clients that want id_tokens
// only need to keep "openid" in their scope list.
//
// The flag is incompatible with [profile.Profile] sets that mandate
// OIDC semantics (FAPI 2.0 Baseline / Message Signing); op.New
// rejects the combination at construction time.
//
// Stable since v0.x.
func WithOpenIDScopeOptional() Option {
	return optionFunc(func(c *config) error {
		c.openIDScopeOptional = true
		return nil
	})
}

// WithACRPolicy installs a custom [ACRPolicy] that decides what acr /
// amr claims the OP writes onto issued id_tokens and which acr_values
// requests the OP treats as satisfied. The library default is
// [DefaultACRPolicy] (lax: any AAL>=AAL1 satisfies any requested
// acr); embedders that need a stricter mapping (e.g. NIST SP 800-63
// binding, a configured per-acr table à la Keycloak) supply their
// own implementation. Passing nil restores the library default.
//
// The default installation is intentional: a deployment that omits
// the option gets the OFCS-passing wire shape automatically.
//
// Stable since v0.x.
func WithACRPolicy(p ACRPolicy) Option {
	return optionFunc(func(c *config) error {
		c.acrPolicy = p
		return nil
	})
}

// WithProfile activates an industry security profile. Profiles compose
// multiplicatively: enabling FAPI2Baseline implies its underlying features
// and policies. Repeated profiles are rejected.
// WithProfile auto-enables every flag returned by
// [profile.RequiredFeatures] for the supplied profile. The auto-enable is
// idempotent: a flag already present in the configured feature set is
// silently skipped (NOT rejected as a duplicate), so an embedder may
// layer [WithFeature] before or after [WithProfile] without surprise.
// The auto-enable is intentionally add-only: WithProfile never removes
// a flag the embedder already set.
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
		// Auto-enable every required feature idempotently. The
		// duplicate check in [WithFeature] is bypassed because the
		// auto-enable contract is "silently skip", not "fail loudly":
		// embedders must remain free to call [WithFeature] explicitly
		// before or after [WithProfile].
		for _, req := range profile.RequiredFeatures(p) {
			if !req.IsValid() {
				continue
			}
			if featureEnabled(c.features, req) {
				continue
			}
			c.features = append(c.features, req)
		}
		return nil
	})
}

// WithInteractionDriver registers the [interaction.Driver] that bridges
// the OP state machine to the user-facing UI. If unset, the [Provider]
// uses [interaction.JSONDriver], which speaks JSON over HTTP: every
// prompt is written as a JSON envelope and every submission is decoded
// from a JSON body. SSR or framework-specific Drivers replace it.
// Stable since v0.1.
func WithInteractionDriver(d interaction.Driver) Option {
	return optionFunc(func(c *config) error {
		if d == nil {
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
// Stable since v0.1.
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
// Stable since v0.1.
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

// WithTrustedProxies declares the CIDRs from which the [Provider] should
// honour [X-Forwarded-*] headers. When a request arrives from outside these
// ranges the headers are ignored, preventing IP / scheme spoofing
// .
// CIDRs may be IPv4 or IPv6; both notations are accepted. Each call
// replaces the previous list — pass every trusted CIDR in a single call.
// Stable since v0.1.
func WithTrustedProxies(cidrs ...string) Option {
	return optionFunc(func(c *config) error {
		if len(cidrs) == 0 {
			return newConfigurationError("WithTrustedProxies requires at least one CIDR", nil)
		}
		// Validate eagerly so misconfiguration surfaces at New time
		// rather than the first cross-proxy request.
		if _, err := proxy.NewTrust(cidrs); err != nil {
			return newConfigurationError("WithTrustedProxies CIDR rejected", err)
		}
		c.trustedProxies = append([]string(nil), cidrs...)
		return nil
	})
}

// WithCORSOrigins adds explicit cross-origin entries to the CORS allowlist.
// The full allowlist is the union of these origins plus every redirect_uri
// origin the [store.ClientStore] returns; this option only handles entries
// that cannot be derived from a registered redirect_uri (admin SPAs,
// management consoles, etc.).
// Origins MUST be absolute URLs with non-empty scheme and host. The path,
// query, and fragment are stripped. Each call appends to the configured
// list; duplicates are deduplicated at allowlist build time.
// Stable since v0.1.
func WithCORSOrigins(origins ...string) Option {
	return optionFunc(func(c *config) error {
		if len(origins) == 0 {
			return newConfigurationError("WithCORSOrigins requires at least one origin", nil)
		}
		for _, o := range origins {
			if _, err := csrf.CanonicalOrigin(o); err != nil {
				return newConfigurationError("WithCORSOrigins origin rejected: "+o, err)
			}
		}
		c.corsOrigins = append(c.corsOrigins, origins...)
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
// library to slog and observers MUST NOT duplicate them here.
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
// KYC, device-trust prompts...). Order is preserved within an
// [InteractionTrigger] bucket; cross-trigger ordering is orchestrator-
// defined. Calling WithInteractions multiple times appends; duplicates
// by [Interaction.Name] are rejected at [New] construction time.
// The library-built-in consent screen is registered automatically by
// the orchestrator; user extensions ship with a unique dotted
// [Interaction.Name] (e.g., "myorg.tos.accept").
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
// Pass a custom client when the deployment already maintains a shared
// outbound transport (instrumentation, proxy resolution, custom
// dialer, …). Embedders that override the client SHOULD preserve a
// CheckRedirect that returns [http.ErrUseLastResponse] so the OP
// continues to refuse redirects on a sensitive POST (back-channel
// logout targets cannot be redirected without forging the audience
// the signed Logout Token commits to).
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
// A zero or negative duration substitutes the package default
// (5 seconds). Embedders SHOULD keep the value low — back-channel
// logout is best-effort, and a long timeout merely keeps the OP
// holding state on a likely-broken RP.
//
// # Delivery integrity
//
// Back-channel logout fan-out walks the active grants the OP
// remembers for the terminating subject. The walk's coverage is
// bounded by the durability of the [op/store.SessionStore] and the
// [op/store.GrantStore] backing the OP: under volatile placement
// (Redis without persistence, Memcached, in-memory under maxmemory
// eviction) a session evicted between establishment and logout
// silently removes the rows the coordinator would walk, narrowing
// OIDC Back-Channel Logout 1.0 §2.7's best-effort floor to zero.
// Embedders who require at-least-once delivery for every initiated
// logout MUST route SessionStore to a durable backend; the
// `bcl.no_sessions_for_subject` audit event ([AuditBCLNoSessionsForSubject])
// surfaces the gap when it actually fires. Declare the chosen
// posture through [WithSessionDurabilityPosture] so the audit
// signal carries the embedder's intent.
// Stable since v0.1.
func WithBackchannelLogoutTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) error {
		c.backchannelLogoutTimeout = d
		return nil
	})
}

// SessionDurabilityPosture is the embedder's declaration of how
// [op/store.SessionStore] writes flow through their persistence
// tier. The choice is plumbed into the back-channel logout
// coordinator's `bcl.no_sessions_for_subject` audit event so SOC
// tooling can distinguish "expected gap under volatile placement"
// from "unexpected gap under durable placement" without keying on
// the store-adapter type. The library does not enforce the
// declaration; embedders who route SessionStore to a volatile
// backend while declaring [SessionDurabilityDurable] will see the
// audit event fire under conditions their dashboard's "durable"
// filter does not expect.
type SessionDurabilityPosture int

const (
	// SessionDurabilityVolatile is the default. SessionStore writes
	// are best-effort; eviction / failover may remove rows the
	// back-channel coordinator would walk. OIDC Back-Channel Logout
	// 1.0 §2.7 explicitly classifies delivery as best-effort, so
	// the volatile floor is spec-conformant — but the audit signal
	// makes the gap observable when it fires.
	SessionDurabilityVolatile SessionDurabilityPosture = iota

	// SessionDurabilityDurable declares that SessionStore writes
	// survive process restarts and tier failover. Embedders who
	// flip the declaration MUST route SessionStore to a durable
	// backend (the SQL adapter, an embedder-supplied store with
	// WAL semantics, etc.).
	SessionDurabilityDurable
)

// WithSessionDurabilityPosture records the embedder's declaration
// of [op/store.SessionStore] durability so the back-channel logout
// coordinator can stamp the value into the
// `bcl.no_sessions_for_subject` audit event ([AuditBCLNoSessionsForSubject]).
// The flag does not change runtime gates; it is a typed declaration
// that lets SOC dashboards filter expected gaps under volatile
// placement from unexpected gaps under durable placement.
//
// Default [SessionDurabilityVolatile]. Embedders who route
// SessionStore to a durable backend (the SQL adapter, an
// embedder-supplied store with WAL semantics) flip the declaration
// to [SessionDurabilityDurable].
// Stable since v0.x.
func WithSessionDurabilityPosture(p SessionDurabilityPosture) Option {
	return optionFunc(func(c *config) error {
		c.sessionDurabilityPosture = p
		return nil
	})
}

// WithDPoPNonceSource opts the provider into the RFC 9449 §8 / §9
// server-supplied nonce flow for DPoP proofs. With a non-nil source
// wired, the /token and /userinfo handlers reject any DPoP proof
// whose "nonce" claim is absent or not accepted by
// [DPoPNonceSource.Validate], emitting the spec-mandated
// `use_dpop_nonce` challenge along with a fresh value from
// [DPoPNonceSource.IssueNonce] in the response's `DPoP-Nonce`
// header.
// Without this option the provider preserves the v0.x posture:
// proofs without a nonce claim are accepted and the challenge is
// never emitted. The option is independent of [WithFeature]
// (feature.DPoP); the nonce flow only fires when DPoP is also
// enabled because the verifier itself is wired only on that flag.
// At most one source may be registered; a second [WithDPoPNonceSource]
// call fails [New] so a typo cannot silently win.
//
// Multi-replica deployments: the supplied [DPoPNonceSource] MUST be
// backed by a distributed cache (Redis / memcached / shared in-process
// gossip) when the OP runs behind more than one replica. A
// process-local source (e.g. the in-memory rotation ring shipped for
// development) issues nonces one replica accepts but the others
// reject, so a client routed across the fleet sees spurious
// `use_dpop_nonce` retries forever. The library deliberately ships no
// distributed implementation today; embedders supply one that matches
// their deployment topology.
// Stable since v0.1.
func WithDPoPNonceSource(source DPoPNonceSource) Option {
	return optionFunc(func(c *config) error {
		if source == nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDPoPNonceSource received nil DPoPNonceSource",
			}
		}
		if c.dpopNonces != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDPoPNonceSource may be called at most once",
			}
		}
		c.dpopNonces = source
		return nil
	})
}

// WithRefreshGracePeriod overrides the RFC 9700 §2.2.2 grace window
// the token endpoint applies to a replayed refresh token. Inside the
// window a parallel client retry that races the rotated child returns
// the same response without revoking the chain; outside it the
// replay is treated as theft and the family is revoked. The library
// default (60 seconds) absorbs typical SPA / mobile retry storms; a
// stricter posture passes a smaller positive duration. Pass zero to
// disable the window entirely so any replay revokes immediately —
// FAPI 2.0 §J.7.2 §3.1.7 mandates this for FAPI2Baseline /
// FAPI2MessageSigning, and the option layer enforces the bound at
// construction time when those profiles are active (a non-zero value
// supplied alongside the profile produces a configuration error).
// Negative values are rejected at the option site; the API treats
// "no grace" as the explicit zero so accidental sign-flip cannot
// silently widen the window.
// Stable since v0.x.
func WithRefreshGracePeriod(d time.Duration) Option {
	return optionFunc(func(c *config) error {
		if d < 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithRefreshGracePeriod must not be negative",
			}
		}
		if c.refreshGracePeriodSet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithRefreshGracePeriod may be called at most once",
			}
		}
		c.refreshGracePeriod = d
		c.refreshGracePeriodSet = true
		c.refreshGracePeriodIsZero = d == 0
		return nil
	})
}

// effectiveRefreshGrace returns the refresh-token grace window the
// token endpoint should apply. The function honours [WithRefreshGracePeriod]
// when called, else returns 0 so the internal exchanger falls back
// to its [refresh.GraceTTLDefault]. The grace window is profile-
// agnostic: FAPI 2.0 OFCS conformance treats a brief replay window
// as legitimate retry handling, so no profile forces a strict zero.
func (c *config) effectiveRefreshGrace() time.Duration {
	if !c.refreshGracePeriodSet {
		return 0
	}
	if c.refreshGracePeriodIsZero {
		// Pass through as a negative sentinel so the internal
		// exchanger treats it as "explicit zero", not "use default".
		return -1
	}
	return c.refreshGracePeriod
}

// WithAllowPrivateNetworkJWKS suppresses the SSRF deny-list the
// internal JWKS fetcher applies to RP-controlled JWKS URIs. The
// default posture rejects URLs whose host is a literal "localhost",
// resolves to a loopback / link-local / RFC 1918 / ULA address, or
// uses a non-http(s) scheme; the OP does this so an attacker-
// controlled jwks_uri value cannot pivot the OP onto an internal
// service.
// Embedders that legitimately host their RPs on a private network
// (CI, on-prem deployment with an internal RP) opt in via this
// option. The opt-in is JWKS-specific so the analogous JAR
// request_uri fetcher remains independently gated by
// [WithAllowPrivateNetworkJAR].
// Stable since v0.x.
func WithAllowPrivateNetworkJWKS() Option {
	return optionFunc(func(c *config) error {
		c.allowPrivateNetworkJWKS = true
		return nil
	})
}

// WithAllowPrivateNetworkJAR is the JAR request_uri counterpart of
// [WithAllowPrivateNetworkJWKS]. It suppresses the SSRF deny-list
// applied to RP-controlled request_uri values when /authorize fetches
// the request object. The option is independent of the JWKS opt-in so
// embedders can grant private-network access to one fetcher without
// widening the other. The default false posture is the safe choice
// for production deployments.
// Stable since v0.x.
func WithAllowPrivateNetworkJAR() Option {
	return optionFunc(func(c *config) error {
		c.allowPrivateNetworkJAR = true
		return nil
	})
}

// WithAllowLocalhostLoopback widens the RFC 8252 §7.3 native-app
// loopback redirect_uri carve-out to admit the textual "localhost"
// host. The default posture only admits the IP literals 127.0.0.1 and
// [::1] over plain http; localhost is rejected so a DNS-rebinding
// attacker (RFC 8252 §8.3) cannot point a registered
// http://localhost:* URI at a host they control after the client
// resolved it once. Native-app SDKs that bind their loopback listener
// to the textual "localhost" hostname (the most common default) opt
// in via this option.
// Stable since v0.x.
func WithAllowLocalhostLoopback() Option {
	return optionFunc(func(c *config) error {
		c.allowLocalhostLoopback = true
		return nil
	})
}

// SPAUI declares the SPA-shell mount points and optional asset root
// the [Provider] should expose so the embedder's React (or framework-
// neutral SPA) frontend can drive the login / consent / RP-Initiated
// Logout flows. The struct is supplied to [WithSPAUI]; the option
// stores it on config and the orchestrator wiring later translates
// the mount points into JSON state endpoints. The scope is
// deliberately limited to login / consent / RP-Initiated Logout:
// front-channel logout and session management iframes are out of
// scope, so [SPAUI] does not carry mounts for those surfaces.
// Experimental: the field set is being introduced in v0.x and MAY
// gain optional fields before v1.0. Embedders SHOULD construct
// [SPAUI] with named field initialisation so future additions
// remain source-compatible.
type SPAUI struct {
	// LoginMount is the URL path the SPA's login entry HTML lives
	// under (typically "/login"). MUST be non-empty and MUST start
	// with "/"; an empty value rejects [WithSPAUI] at the option
	// site so the misconfiguration surfaces at construction time.
	LoginMount string

	// ConsentMount is the URL path the consent screen renders
	// under. Empty means the SPA serves the consent screen from
	// LoginMount and an internal route discriminator. When set
	// MUST start with "/".
	ConsentMount string

	// LogoutMount is the URL path the RP-Initiated Logout
	// confirmation screen renders under. Empty means the OP
	// renders a built-in confirmation; when set MUST start with
	// "/".
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
// Experimental: the field set is being introduced in v0.x. The plan
// reserves a Strings field for an i18n bundle once the public i18n
// surface stabilises; the field is omitted today so embedders are
// not pinned to a placeholder type.
type ConsentUI struct {
	// Template is the [html/template.Template] the consent screen
	// renders. The library passes the canonical consent context
	// (Client, Scopes, CSRFToken) at render time. MUST be non-nil;
	// the option site rejects a nil template so the
	// misconfiguration surfaces at [New].
	Template *template.Template
}

// ChooserUI declares the template the [Provider] uses to render the
// account chooser screen when prompt=select_account fires for a
// session that already has a chooser group. Mutually exclusive with
// [WithSPAUI]; supplying both fails [New] with a structured
// configuration error. The struct field set is intentionally narrow:
// the chooser screen has a fixed data model (Accounts, AddAccountURL,
// CSRFToken) and the embedder supplies an [*template.Template] that
// consumes it.
// Experimental: the field set is being introduced in v0.x. Future
// revisions may add a Strings field for an i18n bundle once the
// public i18n surface stabilises.
type ChooserUI struct {
	// Template is the [html/template.Template] the chooser screen
	// renders. The library passes the canonical chooser context
	// (Accounts, AddAccountURL, CSRFToken) at render time. MUST be
	// non-nil; the option site rejects a nil template so the
	// misconfiguration surfaces at [New].
	Template *template.Template
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
// Experimental: the LoginFlow seam is being introduced in v0.x.
// Field names and evaluation order MAY change before v1.0.
func WithLoginFlow(flow LoginFlow) Option {
	return optionFunc(func(c *config) error {
		if c.loginFlowSet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithLoginFlow may be called at most once",
			}
		}
		if flow.Primary == nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithLoginFlow: LoginFlow.Primary must not be nil",
			}
		}
		seen := make(map[StepKind]struct{}, len(flow.Rules))
		for i, r := range flow.Rules {
			if r.Then == nil {
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
//   - LoginMount MUST be non-empty and MUST start with "/".
//   - ConsentMount and LogoutMount MAY be empty; when set they MUST
//     start with "/".
//   - StaticDir MAY be empty; when set the directory MUST exist at
//     construction time (an [os.Stat] check) so a typo fails [New]
//     rather than the first request.
//
// Experimental — partial wiring: as of v0.x, [New] validates the
// option, suppresses the default HTML driver, and emits a WARN log
// line through the configured logger documenting the gap. The
// configured LoginMount, ConsentMount, LogoutMount, and StaticDir
// are NOT yet mounted by the [Provider] — embedders must serve their
// SPA externally (typically via an outer mux that routes the SPA
// paths to the bundle directory and forwards everything else to the
// Provider). Auto-mounted JSON state endpoints under the configured
// mounts land in a follow-up release.
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
		return nil
	})
}

// checkSPAUIPrecondition rejects repeated [WithSPAUI] calls and the
// [WithConsentUI] mutual-exclusion case. Split out so [WithSPAUI]
// stays under the gocognit ceiling now that mount / StaticDir checks
// also live in helpers.
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
	if c.chooserUISet {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithSPAUI is mutually exclusive with WithChooserUI",
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
//   - Repeated [WithConsentUI] calls are rejected.
//
// Experimental — no-op today: as of v0.x, [New] validates the option
// and emits a WARN log line through the configured logger but does
// NOT yet route the supplied Template into any consent renderer. The
// option is reserved so the v1.0 surface can be planned without
// shipping a placeholder type later; embedders can register a
// template now and have it consumed automatically once the
// consent-interaction wiring lands.
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
		c.consentUI = ui
		c.consentUISet = true
		return nil
	})
}

// WithChooserUI registers the [ChooserUI] template the HTML driver
// uses for the account chooser screen. Mutually exclusive with
// [WithSPAUI]; supplying both fails [New] with a structured
// configuration error.
// Validation:
//   - Template MUST be non-nil.
//   - Repeated [WithChooserUI] calls are rejected.
//
// Experimental — no-op today: as of v0.x, [New] validates the option
// and emits a WARN log line through the configured logger but does
// NOT yet route the supplied Template into the chooser renderer.
// The option is reserved so the v1.0 surface can be planned without
// shipping a placeholder type later; embedders can register a
// template now and have it consumed automatically once the chooser
// HTML render path lands.
func WithChooserUI(ui ChooserUI) Option {
	return optionFunc(func(c *config) error {
		if c.chooserUISet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithChooserUI may be called at most once",
			}
		}
		if c.spaUISet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithChooserUI is mutually exclusive with WithSPAUI",
			}
		}
		if ui.Template == nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithChooserUI: Template must not be nil",
			}
		}
		c.chooserUI = ui
		c.chooserUISet = true
		return nil
	})
}

// WithStaticClients seeds the [Provider]'s static-client surface from
// the supplied [ClientSeed] values. Each seed is projected onto a
// [store.Client] record via its [ClientSeed.seed] method; any error
// from the projection (most commonly an empty
// [ConfidentialClient.Secret] reaching [HashClientSecret]) surfaces at
// the option site with the seed's index in the description so the
// caller can locate the offending entry.
// Repeated calls append to the configured set so embedders MAY layer
// builders (a base set plus a deployment-specific overlay) without
// duplicate-rejection. The aggregate slice feeds the orchestrator
// hookup; today the records are stored on config and consumed by the
// orchestrator wiring that lands in a follow-up.
// Stable since v0.1.
func WithStaticClients(seeds ...ClientSeed) Option {
	return optionFunc(func(c *config) error {
		if len(seeds) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithStaticClients requires at least one ClientSeed",
			}
		}
		for i, s := range seeds {
			if s == nil {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithStaticClients[" + strconv.Itoa(i) + "]: nil ClientSeed",
				}
			}
			rec, err := s.seed()
			if err != nil {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithStaticClients[" + strconv.Itoa(i) + "]: " + err.Error(),
					Cause:       err,
				}
			}
			c.staticClients = append(c.staticClients, rec)
		}
		return nil
	})
}

// WithFirstPartyClients marks the listed client_id values as first-
// party so the consent prompt is skipped for them. The auto-consent
// path is gated on the matching [store.Client.Source] being
// [store.ClientSourceStatic] or [store.ClientSourceAdmin] —
// [store.ClientSourceDynamic] (RFC 7591 self-registered) is excluded
// because dynamically-registered clients cannot be vetted as
// first-party.
// Validation:
//   - The id list MUST be non-empty.
//   - Duplicate ids within a single call are rejected; repeated calls
//     append so embedders may layer deployment-specific entries.
//   - Every advertised id MUST appear in [WithStaticClients] after
//     every option has been applied; the cross-option check runs in
//     [config.validate] so the two options are order-independent.
//   - FAPI 2.0 profiles forbid first-party auto-consent; combining
//     [WithFirstPartyClients] with [WithProfile(profile.FAPI2*)]
//     fails [New].
//
// Stable since v0.1.
func WithFirstPartyClients(ids ...string) Option {
	return optionFunc(func(c *config) error {
		if len(ids) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithFirstPartyClients requires at least one client_id",
			}
		}
		seen := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			if id == "" {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithFirstPartyClients: client_id must not be empty",
				}
			}
			if _, dup := seen[id]; dup {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithFirstPartyClients: duplicate client_id " + id,
				}
			}
			seen[id] = struct{}{}
		}
		c.firstPartyClients = append(c.firstPartyClients, ids...)
		return nil
	})
}

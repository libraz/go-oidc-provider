package op

import (
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/metrics"
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

	// trustedProxyHosts holds the hostnames from
	// [WithTrustedProxyHosts] that the OP will honour in
	// X-Forwarded-Host. Empty composes with the auto-derived issuer
	// host: the runtime allowlist used by [proxy.NewTrustWithHosts]
	// is the union of the explicit entries + the issuer host. A
	// configured set composes additively with the issuer host so an
	// embedder fronting two public hostnames can register the
	// secondary one without losing the canonical issuer match.
	trustedProxyHosts []string

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

	// authnLockoutStore is the optional [store.AuthnLockoutStore]
	// supplied through [WithAuthnLockoutStore]. Nil means "no
	// cross-factor brute-force counter" — every built-in second
	// factor falls back to its per-record FailedCount only.
	// At most one store may be registered.
	authnLockoutStore store.AuthnLockoutStore

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

	// allowPrivateNetworkSector mirrors [allowPrivateNetworkJWKS] for
	// the sector_identifier_uri fetcher invoked at dynamic client
	// registration. The opt-in is sector-specific so embedders can
	// host their RPs on a private network for pairwise subject
	// derivation without widening the JWKS or JAR fetchers.
	allowPrivateNetworkSector bool

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

	// acrValuesSupported carries the Authentication Context Class
	// Reference values supplied through [WithACRValuesSupported].
	// Nil means the option was not invoked and the discovery
	// document omits acr_values_supported; a non-nil slice is
	// published verbatim. The stored slice is a defensive copy so a
	// later mutation of the caller's slice does not silently change
	// the wire output.
	acrValuesSupported []string

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

	// subjectGenerator stores the [SubjectGenerator] supplied through
	// [WithSubjectGenerator] or [WithPairwiseSubject]. Nil means
	// "library default": the issuance pipeline routes through
	// [github.com/libraz/go-oidc-provider/op/subject.UUIDv7] which
	// passes the OP-internal user identifier through verbatim.
	//
	// At most one of [WithSubjectGenerator] and [WithPairwiseSubject]
	// may be supplied; option-site validation rejects the second
	// invocation. Switching the active generator after grants have
	// been issued is rejected at construction time by the subject-mode
	// immutability gate.
	subjectGenerator SubjectGenerator

	// subjectGeneratorSource records which option produced the
	// [config.subjectGenerator]. Empty means "library default";
	// "WithSubjectGenerator" / "WithPairwiseSubject" name the call
	// site so a duplicate registration error can blame the original
	// option without re-deriving it from the value.
	subjectGeneratorSource string

	// pairwiseSalt is the salt supplied through
	// [WithPairwiseSubject], copied defensively so a later mutation
	// of the caller's slice cannot silently change subject derivation
	// at runtime. Non-empty when (and only when) the pairwise option
	// was invoked; the dynamic-registration mount consults the field
	// to decide whether "subject_type": "pairwise" is acceptable on
	// inbound RFC 7591 metadata.
	pairwiseSalt []byte

	// customGrants is the dispatch table the token endpoint consults
	// for grant_type values that match none of the built-in cases.
	// Order is preserved (registration order) so collision checks
	// can blame the prior registrant by name; the slice is read-only
	// after [config.validate] runs.
	customGrants []CustomGrantHandler

	// tokenExchangePolicy stores the [TokenExchangePolicy] the embedder
	// supplied through [RegisterTokenExchange]. Nil means token-exchange
	// is not enabled on this provider; non-nil means the dispatcher
	// hosts the in-tree RFC 8693 handler with the policy as its admission
	// hook. At most one policy may be registered; a second
	// [RegisterTokenExchange] call yields [ErrTokenExchangeDuplicate].
	tokenExchangePolicy TokenExchangePolicy

	// deviceCodeGrantEnabled records the explicit
	// [WithDeviceCodeGrant] opt-in. When true the construction-time
	// validator requires the configured [store.Store] to expose a
	// non-nil [store.DeviceCodeStore] substore; when false the
	// device_code grant is enabled iff [grant.DeviceCode] appears in
	// [config.grants], and the runtime path falls back to
	// unsupported_grant_type if the substore is missing.
	deviceCodeGrantEnabled bool

	// deviceVerificationURI overrides the verification URI advertised
	// to the device in the RFC 8628 §3.2 response. Empty falls back
	// to `<issuer>/device`; a non-empty value is validated at the
	// option site (absolute URL with a non-empty host).
	deviceVerificationURI string

	// encryptionKeyset carries the asymmetric private keys the OP
	// uses to decrypt inbound JWE (request_object) and to encrypt
	// outbound JWE addressed to RP keys (id_token / userinfo / JARM
	// / introspection). Nil means JWE is not configured: discovery
	// omits the *_encryption_*_values_supported arrays and inbound
	// decryption attempts fail with invalid_request_object. RFC 7517
	// §4.2 requires the keyset to be disjoint by kid from the signing
	// keyset; the construction-time gate runs in
	// [config.validateEncryptionKeyset].
	encryptionKeyset EncryptionKeyset

	// encryptionAlgsAllowed is the embedder-narrowed JWE alg
	// allow-list. Empty (with the Set companion flag false) falls
	// back to [SupportedEncryptionAlgs]; an empty (non-nil) slice
	// with the flag true means "advertise no algs" — a deliberate
	// disable-negotiation posture.
	encryptionAlgsAllowed    []string
	encryptionAlgsAllowedSet bool

	// encryptionEncsAllowed mirrors encryptionAlgsAllowed for the JWE
	// content-encryption advertisement.
	encryptionEncsAllowed    []string
	encryptionEncsAllowedSet bool
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

// acrValuesSupportedCopy returns a defensive copy of the ACR class
// references the embedder supplied through [WithACRValuesSupported],
// or nil when the option was not invoked. The copy isolates the
// discovery builder from a caller that retained a handle to the
// original slice; the discovery builder also clones before publishing,
// so the wire is double-protected against in-place mutation.
func (c *config) acrValuesSupportedCopy() []string {
	if c.acrValuesSupported == nil {
		return nil
	}
	return slices.Clone(c.acrValuesSupported)
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
func (c *config) effectiveACRPolicy() ACRPolicy { //nolint:ireturn,nolintlint // sealed-sum interface return is the contract.
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

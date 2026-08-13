package op

import (
	"crypto/x509"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/metrics"
	"github.com/libraz/go-oidc-provider/internal/redact"
	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
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
	userStore            store.UserStore
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
	grantsSet            bool
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

	// backchannelLogoutHTTPClient supplies the outbound Transport the
	// back-channel logout coordinator uses to POST Logout Tokens to RPs.
	// Nil means "use the package default". The builder intentionally
	// ignores the supplied client's timeout and redirect policy so its
	// hardened envelope remains mandatory.
	backchannelLogoutHTTPClient *http.Client

	// backchannelLogoutTimeout is the per-RP request budget. Zero
	// substitutes [backchannel.DefaultTimeout].
	backchannelLogoutTimeout time.Duration

	// backchannelFanOutBudget caps the total wall-clock time one
	// detached back-channel logout fan-out may occupy, across every
	// RP it notifies. Zero substitutes
	// [backchannel.DefaultFanOutBudget]; non-positive values are
	// rejected at the option site. See [WithBackchannelFanOutBudget].
	backchannelFanOutBudget time.Duration

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

	// parLifetime overrides the lifetime of a persisted PAR record's
	// request_uri (RFC 9126 §2.2). Zero defers to the PAR endpoint's
	// own default (60s). The lifetime governs only how long the client
	// has to present the request_uri at /authorize; once the request is
	// resolved there, an interactive login that outlives the window
	// still completes, because single-use — not expiry — is what the
	// store enforces at code emission. See [WithPARLifetime].
	parLifetime time.Duration

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

	// backchannelAllowPrivateNetwork mirrors
	// [allowPrivateNetworkJWKS] for the back-channel logout
	// deliverer. The default false rejects loopback / link-local /
	// RFC 1918 / IPv6 ULA destinations so a hostile RP cannot
	// register a backchannel_logout_uri that aims the OP's signed
	// logout_token at an internal service. Embedders opt in via
	// [WithBackchannelAllowPrivateNetwork].
	backchannelAllowPrivateNetwork bool

	// allowLocalhostLoopback widens the RFC 8252 §7.3 loopback
	// redirect_uri carve-out to admit the textual "localhost" host
	// in addition to the IP literals 127.0.0.1 and [::1]. The
	// default false keeps the IP-only posture so a DNS-rebinding
	// adversary cannot pivot a registered http://localhost URI onto
	// an attacker-controlled address (RFC 8252 §8.3). Embedders that
	// rely on the textual host (most native-app SDKs default to
	// http://localhost) opt in via [WithAllowLocalhostLoopback].
	allowLocalhostLoopback bool

	// allowInsecureBackchannelLogoutForDev is the
	// [WithAllowInsecureBackchannelLogoutForDev] dev-only opt-out: it
	// admits http:// loopback (127.0.0.1, [::1], localhost) for
	// backchannel_logout_uri at static-client and DCR validation, and
	// suppresses the deliverer's SSRF gate so the demo round-trip
	// completes against a local RP stub. The default false keeps the
	// production posture (https-only, public-network-only) intact.
	allowInsecureBackchannelLogoutForDev bool

	// jwksHTTPTransport is the [http.RoundTripper] [WithJWKSHTTPTransport]
	// passes to every relying-party JWKS fetch: the JAR resolver, the
	// client-assertion verifier, and the outbound-encryption recipient
	// resolver. All three read the same RP endpoints, so a private CA
	// that one of them needs is a private CA all of them need. Nil means
	// "use the package default": an [http.Transport] backed by Go's
	// system trust store. Embedders that need a private CA (an internal
	// CA-issued RP JWKS endpoint, the OFCS conformance harness against a
	// self-signed runner cert) inject one here. The dial-time SSRF gate
	// survives either way, because the fetch layer re-wires DialContext
	// on whichever transport it ends up with.
	jwksHTTPTransport http.RoundTripper

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

	// chooserUIShadowedBySPA records that both [WithSPAUI] and
	// [WithChooserUI] are configured. The combination is permitted mode
	// (SPA owns the chooser surface via the JSON state envelope); the
	// chooser HTML template is silently ignored. The flag is set in
	// either order — by [WithChooserUI] when SPA is already configured,
	// or by [WithSPAUI] when the chooser is already configured — so
	// [config.applyDefaults] can emit a single structured warning
	// regardless of option invocation order.
	chooserUIShadowedBySPA bool

	// highEntropyClientSecrets records [WithHighEntropyClientSecrets].
	// It selects the client_secret verifier installed on every endpoint
	// that authenticates a client, which in turn fixes both the
	// verification cost and the cost of the timing shim that stands in
	// for it — the two have to move together or the shim stops hiding
	// anything.
	highEntropyClientSecrets bool

	// staticClients carries the [store.Client] records produced by
	// every [WithStaticClients] call (in invocation order, in seed
	// order within each call). The slice is the orchestrator's
	// input; the option layer only validates seeds and aggregates.
	staticClients []store.Client

	// staticClientSecrets temporarily retains the plaintext supplied by
	// ConfidentialClient seeds so startup reconciliation can compare a
	// freshly salted desired hash with an existing hash semantically. New
	// clears the map before returning; plaintext never reaches a store or the
	// constructed Provider.
	staticClientSecrets map[string]string

	// firstPartyClients carries the client_id values supplied
	// through [WithFirstPartyClients]. Validated against
	// [config.staticClients] in [config.validate] so unknown ids
	// fail at construction time.
	firstPartyClients []string

	// protectedResources carries the RFC 9728 resource-server metadata
	// documents registered through [WithProtectedResources], in
	// invocation order. Each entry's Resource is validated at the
	// option site; duplicate-resource detection runs in
	// [config.validate]. The router mounts one well-known handler per
	// entry.
	protectedResources []ProtectedResource

	// authorizationDetailTypes carries the RFC 9396 authorization_details
	// types registered through [WithAuthorizationDetailTypes], in
	// registration order. A non-empty slice implies [feature.RAR]. The
	// registered validators are consulted when parsing
	// authorization_details at /authorize, /par, and /token.
	authorizationDetailTypes []AuthorizationDetailType

	// grantManagement* carry the OAuth 2.0 Grant Management draft
	// configuration from [WithGrantManagement]. grantManagementEnabled
	// gates the feature; Actions is the advertised / accepted set;
	// ActionRequired maps to grant_management_action_required.
	grantManagementEnabled        bool
	grantManagementActions        []GrantManagementAction
	grantManagementActionRequired bool

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

	// backchannelCoordinator is the back-channel logout fan-out
	// coordinator the /end_session handler dispatches to. It is
	// populated by [op.New] while the router is assembled, and only
	// for a configuration that mounts the browser authorize endpoint;
	// nil otherwise. Stored on the config so [Provider.Shutdown] can
	// reach the same instance the handler uses without the router
	// growing a second return value.
	backchannelCoordinator *backchannel.Coordinator

	// accessTokenFormat selects the wire encoding the OP applies to
	// access tokens issued by every grant type. Default
	// [AccessTokenFormatJWT] (RFC 9068); embedders flip the value via
	// [WithAccessTokenFormat]. The opaque path requires
	// [store.Store.OpaqueAccessTokens] to return a non-nil substore; the
	// construction-time validator enforces that invariant.
	accessTokenFormat store.AccessTokenFormat

	// accessTokenFormatPerAudience binds an access-token format to
	// individual RFC 8707 resource indicators. Nil means "no
	// per-audience override"; tokens then take their format from
	// [accessTokenFormat]. Map keys MUST be canonical resource
	// indicators (lowercase scheme + host, no fragment, RFC 3986
	// normal form); the option site rejects non-canonical keys at
	// construction time.
	accessTokenFormatPerAudience map[string]store.AccessTokenFormat

	// atRevocation selects the JWT access-token revocation strategy the
	// OP applies. The zero value is
	// [store.RevocationStrategyGrantTombstone], which is the documented
	// default; embedders flip the value via
	// [WithAccessTokenRevocationStrategy]. The opaque AT path is
	// unaffected because opaque tokens are intrinsically per-token in
	// storage. Out-of-range values and FAPI-incompatible combinations
	// are rejected at construction time.
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

	// deviceCodeExpiry is the lifetime advertised to the device as
	// `expires_in` and stamped on the persisted device_code record.
	// Zero before [config.applyDefaults] runs; the defaults pass
	// populates it with [devicecode.DefaultExpiresIn]. This knob is
	// intentionally independent of [config.accessTokenTTL]: RFC 8628
	// leaves the device_code lifetime unspecified, and a deployment
	// that runs a short access-token TTL must still give a
	// distracted user enough time to reach a secondary device.
	// See [WithDeviceCodeExpiry].
	deviceCodeExpiry time.Duration

	// deviceCodePollInterval is the value advertised to the device
	// as `interval` (RFC 8628 §3.2). Zero before
	// [config.applyDefaults] runs; the defaults pass populates it
	// with [devicecode.DefaultInterval]. See
	// [WithDeviceCodePollInterval].
	deviceCodePollInterval time.Duration

	// cibaGrantEnabled records the explicit [WithCIBA] opt-in. When
	// true the construction-time validator requires the configured
	// [store.Store] to expose a non-nil [store.CIBARequestStore]
	// substore AND a non-nil [HintResolver]; when false the CIBA
	// grant is enabled iff [grant.CIBA] appears in [config.grants],
	// and the runtime path falls back to unsupported_grant_type if
	// the substore is missing.
	cibaGrantEnabled bool

	// cibaHintResolver maps the inbound CIBA hint (login_hint,
	// id_token_hint, or login_hint_token) to a stable end-user
	// subject. Required by [WithCIBA] because the /bc-authorize
	// handler returns login_required when the resolver is nil.
	cibaHintResolver HintResolver

	// cibaDefaultExpiresIn overrides the auth_req_id lifetime the
	// OP advertises when the client did not supply requested_expiry.
	// Zero falls back to [ciba.DefaultExpiresIn] (600s).
	cibaDefaultExpiresIn time.Duration

	// cibaMaxExpiresIn caps the requested_expiry value the client
	// supplies. Zero disables clamping (the client's value passes
	// through verbatim); a non-zero value is the maximum
	// auth_req_id lifetime the OP will honour regardless of the
	// client's request.
	cibaMaxExpiresIn time.Duration

	// cibaPollInterval overrides the `interval` value the OP
	// advertises to the client. Zero falls back to
	// [ciba.DefaultInterval] (5s).
	cibaPollInterval time.Duration

	// cibaMaxPollViolations overrides the strike threshold above
	// which the token endpoint locks a CIBA record by calling Deny
	// with reason "poll_abuse". Zero falls back to the library
	// default ([ciba.MaxPollViolations], currently 5). 255 disables
	// the lockout effectively (the strike counter is uint8 and never
	// wraps past 255). The knob exists because the OFCS
	// fapi-ciba multiple-call-to-token-endpoint module exercises the
	// slow_down ladder more times than the default cap permits.
	cibaMaxPollViolations uint8

	// encryptionKeyset carries the asymmetric private keys the OP
	// uses to decrypt inbound JWE (request_object). Nil means the OP
	// accepts no encrypted request object: discovery omits the
	// request_object_encryption_*_values_supported arrays and a
	// decryption attempt fails with invalid_request_object. Outbound
	// encryption is unaffected — it addresses the recipient client's
	// key, not one of these. RFC 7517 §4.2 requires the keyset to be
	// disjoint by kid from the signing keyset; the construction-time
	// gate runs in [config.validateEncryptionKeyset].
	encryptionKeyset EncryptionKeyset

	// encryptionAlgsAllowed is the embedder-narrowed JWE alg
	// allow-list. Empty (with the Set companion flag false) falls
	// back to [SupportedEncryptionAlgs]; an empty (non-nil) slice
	// with the flag true means "permit no algs" — a deliberate
	// disable-negotiation posture. [config.jwePolicy] turns the pair
	// into the value the decryption, encryption and registration
	// gates all enforce.
	encryptionAlgsAllowed    []string
	encryptionAlgsAllowedSet bool

	// encryptionEncsAllowed mirrors encryptionAlgsAllowed for the JWE
	// content-encryption half.
	encryptionEncsAllowed    []string
	encryptionEncsAllowedSet bool

	// mtlsProxy stores the [WithMTLSProxy] state. The zero value
	// (empty header, nil trusted list) means the header path is
	// disabled and the verifier consults TLS-handshake certs only.
	// The field lives on config (not a package-level registry) so its
	// lifetime is tied to the owning [Provider]: once the Provider is
	// unreachable, this field is collected with it.
	mtlsProxy mtlsProxyState

	// mtlsRootCAs stores the [WithMTLSRootCAs] trust anchors. Nil
	// (the default) leaves chain validation to whoever terminated the
	// client's TLS connection; a non-nil pool makes the OP's own mTLS
	// verifier re-validate every client leaf it selects before the
	// certificate is thumbprinted or matched.
	mtlsRootCAs *x509.CertPool
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
//
// Defence in depth: every grant endpoint canonicalises the request's
// resource value — lower-cased scheme and host, default port and
// trailing slash normalised — before the wire layer reaches this
// lookup. The canonicalisation here is a second pass so an embedder
// who reaches into the issuance call
// site directly still gets a correct hit for a request whose verbatim
// bytes differ from the registered key only by case or trailing slash.
// A malformed resource (validation should have rejected it before this
// point) collapses onto the global default.
func (c *config) formatForAudience(resource string) store.AccessTokenFormat {
	if resource != "" && c.accessTokenFormatPerAudience != nil {
		if f, ok := c.accessTokenFormatPerAudience[resource]; ok {
			return f
		}
		if canonical, err := resourceindicator.Canonicalize(resource); err == nil {
			if f, ok := c.accessTokenFormatPerAudience[canonical]; ok {
				return f
			}
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

// WithIssuer sets the OP issuer URL. The value MUST be the canonical form an
// RP can use for byte-exact comparison under RFC 9207 mix-up defense: an
// absolute URL with a non-empty lowercase authority (scheme and host),
// no default port (:443 for https, :80 for http), no trailing slash,
// no query, no fragment, and a canonical path (no "..", ".", or
// duplicate slashes), per OpenID Connect Discovery 1.0 §3 /
// RFC 8414 §3 / FAPI 2.0 §5.4. The scheme MUST be https; loopback IP
// literals (127.0.0.0/8 and [::1]) are exempted from the https
// requirement so a development boot can use plain http. The textual
// host "localhost" is intentionally NOT exempted because it can be
// DNS-hijacked (RFC 8252 §7.3 reasoning); a development boot binding
// loopback uses the IP literal directly.
//
// [WithAllowLocalhostLoopback] additionally admits the textual
// "localhost" host over http. It is the only way to run a WebAuthn
// deployment locally without TLS: a Relying Party ID must be a domain
// and browsers reject an IP literal for it, so an http issuer on
// 127.0.0.1 has no valid RP ID to pair with.
//
// The rule is shared with the metadata-build pass so the option site and
// the wire document cannot disagree. Malformed values fail [New] rather
// than the first request; the check runs during [New]'s validation pass
// rather than at this call site, so it sees the opt-in whichever order
// the options were given in.
// Stable since v1.0.
func WithIssuer(issuer string) Option {
	return optionFunc(func(c *config) error {
		if issuer == "" {
			return ErrIssuerRequired
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
// Stable since v1.0.
func WithStore(s store.Store) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(s) {
			return ErrStoreRequired
		}
		c.store = s
		return nil
	})
}

// WithUserStore replaces the source of end-user records the OP reads claims
// from, leaving every other substore of the [store.Store] given to [WithStore]
// exactly as it is.
//
// Projecting an application's own users table onto OIDC is the ordinary case,
// and this is the seam for it: implement [store.UserStore] over whatever
// schema already exists and pass it here. Without the option the same effect
// requires a wrapper type that shadows Users() on the backend store, which is
// easy to get subtly wrong — a wrapper that embeds the [store.Store] interface
// instead of the concrete backend silently drops every optional capability the
// backend implemented, and the features built on those capabilities disable
// themselves. Nothing is wrapped here, so nothing can be dropped.
//
// The store is read-only from the library's perspective: it supplies the
// claims released through the ID Token and /userinfo, projected by the scopes
// the grant carries. Authentication is a separate wiring — [PrimaryPassword]
// carries its own store — and the two are meant to be the same records. [New]
// warns when they are not, because a login that resolves a subject from one
// set of records and then serves claims from another fails silently.
//
// Omitting the option leaves claim reads on [store.Store.Users].
// Stable since v1.0.
func WithUserStore(s store.UserStore) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(s) {
			return ErrUserStoreRequired
		}
		c.userStore = s
		return nil
	})
}

// WithKeyset registers the OP signing keys. The first entry is the active
// signer; subsequent entries are kept in JWKS so RPs can verify tokens
// issued under previous keys during a rotation window.
// Every entry MUST be ECDSA on curve P-256: the OP signs with ES256 and
// only ES256, permanently. Supplying any other key shape causes [New] to
// fail at construction time. See [SigningKey] for the rationale.
// Stable since v1.0.
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
// Stable since v1.0.
func WithClock(clock Clock) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(clock) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithClock received nil Clock",
			}
		}
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
// Stable since v1.0.
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
// did not split the streams.
//
// The return is never nil in a configured [Provider]: when neither
// option was supplied, [config.applyDefaults] has already installed a
// logger over the internal discard handler, so the emitter is a live
// [audit.Slog] whose handler reports itself disabled rather than
// [audit.Discard]. The two are equivalent at the sink — no record is
// written either way — and the emitter skips flattening an event whose
// handler is disabled, so the silent default costs no per-event work.
// The nil branch remains for a config that has not been through the
// defaults pass.
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
// Every metric carries the constant label issuer="<the value given to
// [WithIssuer]>". Several Providers may therefore share one registry:
// their series are distinguished by that label rather than by the
// metric name. Two Providers configured with the same issuer on the
// same registry remain a collision and fail [New].
//
// The registry's lifecycle is the embedder's responsibility — the
// library calls Unregister only to undo a partially completed
// registration when [New] fails, never on a live collector.
//
// Stable since v1.0.
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
// Stable since v1.0.
func WithJWKSRotationActive(predicate func() bool) Option {
	return optionFunc(func(c *config) error {
		c.jwksRotationActive = predicate
		return nil
	})
}

// WithAuditLogger injects the [*slog.Logger] the library routes
// audit events on. Audit records carry the slog attribute
// "audit"="true" so log shippers can split them onto a dedicated
// retention bucket without parsing the [AuditEvent] name — the
// attribute keeps the routing decision independent of the event
// vocabulary, which may grow in a minor release.
// If unset, the [Provider] uses the operational logger from
// [WithLogger]; if neither is configured, audit records are dropped.
//
// The handler is invoked synchronously, on the request goroutine that
// produced the event, and the OP waits for it to return before the
// response is written. Handlers MUST therefore be non-blocking:
// serialise the record and hand it to a buffered channel / batching
// worker, and never perform a network round trip inline. A handler
// that ships each record to long-retention storage (S3, BigQuery, an
// ELK index, …) — which embedders SHOULD do, so audit lines outlive
// the operational stream — belongs behind that asynchronous hop, not
// on the emission path: a slow or stalled sink otherwise adds its
// latency to every token, authorize and logout request. Handlers MUST
// also be safe for concurrent use by multiple goroutines.
//
// The OP does not retry, and it recovers from a panicking handler
// rather than failing the request; a dropped record is the failure
// mode a broken sink produces.
//
// The supplied logger's handler is wrapped with the same redaction
// hook as [WithLogger] so a regression that puts a token into an
// [AuditEvent] extras map cannot escape the wire posture.
// Stable since v1.0.
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
// The supplied prefix MUST be a clean absolute request path beginning with
// "/" and MUST NOT contain a query, fragment, wildcard, percent-encoding, or
// trailing slash. Empty values reject; the empty-prefix case (mounting at
// root) is supported by passing "/" explicitly.
// Stable since v1.0.
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
// Stable since v1.0.
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
// The grants that own a dedicated option — [WithCIBA] and
// [WithDeviceCodeGrant], which also wire the collaborators those
// grants need — compose on top of this list rather than competing
// with it. Enabling one of them adds its grant to whatever this
// option selected, in either option order, and naming the same grant
// here as well is a no-op rather than a duplicate. A deployment that
// wants a grant this option lists to be the ONLY way into the token
// endpoint therefore must not also call the dedicated option.
//
// Stable since v1.0.
func WithGrants(grants ...grant.Type) Option {
	return optionFunc(func(c *config) error {
		// Reject a second call rather than silently replacing the first
		// set: a caller composing option slices from several helpers must
		// not have an earlier WithGrants (e.g. refresh_token + device_code)
		// vanish under a later one. Mirrors WithProfile /
		// WithDiscoveryMetadata, whose duplicate calls also error.
		if c.grantsSet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithGrants may be called at most once",
			}
		}
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
		c.grantsSet = true
		return nil
	})
}

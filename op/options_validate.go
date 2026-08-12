package op

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/protectedresource"
	"github.com/libraz/go-oidc-provider/internal/proxy"
	"github.com/libraz/go-oidc-provider/internal/registrationendpoint"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
)

// validate checks that required fields are set and that combinations of
// options are internally consistent. It runs after applyDefaults so that
// "missing required" errors are not masked by a default value.
func (c *config) validate() error {
	if err := c.validateRequired(); err != nil {
		return err
	}
	if err := c.validateNetwork(); err != nil {
		return err
	}
	for _, fn := range []func() error{
		c.validateScopes,
		c.validateProfiles,
		c.validateFeatureActivation,
		c.validateRegistration,
		c.validateAuthenticators,
		c.validateInteractions,
		c.validateLocales,
		c.validateFirstPartyClients,
		c.validateOpenIDScopeOptional,
		c.validateStrictOfflineAccess,
		c.validateLoginFlow,
		c.validateAccessTokenFormat,
		c.validateAccessTokenRevocation,
		c.validateDeviceCodeGrant,
		c.validateCIBAGrant,
		c.validateEncryptionKeyset,
		c.validateStaticClients,
		c.validateStoreCapabilities,
		c.validateProtectedResources,
		c.validateEndpointRouting,
	} {
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}

// validateRequired enforces the four-argument boot contract (Issuer +
// Store + Keyset + cookie keys) plus keyset shape. Split out so
// [validate] stays under the gocognit ceiling and so a future "what
// MUST be set" check has one obvious home.
func (c *config) validateRequired() error {
	if c.issuer == "" {
		return ErrIssuerRequired
	}
	// Deferred from WithIssuer: the localhost carve-out depends on an
	// opt-in that may have been registered by a later option.
	if err := discovery.ValidateIssuerWithLocalhostName(c.issuer, c.allowLocalhostLoopback); err != nil {
		return ErrIssuerInvalid
	}
	if isNilLike(c.store) {
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
	return validateCookieKeysRequired(c.grants, c.cookieKeys)
}

// validateNetwork wraps the trusted-proxy and CORS-origin parsers.
// They share a single shape — parser returns an error, validate wraps
// it as a configuration error — so collapsing them here keeps the
// option-name strings together with the wrapper that surfaces them.
func (c *config) validateNetwork() error {
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
	return nil
}

type configuredEndpoint struct {
	name  string
	value string
}

type routeReservation struct {
	name   string
	path   string
	prefix bool
}

// validateEndpointRouting rejects paths that net/http cannot route
// predictably and detects conflicts in the route set that this exact
// configuration enables. The check runs before buildRouter so an embedder
// always receives a configuration error instead of an http.ServeMux panic.
func (c *config) validateEndpointRouting() error {
	if err := c.validateConfiguredRoutePaths(); err != nil {
		return err
	}
	return validateRouteCollisions(c.activeRouteReservations())
}

func (c *config) validateConfiguredRoutePaths() error {
	if err := validateConfiguredRoutePath("WithMountPrefix", c.mountPrefix, true); err != nil {
		return err
	}
	if p := issuerPath(c.issuer); p != "" {
		if err := validateConfiguredRoutePath("WithIssuer path", p, false); err != nil {
			return err
		}
	}
	for _, endpoint := range c.configuredEndpoints() {
		if err := validateConfiguredRoutePath("WithEndpoints."+endpoint.name, endpoint.value, false); err != nil {
			return err
		}
	}
	if c.spaUISet {
		if err := validateConfiguredRoutePath("WithSPAUI.LoginMount", c.spaUI.LoginMount, false); err != nil {
			return err
		}
	}

	return nil
}

func validateRouteCollisions(routes []routeReservation) error {
	for i := range routes {
		for j := i + 1; j < len(routes); j++ {
			if routesConflict(routes[i], routes[j]) {
				return &Error{
					Code: codeConfiguration,
					Description: "route collision between " + routes[i].name + " (" + routes[i].path +
						") and " + routes[j].name + " (" + routes[j].path + ")",
				}
			}
		}
	}
	return nil
}

func (c *config) configuredEndpoints() []configuredEndpoint {
	return []configuredEndpoint{
		{name: "Discovery", value: c.endpoints.Discovery},
		{name: "JWKS", value: c.endpoints.JWKS},
		{name: "Authorize", value: c.endpoints.Authorize},
		{name: "Token", value: c.endpoints.Token},
		{name: "UserInfo", value: c.endpoints.UserInfo},
		{name: "EndSession", value: c.endpoints.EndSession},
		{name: "Introspect", value: c.endpoints.Introspect},
		{name: "Revoke", value: c.endpoints.Revoke},
		{name: "PAR", value: c.endpoints.PAR},
		{name: "Interaction", value: c.endpoints.Interaction},
		{name: "Session", value: c.endpoints.Session},
		{name: "Register", value: c.endpoints.Register},
		{name: "DeviceAuthorization", value: c.endpoints.DeviceAuthorization},
		{name: "Backchannel", value: c.endpoints.Backchannel},
		{name: "GrantManagement", value: c.endpoints.GrantManagement},
	}
}

func validateConfiguredRoutePath(name, value string, allowRoot bool) error {
	description := name + " must be a clean absolute path without query, fragment, wildcard, or percent-encoding"
	if value == "" || !strings.HasPrefix(value, "/") {
		return &Error{Code: codeConfiguration, Description: description}
	}
	if (!allowRoot && value == "/") ||
		strings.ContainsAny(value, "?#{}%\\") ||
		path.Clean(value) != value {
		return &Error{Code: codeConfiguration, Description: description}
	}
	for _, r := range value {
		if r < ' ' || r == 0x7f {
			return &Error{Code: codeConfiguration, Description: description}
		}
	}
	u, err := url.ParseRequestURI(value)
	if err != nil || u.IsAbs() || u.Host != "" || u.RawQuery != "" || u.Fragment != "" {
		return &Error{Code: codeConfiguration, Description: description, Cause: err}
	}
	return nil
}

func (c *config) activeRouteReservations() []routeReservation {
	routes := []routeReservation{
		{name: "WithEndpoints.Discovery", path: discoveryEndpointPath(c)},
		{name: "WithEndpoints.JWKS", path: protocolEndpointPath(c, c.endpoints.JWKS)},
		{name: "WithEndpoints.Token", path: protocolEndpointPath(c, c.endpoints.Token)},
		{name: "WithEndpoints.UserInfo", path: protocolEndpointPath(c, c.endpoints.UserInfo)},
	}
	authorizeEnabled := grantsRequireAuthorizeEndpoint(c.grants)
	if authorizeEnabled {
		routes = append(routes,
			routeReservation{name: "WithEndpoints.Authorize", path: protocolEndpointPath(c, c.endpoints.Authorize)},
			routeReservation{name: "WithEndpoints.EndSession", path: protocolEndpointPath(c, c.endpoints.EndSession)},
			// Session is a public endpoint namespace reserved for the
			// interaction API. Reserve it even while its individual
			// operations remain owned by the interaction handler so an
			// override cannot be shadowed by another endpoint.
			routeReservation{name: "WithEndpoints.Session", path: protocolEndpointPath(c, c.endpoints.Session), prefix: true},
		)
		if c.spaUISet {
			routes = append(routes, routeReservation{
				name: "WithSPAUI.LoginMount", path: c.spaUI.LoginMount, prefix: true,
			})
		} else {
			routes = append(routes, routeReservation{
				name: "WithEndpoints.Interaction",
				path: protocolEndpointPath(c, c.endpoints.Interaction), prefix: true,
			})
		}
	}
	if featureEnabled(c.features, feature.PAR) {
		routes = append(routes, routeReservation{name: "WithEndpoints.PAR", path: protocolEndpointPath(c, c.endpoints.PAR)})
	}
	if featureEnabled(c.features, feature.Introspect) {
		routes = append(routes, routeReservation{name: "WithEndpoints.Introspect", path: protocolEndpointPath(c, c.endpoints.Introspect)})
	}
	if featureEnabled(c.features, feature.Revoke) {
		routes = append(routes, routeReservation{name: "WithEndpoints.Revoke", path: protocolEndpointPath(c, c.endpoints.Revoke)})
	}
	if c.dcr != nil {
		routes = append(routes, routeReservation{name: "WithEndpoints.Register", path: protocolEndpointPath(c, c.endpoints.Register), prefix: true})
	}
	if c.deviceCodeGrantConfigured() {
		routes = append(routes, routeReservation{name: "WithEndpoints.DeviceAuthorization", path: protocolEndpointPath(c, c.endpoints.DeviceAuthorization)})
	}
	if c.cibaGrantConfigured() {
		routes = append(routes, routeReservation{name: "WithEndpoints.Backchannel", path: protocolEndpointPath(c, c.endpoints.Backchannel)})
	}
	if c.grantManagementEnabled {
		routes = append(routes, routeReservation{name: "WithEndpoints.GrantManagement", path: protocolEndpointPath(c, c.endpoints.GrantManagement), prefix: true})
	}
	for i := range c.protectedResources {
		routes = append(routes, routeReservation{
			name: "WithProtectedResources[" + strconv.Itoa(i) + "]",
			path: protectedresource.WellKnownPath(c.protectedResources[i].Resource),
		})
	}
	return routes
}

func routesConflict(a, b routeReservation) bool {
	if a.path == b.path {
		return true
	}
	return a.prefix && strings.HasPrefix(b.path, a.path+"/") ||
		b.prefix && strings.HasPrefix(a.path, b.path+"/")
}

// validateFirstPartyClients enforces the cross-cutting invariants
// between [WithFirstPartyClients] and the static-client surface:
//   - every advertised client_id MUST appear in [config.staticClients]
//     after every option has been applied (the option site cannot
//     enforce this because the two options are order-independent);
//   - no FAPI 2.0 profile MAY be active simultaneously. FAPI 2.0
//     forbids auto-consent because the profile mandates explicit
//     user authorization for every protected resource.
func (c *config) validateFirstPartyClients() error {
	if len(c.firstPartyClients) == 0 {
		return nil
	}
	for _, p := range c.profiles {
		if isFAPI2Profile(p) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithFirstPartyClients is incompatible with FAPI 2.0 profile " + p.String(),
			}
		}
	}
	known := make(map[string]struct{}, len(c.staticClients))
	for _, sc := range c.staticClients {
		known[sc.ID] = struct{}{}
	}
	for _, id := range c.firstPartyClients {
		if _, ok := known[id]; !ok {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithFirstPartyClients: unknown client_id " + id,
			}
		}
	}
	return nil
}

// validateStaticClients runs the same structural validator DCR drives
// on inbound /register payloads against every embedder-supplied static
// seed. The check closes the gap where an invalid redirect_uri /
// backchannel_logout_uri / grant_type / response_type / subject_type
// value persisted by [WithStaticClients] would only surface at the
// first request that touched the offending field; running the
// validator at construction time forces the misconfiguration to land
// at op.New so embedders see it during boot.
//
// Scope catalogue checks are intentionally skipped — the embedder
// authoritatively names the scopes their static clients carry, and
// the runtime intersection at /authorize already rejects unregistered
// values.
//
// The seam between this method and the registration-endpoint package
// flows through a thin shim function so internal/* never imports op/
// while op/ continues to own the wire-error wrapping.
func (c *config) validateStaticClients() error {
	if len(c.staticClients) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(c.staticClients))
	opts := registrationendpoint.StaticClientValidationOptions{
		AllowedGrantTypes:                    c.staticClientAllowedGrantTypes(),
		AllowedResponseTypes:                 c.staticClientAllowedResponseTypes(),
		AllowedClientAuthMethods:             c.profileAllowedAuthMethodNames(),
		PairwiseEnabled:                      c.pairwiseEnabled(),
		AllowLocalhostLoopback:               c.allowLocalhostLoopback,
		AllowInsecureBackchannelLogoutForDev: c.allowInsecureBackchannelLogoutForDev,
		JWEPolicy:                            c.jwePolicy(),
	}
	for i := range c.staticClients {
		seed := c.staticClients[i]
		if _, duplicate := seen[seed.ID]; duplicate {
			return &Error{
				Code: codeConfiguration,
				Description: "WithStaticClients[" + strconv.Itoa(i) +
					"]: duplicate client_id " + seed.ID,
			}
		}
		seen[seed.ID] = struct{}{}
		if err := c.validateStaticClientSecretFormat(i, seed); err != nil {
			return err
		}
		if err := registrationendpoint.ValidateStaticClient(seed, opts); err != nil {
			return &Error{
				Code: codeConfiguration,
				Description: "WithStaticClients[" + strconv.Itoa(i) +
					"] (client_id " + seed.ID + "): " + err.Error(),
				Cause: err,
			}
		}
	}
	return nil
}

// validateStaticClientSecretFormat enforces the promise
// [WithHighEntropyClientSecrets] is built on: with that option set,
// no client may be stored under the password KDF.
//
// The check runs against the projected record rather than the seed's
// input fields, so it catches a hash that arrived any way at all —
// [ConfidentialClient.Secret], a pre-computed [ConfidentialClient.SecretHash]
// produced by the wrong helper, or a builder added later. Refusing at
// construction is the point: the alternative is an OP that boots, runs,
// and quietly answers an unknown client_id in microseconds while
// answering this one in ninety milliseconds.
func (c *config) validateStaticClientSecretFormat(index int, seed store.Client) error {
	if !c.highEntropyClientSecrets || seed.SecretHash == "" {
		return nil
	}
	if clientauth.IsHighEntropyEncoding(seed.SecretHash) {
		return nil
	}
	return &Error{
		Code: codeConfiguration,
		Description: "WithStaticClients[" + strconv.Itoa(index) +
			"] (client_id " + seed.ID + "): WithHighEntropyClientSecrets requires a secret " +
			"provisioned through NewClientSecret or HashHighEntropyClientSecret; " +
			"ConfidentialClient.Secret hashes with Argon2id, which this option does not admit",
	}
}

// staticClientAllowedGrantTypes returns the grant_type whitelist the
// static-client validator runs against. Static clients are trusted
// configuration: the embedder authoritatively names the grants their
// clients participate in. The validator therefore admits every
// grant_type the library implements plus any custom grant the embedder
// wired through [WithCustomGrant], so a seed listing
// `["authorization_code", "refresh_token"]` flows through cleanly even
// when the OP only mounts the CIBA grant at runtime — the runtime
// dispatcher rejects an unsupported grant on the wire side, and the
// static-client gate stays focused on structural rules (malformed
// values, unknown wire form).
//
// The library half comes from [builtinGrantTypeWireList] rather than a
// second transcription of the same wires: a grant added to the library
// is admitted here with no parallel edit. Membership is unconditional,
// independent of which grants this deployment enabled — a seed naming
// a grant the OP does not mount still receives unsupported_grant_type
// at /token, which is the surface where "configured but not enabled"
// belongs.
func (c *config) staticClientAllowedGrantTypes() []string {
	allowed := builtinGrantTypeWireList()
	for _, h := range c.customGrants {
		if h == nil {
			continue
		}
		name := h.Name()
		if name != "" && !slices.Contains(allowed, name) {
			allowed = append(allowed, name)
		}
	}
	return allowed
}

// staticClientAllowedResponseTypes returns the response_type whitelist
// the static-client validator runs against. v1.0 ships with "code"
// only at the authorization endpoint, so the helper hard-codes the
// single value.
func (c *config) staticClientAllowedResponseTypes() []string {
	return []string{"code"}
}

// validateOpenIDScopeOptional rejects the combination of
// [WithOpenIDScopeOptional] and any active FAPI 2.0 profile. FAPI 2.0
// Baseline / Message Signing both presuppose OpenID Connect semantics
// (id_token-bound state-or-nonce, scope-driven refresh gating); the
// profile MUSTs lose meaning without "openid" in scope, so the
// combination is a misconfiguration we surface at construction time
// rather than letting the runtime emit subtly-wrong responses.
func (c *config) validateOpenIDScopeOptional() error {
	if !c.openIDScopeOptional {
		return nil
	}
	for _, p := range c.profiles {
		if isFAPI2Profile(p) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithOpenIDScopeOptional is incompatible with FAPI 2.0 profile " + p.String(),
			}
		}
	}
	return nil
}

// validateStrictOfflineAccess rejects the combination of
// [WithStrictOfflineAccess] and [WithOpenIDScopeOptional]. The strict
// reading of OIDC Core 1.0 §11 only has meaning for OIDC requests;
// admitting it on a deployment that also accepts plain OAuth 2.0
// /authorize requests would silently disable refresh token issuance
// for every non-OIDC client. Surface the misconfiguration at startup
// rather than letting it manifest as missing refresh tokens at /token.
func (c *config) validateStrictOfflineAccess() error {
	if c.strictOfflineAccess && c.openIDScopeOptional {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithStrictOfflineAccess is incompatible with WithOpenIDScopeOptional",
		}
	}
	return nil
}

// validateAccessTokenFormat enforces the fail-fast contract: when the
// global format or any per-audience override selects
// [AccessTokenFormatOpaque], the configured [Store] MUST expose a
// non-nil [store.OpaqueAccessTokenStore]. Embedders who request
// opaque tokens with no place to persist them get a build-time error
// rather than a runtime crash on the first issuance.
//
// The check intentionally walks the per-audience map even when the
// global default is [AccessTokenFormatJWT]: a single opaque entry
// pointed at one resource is enough to require the substore. The
// store value is read from [config.store] which [validateRequired]
// already ensured is non-nil.
func (c *config) validateAccessTokenFormat() error {
	needsOpaque := c.accessTokenFormat == store.AccessTokenFormatOpaque
	if !needsOpaque {
		for _, f := range c.accessTokenFormatPerAudience {
			if f == store.AccessTokenFormatOpaque {
				needsOpaque = true
				break
			}
		}
	}
	if !needsOpaque {
		return nil
	}
	if c.store.OpaqueAccessTokens() == nil {
		return &Error{
			Code: codeConfiguration,
			Description: "op.WithAccessTokenFormat(AccessTokenFormatOpaque) " +
				"requires Store.OpaqueAccessTokens() to be non-nil",
		}
	}
	return nil
}

// validateAccessTokenRevocation enforces the fail-fast contract on
// the JWT access-token revocation strategy:
//
//   - Out-of-range enum values are rejected at construction time so
//     a regression in the option-layer validator surfaces at startup.
//   - Under any FAPI profile, [store.RevocationStrategyNone] is
//     rejected because FAPI 2.0 Security Profile §5.3.2.2 mandates
//     server-side access-token revocation. Embedders pin
//     [store.RevocationStrategyGrantTombstone] (default) or
//     [store.RevocationStrategyJTIRegistry] under those profiles.
//
// The default value (zero) is [store.RevocationStrategyGrantTombstone],
// which is FAPI-compliant; embedders that never call
// [WithAccessTokenRevocationStrategy] therefore pass this check on
// every profile.
func (c *config) validateAccessTokenRevocation() error {
	if !c.atRevocation.IsValid() {
		return &Error{
			Code: codeConfiguration,
			Description: "WithAccessTokenRevocationStrategy received an " +
				"unknown AccessTokenRevocationStrategy value",
		}
	}
	if c.atRevocation != store.RevocationStrategyNone {
		if c.atRevocation == store.RevocationStrategyGrantTombstone &&
			c.store.GrantRevocations() == nil {
			return &Error{
				Code: codeConfiguration,
				Description: "RevocationStrategyGrantTombstone requires " +
					"Store.GrantRevocations() to be non-nil",
			}
		}
		if c.atRevocation == store.RevocationStrategyJTIRegistry &&
			c.store.AccessTokens() == nil {
			return &Error{
				Code: codeConfiguration,
				Description: "RevocationStrategyJTIRegistry requires " +
					"Store.AccessTokens() to be non-nil",
			}
		}
		return nil
	}
	for _, p := range c.profiles {
		if profile.RequiresAccessTokenRevocation(p) {
			return &Error{
				Code: codeConfiguration,
				Description: "FAPI 2.0 Security Profile §5.3.2.2 requires " +
					"access-token revocation; RevocationStrategyNone is " +
					"rejected under profile " + p.String() +
					" — use RevocationStrategyGrantTombstone (default) or " +
					"RevocationStrategyJTIRegistry",
			}
		}
	}
	return nil
}

// validateLoginFlow enforces the cross-cutting invariants between
// [WithLoginFlow] and the legacy authenticator surface:
//   - [WithLoginFlow] is mutually exclusive with [WithAuthenticators].
//     The two surfaces drive the orchestrator through different code
//     paths; combining them invites silent misordering. Reject at the
//     option-validation phase so the embedder sees a clear error
//     before the orchestrator construction returns its own (less
//     specific) refusal.
//   - When [WithLoginFlow] is present, its [op.ExternalStep]
//     KindLabel values MUST be user-defined (dotted prefix) so they
//     cannot collide with the built-in [StepKind] reserved
//     identifiers.
//
// The compiler-level checks (duplicate StepKind across rules, nil
// Authenticator inside ExternalStep, …) live in
// [authn.CompileLoginFlow]; this method handles the option-layer
// shape.
func (c *config) validateLoginFlow() error {
	if !c.loginFlowSet {
		return nil
	}
	if len(c.authenticators) > 0 {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithLoginFlow is mutually exclusive with WithAuthenticators",
		}
	}
	if err := validateLoginFlowDependencies(c.loginFlow); err != nil {
		return err
	}
	if err := validateLoginFlowKinds(c.loginFlow); err != nil {
		return err
	}
	return nil
}

// validateLoginFlowKinds asserts that every [ExternalStep] KindLabel
// participating in the LoginFlow uses a dotted prefix (so
// [StepKind.IsUserDefined] returns true). The check is conservative —
// built-in [Step] values declare their own kinds at the type level,
// only [ExternalStep] gives the embedder a free choice — but
// surfacing a clear error at New spares the embedder from finding
// out at the first authentication request.
func validateLoginFlowKinds(flow LoginFlow) error {
	if ext, ok := flow.Primary.(ExternalStep); ok {
		if err := checkExternalStepKind("Primary", ext); err != nil {
			return err
		}
	}
	for i, r := range flow.Rules {
		if ext, ok := r.Then.(ExternalStep); ok {
			if err := checkExternalStepKind("Rules["+strconv.Itoa(i)+"].Then", ext); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkExternalStepKind enforces the non-empty and user-defined
// invariants on an [ExternalStep] declaration. The label string is
// inlined into the error message so the embedder can locate the
// offending entry.
func checkExternalStepKind(where string, ext ExternalStep) error {
	if isNilLike(ext.Authenticator) {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithLoginFlow: " + where + ".Authenticator must not be nil",
		}
	}
	if ext.KindLabel == "" {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithLoginFlow: " + where + ".KindLabel must not be empty",
		}
	}
	if ext.KindLabel.IsBuiltin() {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithLoginFlow: " + where + ".KindLabel must not collide with a built-in StepKind (" + ext.KindLabel.String() + ")",
		}
	}
	if !ext.KindLabel.IsUserDefined() {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithLoginFlow: " + where + ".KindLabel must use a dotted prefix (e.g., \"myorg.factor\") so it cannot collide with future built-ins",
		}
	}
	return nil
}

// isFAPI2Profile reports whether p is one of the FAPI 2.0 family
// profiles. Centralising the check lets future first-party / FAPI
// interactions extend the predicate without scattering profile
// enumerations across the option layer.
// hasFAPI2Profile reports whether any profile the embedder declared is
// one of the FAPI 2.0 profiles. Callers that need the profile-driven
// default rather than the validation verdict use this, so the two stay
// derived from the same predicate.
func (c *config) hasFAPI2Profile() bool {
	if c == nil {
		return false
	}
	for _, p := range c.profiles {
		if isFAPI2Profile(p) {
			return true
		}
	}
	return false
}

func isFAPI2Profile(p profile.Profile) bool {
	switch p {
	case profile.FAPI2Baseline, profile.FAPI2MessageSigning:
		return true
	case profile.Baseline, profile.FAPICIBA:
		return false
	}
	return false
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

// validateProfiles enforces the MUST clauses each enabled
// [profile.Profile] inherits from its source spec. The check runs
// after [config.applyDefaults] so default-on features are visible to
// the lookup, and after [config.validateScopes] so scope-shape errors
// surface first.
// The rule is one-directional and add-only: a profile MUST NOT be
// relaxed by a later option, but stricter-than-profile configurations
// are permitted (an embedder may layer additional [WithFeature] calls
// on top). The library therefore only fails [New] when a required
// flag is missing — never when an extra flag is present. The
// add-only invariant is the defensive twin of the auto-enable
// contract documented on [WithProfile]: WithProfile only appends to
// [config.features] and no public [Option] removes a feature, so a
// missing required feature can only originate from an internal
// refactor that violates the contract. The check here surfaces that
// regression as a configuration_error rather than letting the
// runtime emit a profile-non-conformant response.
func (c *config) validateProfiles() error {
	if len(c.profiles) == 0 {
		return nil
	}
	enabled := make(map[feature.Flag]struct{}, len(c.features))
	for _, f := range c.features {
		enabled[f] = struct{}{}
	}
	for _, p := range c.profiles {
		if err := c.validateProfile(p, enabled); err != nil {
			return err
		}
	}
	return nil
}

// validateProfile checks one [profile.Profile] against the enabled
// feature set and the rest of the config. The per-profile loop is
// extracted from [config.validateProfiles] so the outer iteration
// stays under the gocognit budget as additional MUST clauses land
// (Access Token TTL, refresh grace, client auth method, …).
func (c *config) validateProfile(p profile.Profile, enabled map[feature.Flag]struct{}) error {
	for _, req := range profile.RequiredFeatures(p) {
		if _, ok := enabled[req]; ok {
			continue
		}
		return &Error{
			Code: codeConfiguration,
			Description: "WithProfile " + p.String() +
				" requires WithFeature(" + req.String() + ")",
		}
	}
	for _, anyOf := range profile.RequiredAnyOf(p) {
		if anyEnabled(enabled, anyOf) {
			continue
		}
		return &Error{
			Code: codeConfiguration,
			Description: "WithProfile " + p.String() +
				" requires at least one of WithFeature(" +
				strings.Join(featureFlagNames(anyOf), ") or WithFeature(") + ")",
		}
	}
	if err := c.validateProfileGrants(p); err != nil {
		return err
	}
	if maxTTL := profile.MaxAccessTokenTTL(p); maxTTL > 0 && c.accessTokenTTL > maxTTL {
		return &Error{
			Code: codeConfiguration,
			Description: "WithProfile " + p.String() +
				" caps WithAccessTokenTTL at " + maxTTL.String() +
				"; got " + c.accessTokenTTL.String(),
		}
	}
	if profileForcesDPoPNonce(p) && hasDPoPFeature(enabled) && c.dpopNonces == nil {
		return &Error{
			Code: codeConfiguration,
			Description: "WithProfile " + p.String() +
				" requires WithDPoPNonceSource when WithFeature(DPoP) is active",
		}
	}
	if isFAPI2Profile(p) && c.refreshGracePeriodSet && !c.refreshGracePeriodIsZero {
		return &Error{
			Code: codeConfiguration,
			Description: "WithProfile " + p.String() +
				" requires WithRefreshGracePeriod(0); FAPI 2.0 §3.1.7 " +
				"forbids a replay-tolerant grace window for a replayed " +
				"refresh token under this profile",
		}
	}
	return nil
}

// validateProfileGrants rejects a profile whose [profile.RequiredGrants]
// set is not covered by the resolved grant set. The check runs after
// [config.applyDefaults], so the implicit authorization_code +
// refresh_token pair is visible here.
//
// Unlike the feature constraints above, a missing grant is never
// filled in for the embedder. Activating a grant pulls in
// collaborators only the deployment can provide — the CIBA grant
// needs a [store.CIBARequestStore] substore and a [HintResolver] —
// so auto-enabling would swap a precise "the profile you declared
// needs this grant" message for a substore complaint about a grant
// nobody requested. The error therefore names the option that
// activates the grant rather than silently activating it.
func (c *config) validateProfileGrants(p profile.Profile) error {
	for _, want := range profile.RequiredGrants(p) {
		if slices.Contains(c.grants, want) {
			continue
		}
		return &Error{
			Code: codeConfiguration,
			Description: "WithProfile " + p.String() +
				" requires the " + want.String() + " grant; enable it with " +
				grantActivationOption(want),
		}
	}
	return nil
}

// grantActivationOption names the [Option] an embedder calls to
// activate g. Grants that own a dedicated option report only that
// option, never [WithGrants]: listing the grant type alone leaves the
// grant's collaborators unwired and lands the embedder on a second
// construction error instead of a working OP.
func grantActivationOption(g grant.Type) string {
	switch g {
	case grant.CIBA:
		return "WithCIBA(WithCIBAHintResolver(...))"
	case grant.DeviceCode:
		return "WithDeviceCodeGrant()"
	case grant.AuthorizationCode, grant.ClientCredentials, grant.RefreshToken:
		return "WithGrants(..., grant." + g.String() + ")"
	}
	return "WithGrants"
}

// profileForcesDPoPNonce reports whether p mandates the RFC 9449 §8/§9
// nonce challenge flow. FAPI 2.0 Message Signing §5.3.4 requires the
// AS to issue a server-side DPoP nonce; FAPI-CIBA inherits the same
// posture by reference (FAPI-CIBA-ID1 §5).
func profileForcesDPoPNonce(p profile.Profile) bool {
	switch p {
	case profile.FAPI2MessageSigning, profile.FAPICIBA:
		return true
	case profile.Baseline, profile.FAPI2Baseline:
		return false
	}
	return false
}

// hasDPoPFeature reports whether [feature.DPoP] is in have. The check
// is split out so [validateProfile] reads as a guarded clause rather
// than poking the map directly.
func hasDPoPFeature(have map[feature.Flag]struct{}) bool {
	_, ok := have[feature.DPoP]
	return ok
}

// anyEnabled reports whether any flag in want is present in have. The
// helper exists so [config.validateProfiles] reads as the disjunctive
// rule from the spec rather than an inlined map lookup loop.
func anyEnabled(have map[feature.Flag]struct{}, want []feature.Flag) bool {
	for _, f := range want {
		if _, ok := have[f]; ok {
			return true
		}
	}
	return false
}

// featureFlagNames returns the canonical string identifier of every
// flag in fs in the same order, suitable for joining into a
// human-readable error message. Centralising the conversion keeps
// the formatting consistent across [config.validateProfiles] and any
// future profile-aware diagnostics.
func featureFlagNames(fs []feature.Flag) []string {
	names := make([]string, len(fs))
	for i, f := range fs {
		names[i] = f.String()
	}
	return names
}

// validateAuthenticators enforces uniqueness of [Authenticator.Type]
// across the registered set. The orchestrator layers further rules on
// top — minimum cardinality, capability checks against the risk
// engine — but the bare uniqueness invariant is owned here so
// duplicate registrations surface at [New] rather than the first
// chain run.
func (c *config) validateAuthenticators() error {
	if len(c.authenticators) == 0 {
		return c.validateAuthenticatorsRequired()
	}
	seen := make(map[FactorType]struct{}, len(c.authenticators))
	for i, a := range c.authenticators {
		if isNilLike(a) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAuthenticators received nil Authenticator at position " + strconv.Itoa(i),
			}
		}
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

// validateAuthenticatorsRequired covers the zero-authenticator case.
//
// Registering none is legitimate for a deployment that runs only
// non-interactive grants — client_credentials, or refresh_token against
// a code some other component issued. Those never reach the chain
// runner, and [New] deliberately builds no orchestrator for them.
//
// The authorization_code grant is the opposite: every /authorize request
// that is not resumed from a live session has to run the chain, so an OP
// that offers the grant without a way to authenticate anyone cannot
// serve a single one. Left unchecked the failure lands on the first real
// authorization request as a server_error, which reads as an OP fault to
// the relying party and gives the operator nothing to act on. This is
// exactly the class the boot contract exists to exclude, so it is
// refused at construction alongside the other required wiring.
//
// [WithLoginFlow] satisfies the requirement in place of
// [WithAuthenticators]: it declares the same chain in compiled form.
func (c *config) validateAuthenticatorsRequired() error {
	if c.loginFlowSet {
		return nil
	}
	for _, g := range c.grants {
		if g != grant.AuthorizationCode {
			continue
		}
		return &Error{
			Code: codeConfiguration,
			Description: "the authorization_code grant is enabled but no Authenticator is registered; " +
				"supply WithAuthenticators or WithLoginFlow, or drop the grant",
		}
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
	for i, ix := range c.interactions {
		if isNilLike(ix) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithInteractions received nil Interaction at position " + strconv.Itoa(i),
			}
		}
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

// validateRegistration enforces the cross-cutting invariants of
// [WithDynamicRegistration] and owns the [feature.DynamicRegistration]
// flag: the option records only the configuration, and the flag is
// derived here once every option has been applied.
//
// Deriving it here rather than inside the option is what makes the
// "flag declared twice" diagnostic order-independent. [WithFeature] is
// idempotent, so an embedder who passed the flag explicitly leaves no
// trace once the option has also set it — the duplicate would be
// visible in one call order and invisible in the other. With the
// option no longer setting the flag, a flag present alongside a
// configured [config.dcr] can only have come from [WithFeature].
func (c *config) validateRegistration() error {
	flagOn := featureEnabled(c.features, feature.DynamicRegistration)
	if c.dcr == nil {
		if flagOn {
			return &Error{
				Code:        codeConfiguration,
				Description: "feature.DynamicRegistration enabled without WithDynamicRegistration",
			}
		}
		return nil
	}
	if flagOn {
		return &Error{
			Code:        codeConfiguration,
			Description: "feature.DynamicRegistration was enabled more than once",
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
	if _, ok := resolveClientRegistry(c.store); !ok {
		return &Error{
			Code:        codeConfiguration,
			Description: "Store does not expose ClientRegistry; dynamic registration requires a client backend with write access",
		}
	}
	for _, name := range c.dcr.OpenRegistrationDefaultScopes {
		if name == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDynamicRegistration: OpenRegistrationDefaultScopes contains an empty entry",
			}
		}
		if _, ok := c.scopeIndex[name]; !ok {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDynamicRegistration: OpenRegistrationDefaultScopes contains unknown scope " + name,
			}
		}
	}
	// Every check has passed, so the configuration is complete: publish
	// the flag the router and the discovery builder read.
	c.features = append(c.features, feature.DynamicRegistration)
	return nil
}

// validateFeatureActivation rejects the feature flags that carry no
// behaviour of their own. [feature.RAR] and [feature.GrantManagement]
// are activated by the option that supplies their configuration —
// [WithAuthorizationDetailTypes] registers the type set RAR validates
// against, [WithGrantManagement] supplies the action set and mounts the
// endpoint — so a flag arriving without that option describes a
// deployment the OP cannot serve. Accepting it silently would advertise
// nothing, mount nothing, and give the embedder no way to discover why.
// [feature.DynamicRegistration] is rejected the same way, in
// [config.validateRegistration], where the store checks it shares live.
func (c *config) validateFeatureActivation() error {
	if featureEnabled(c.features, feature.RAR) && len(c.authorizationDetailTypes) == 0 {
		return &Error{
			Code:        codeConfiguration,
			Description: "feature.RAR enabled without WithAuthorizationDetailTypes",
		}
	}
	if featureEnabled(c.features, feature.GrantManagement) && !c.grantManagementEnabled {
		return &Error{
			Code:        codeConfiguration,
			Description: "feature.GrantManagement enabled without WithGrantManagement",
		}
	}
	return nil
}

// validateScopes enforces the [WithScope] invariants and builds
// [config.scopeIndex] for the post-validate config:
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

// validateStoreCapabilities enforces fail-fast detection of substores
// the configured store does not implement. Single-backend adapters
// such as oidcredis return nil from accessors that fall outside their
// scope; without this check the OP would defer the failure to the
// first request that touches the missing substore (or, for stores
// that previously panicked, crash the process). The check is keyed on
// the active grant / feature set so an embedder who runs only the
// flows their backend supports never sees a spurious rejection.
//
// Substore-specific validators (validateAccessTokenFormat,
// validateAccessTokenRevocation, validateRegistration, ...) keep
// their existing checks; this function fills the gap for the
// always-on substores (Clients, AuthorizationCodes, RefreshTokens,
// Grants) and the grant-gated specialty substores (DeviceCodes,
// CIBARequests, PushedAuthRequests).
func (c *config) validateStoreCapabilities() error {
	for _, check := range []struct {
		need    bool
		got     any
		desc    string
		because string
	}{
		{
			need:    true,
			got:     c.store.Clients(),
			desc:    "ClientStore",
			because: "every client lookup at the authorize / token endpoints requires it",
		},
		{
			need:    slices.Contains(c.grants, grant.AuthorizationCode),
			got:     c.store.AuthorizationCodes(),
			desc:    "AuthorizationCodeStore",
			because: "grant.AuthorizationCode is enabled",
		},
		{
			need:    slices.Contains(c.grants, grant.RefreshToken),
			got:     c.store.RefreshTokens(),
			desc:    "RefreshTokenStore",
			because: "grant.RefreshToken is enabled",
		},
		{
			need:    needsGrantStore(c.grants),
			got:     c.store.Grants(),
			desc:    "GrantStore",
			because: "an interactive grant that issues consent records is enabled",
		},
		{
			need:    grantsRequireAuthorizeEndpoint(c.grants),
			got:     c.store.Sessions(),
			desc:    "SessionStore",
			because: "a grant that mounts the browser authorize endpoint is enabled",
		},
		{
			need:    grantsRequireAuthorizeEndpoint(c.grants),
			got:     c.store.Interactions(),
			desc:    "InteractionStore",
			because: "a grant that mounts the browser authorize endpoint is enabled",
		},
		{
			need:    slices.Contains(c.grants, grant.DeviceCode),
			got:     c.store.DeviceCodes(),
			desc:    "DeviceCodeStore",
			because: "grant.DeviceCode is enabled",
		},
		{
			need:    slices.Contains(c.grants, grant.CIBA),
			got:     c.store.CIBARequests(),
			desc:    "CIBARequestStore",
			because: "grant.CIBA is enabled",
		},
		{
			need:    slices.Contains(c.features, feature.PAR),
			got:     c.store.PushedAuthRequests(),
			desc:    "PushedAuthRequestStore",
			because: "feature.PAR is enabled",
		},
	} {
		if !check.need {
			continue
		}
		if isNilLike(check.got) {
			return &Error{
				Code: codeConfiguration,
				Description: "Store." + check.desc + "() returned nil but " +
					check.because,
			}
		}
	}
	if err := c.validateRefreshRetryStoreCapability(); err != nil {
		return err
	}
	if grantsRequireAuthorizeEndpoint(c.grants) {
		return c.validateAuthorizeEndpointStoreCapabilities()
	}
	return nil
}

// validateRefreshRetryStoreCapability enforces [store.RefreshRetryResponseStore]
// on the refresh substore whenever the token endpoint will actually reach for
// it. The refresh rotation path persists a sealed retry response when it holds
// encryption keys, and those keys are the cookie keys, so the capability is
// mandatory exactly when the refresh_token grant is enabled and cookie keys are
// configured. Without this check the shortfall surfaces as a request-time
// failure on every rotation rather than at construction.
func (c *config) validateRefreshRetryStoreCapability() error {
	if !slices.Contains(c.grants, grant.RefreshToken) || len(c.cookieKeys) == 0 {
		return nil
	}
	refreshTokens := c.store.RefreshTokens()
	if isNilLike(refreshTokens) {
		return nil
	}
	if _, ok := refreshTokens.(store.RefreshRetryResponseStore); !ok {
		return &Error{
			Code: codeConfiguration,
			Description: "Store.RefreshTokens() must implement " +
				"store.RefreshRetryResponseStore because grant.RefreshToken is " +
				"enabled and cookie keys are configured, which makes the token " +
				"endpoint persist durable refresh retry responses",
		}
	}
	return nil
}

// validateAuthorizeEndpointStoreCapabilities enforces the transactional and
// compare-and-swap store contracts that a grant mounting the browser authorize
// endpoint depends on: the store must be [store.Transactional], its interaction
// substore must implement [store.InteractionStoreCAS], and its grant substore
// must implement [store.GrantClientLister].
func (c *config) validateAuthorizeEndpointStoreCapabilities() error {
	if tx := transactionalStore(c.store); isNilLike(tx) {
		return &Error{
			Code: codeConfiguration,
			Description: "Store must implement store.Transactional because " +
				"a grant that mounts the browser authorize endpoint is enabled",
		}
	}
	if interactions := c.store.Interactions(); !isNilLike(interactions) {
		if _, ok := interactions.(store.InteractionStoreCAS); !ok {
			return &Error{
				Code: codeConfiguration,
				Description: "Store.Interactions() must implement " +
					"store.InteractionStoreCAS because a grant that mounts " +
					"the browser authorize endpoint is enabled",
			}
		}
	}
	if grants := c.store.Grants(); !isNilLike(grants) {
		if _, ok := grants.(store.GrantClientLister); !ok {
			return &Error{
				Code: codeConfiguration,
				Description: "Store.Grants() must implement " +
					"store.GrantClientLister because a grant that mounts " +
					"the browser authorize endpoint is enabled",
			}
		}
	}
	return nil
}

// needsGrantStore reports whether the configured grant set requires a
// non-nil [store.GrantStore]. Every interactive grant issues a grant
// record, so the predicate is "any grant other than
// client_credentials".
func needsGrantStore(grants []grant.Type) bool {
	for _, g := range grants {
		if g == grant.ClientCredentials {
			continue
		}
		return true
	}
	return false
}

// isNilLike reports whether v is nil or an interface carrying a nil-able
// concrete value whose value is nil. Public dependencies cross interface
// boundaries throughout the option surface; a direct `== nil` comparison
// misses typed-nil pointers and functions and can defer a configuration
// mistake until the first method call.
func isNilLike(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return rv.IsNil()
	default:
		return false
	}
}

// validateCookieKeys runs the same shape checks as [cookie.NewCodec] but
// without instantiating the codec — startup validation must surface every
// wrong-length key with a stable [*Error] code regardless of order.
func validateCookieKeys(keys [][]byte) error {
	for i, k := range keys {
		if len(k) != cookieKeyLen {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCookieKeys: entry " + strconv.Itoa(i) + " is not 32 bytes",
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
// authorization_code grant is the only one that imposes the
// requirement; the rule is centralised here so another grant can opt in by
// adding itself to the switch.
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
		if isNilLike(k.Signer) {
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

package op

import (
	"errors"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/internal/proxy"
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
		c.validateIDTokenScopeClaims,
		c.validateProfiles,
		c.validateRegistration,
		c.validateAuthorizationCodeGrantRequired,
		c.validateInteractions,
		c.validateLocales,
		c.validateFirstPartyClients,
		c.validateClientIDMetadataDocuments,
		c.validateOpenIDScopeOptional,
		c.validateStrictOfflineAccess,
		c.validateLoginFlow,
		c.validateACRAdvertisement,
		c.validateInteractionUICapabilities,
		c.validateAccessTokenFormat,
		c.validateAccessTokenRevocation,
		c.validateDeviceCodeGrant,
		c.validateCIBAGrant,
		c.validateJWTBearerGrant,
		c.validateSessionDurabilityPosture,
		c.validateEncryptionKeyset,
		c.validateStaticClients,
		c.validateMTLSOptions,
		c.validateMTLSClientAuth,
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

// isDevelopmentIssuer reports whether issuer names a host that cannot be a
// public deployment: a loopback IP literal, "localhost", or a name under
// an RFC 6761 special-use TLD. issuer has already passed issuer validation.
func isDevelopmentIssuer(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	for _, tld := range []string{"localhost", "test", "invalid", "example"} {
		if host == tld || strings.HasSuffix(host, "."+tld) {
			return true
		}
	}
	return false
}

// isLocalhostHTTPIssuer reports whether issuer is an http URL on the
// textual host "localhost", the only shape [WithAllowLocalhostIssuerForDev]
// has any effect on. issuer has already passed issuer validation.
func isLocalhostHTTPIssuer(issuer string) bool {
	u, err := url.Parse(issuer)
	return err == nil && u.Scheme == "http" && u.Hostname() == "localhost"
}

// issuerInvalid names the rule raw broke and quotes it, keeping
// [ErrIssuerInvalid] reachable through errors.Is.
func issuerInvalid(raw string, err error) error {
	reason := strings.TrimPrefix(err.Error(), discovery.ErrIssuerInvalid.Error()+": ")
	return newConfigurationError("issuer "+strconv.Quote(raw)+": "+reason, ErrIssuerInvalid)
}

// validateRequired enforces the boot contract (Issuer + Store + Keyset +
// cookie keys + login flow). Each field is checked for existence and then
// for its own shape, fail-fast within the field; the errors of all fields
// are collected so one [New] call reports everything wrong. A single
// error is returned bare, two or more as an [errors.Join] in field order
// (issuer, backchannel-dev issuer, store, keyset, cookie keys, login
// flow), each reachable through errors.Is. Split out so [validate] stays
// under the gocognit ceiling and so a future "what MUST be set" check has
// one obvious home.
func (c *config) validateRequired() error {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	add(c.validateIssuerRequired())
	if nilcheck.IsNil(c.store) {
		add(ErrStoreRequired)
	}
	add(c.validateKeysetRequired())
	add(c.validateCookieKeysField())
	add(c.validateLoginFlowRequired())
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return errors.Join(errs...)
	}
}

// validateIssuerRequired checks the issuer's existence, format and the
// backchannel-dev pairing; the pairing is only judged against a present,
// valid issuer.
func (c *config) validateIssuerRequired() error {
	if c.issuer == "" {
		return ErrIssuerRequired
	}
	// Deferred from WithIssuer: the localhost carve-out depends on an
	// opt-in that may have been registered by a later option.
	if err := discovery.ValidateIssuerWithLocalhostName(c.issuer, c.allowLocalhostIssuer); err != nil {
		return issuerInvalid(c.issuer, err)
	}
	if c.allowLocalhostIssuer && !isLocalhostHTTPIssuer(c.issuer) {
		return newConfigurationError(
			"WithAllowLocalhostIssuerForDev requires an http issuer on the host localhost (for example http://localhost:8080)", nil,
		)
	}
	if c.allowInsecureBackchannelLogoutForDev && !isDevelopmentIssuer(c.issuer) {
		return newConfigurationError(
			"WithAllowInsecureOutboundForDev(op.OutboundBackchannel) requires a development issuer (loopback, localhost, or a .localhost/.test/.invalid/.example host)", nil,
		)
	}
	return nil
}

// validateKeysetRequired checks the keyset's existence, shape and that
// the active key is live.
func (c *config) validateKeysetRequired() error {
	if len(c.keyset) == 0 {
		return ErrKeysetRequired
	}
	if err := validateKeyset(c.keyset, c.issuingAlg()); err != nil {
		return err
	}
	return validateActiveSigningKeyLive(c.keyset, c.clock.Now())
}

// validateCookieKeysField checks the cookie keys' shape, then that they
// exist when the grant set needs them.
func (c *config) validateCookieKeysField() error {
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
		return newConfigurationError("WithTrustedProxies rejected by parser", err)
	}
	if _, err := csrf.NewAllowlist(c.corsOrigins); err != nil {
		return newConfigurationError("WithCORSOrigins rejected by parser", err)
	}
	return nil
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
			return newConfigurationError("WithOpenIDScopeOptional is incompatible with FAPI 2.0 profile "+profileOptionName(p), nil)
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
		return newConfigurationError("WithStrictOfflineAccess is incompatible with WithOpenIDScopeOptional", nil)
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
	if nilcheck.IsNil(c.store.OpaqueAccessTokens()) {
		return newConfigurationError("op.WithAccessTokenFormat(AccessTokenFormatOpaque) "+
			"requires Store.OpaqueAccessTokens() to be non-nil", nil)
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
		return newConfigurationError("WithAccessTokenRevocationStrategy received an "+
			"unknown AccessTokenRevocationStrategy value", nil)
	}
	if c.atRevocation != store.RevocationStrategyNone {
		if c.atRevocation == store.RevocationStrategyGrantTombstone &&
			nilcheck.IsNil(c.store.GrantRevocations()) {
			return newConfigurationError("the access-token revocation strategy RevocationStrategyGrantTombstone "+
				"(the default) requires Store.GrantRevocations() to be non-nil; implement it, or choose "+
				"another strategy with WithAccessTokenRevocationStrategy", nil)
		}
		if c.atRevocation == store.RevocationStrategyJTIRegistry &&
			nilcheck.IsNil(c.store.AccessTokens()) {
			return newConfigurationError("RevocationStrategyJTIRegistry requires "+
				"Store.AccessTokens() to be non-nil", nil)
		}
		return nil
	}
	for _, p := range c.profiles {
		if profile.RequiresAccessTokenRevocation(p) {
			return newConfigurationError("FAPI 2.0 Security Profile §5.3.2.2 requires "+
				"access-token revocation; RevocationStrategyNone is "+
				"rejected under profile "+profileOptionName(p)+
				" — use RevocationStrategyGrantTombstone (default) or "+
				"RevocationStrategyJTIRegistry", nil)
		}
	}
	return nil
}

// validateLoginFlow enforces the option-layer invariants of
// [WithLoginFlow]: its step dependencies are wired, and its
// [op.ExternalStep] KindLabel values are user-defined (dotted prefix)
// so they cannot collide with the built-in [StepKind] reserved
// identifiers.
//
// The compiler-level checks (duplicate StepKind across rules, nil
// Authenticator inside ExternalStep, …) live in
// [authn.CompileLoginFlow]; this method handles the option-layer
// shape.
func (c *config) validateLoginFlow() error {
	if !c.loginFlowSet {
		return nil
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
	if ext, ok := flow.Registration.(ExternalStep); ok {
		if err := checkExternalStepKind("Registration", ext); err != nil {
			return err
		}
		if err := checkRegistrationKindUnique(flow, ext.KindLabel); err != nil {
			return err
		}
	}
	return nil
}

// checkRegistrationKindUnique refuses a Registration KindLabel that
// Primary or a step of a [StepOneOf] anywhere in the flow already uses.
// A Rule whose Then carries it is refused by [WithLoginFlow].
func checkRegistrationKindUnique(flow LoginFlow, kind StepKind) error {
	clash := func(where string, step Step) error {
		if nilcheck.IsNil(step) || step.Kind() != kind {
			return nil
		}
		return newConfigurationError("WithLoginFlow: Registration.KindLabel "+kind.String()+
			" is already used by "+where, nil)
	}
	type placed struct {
		where string
		step  Step
	}
	steps := make([]placed, 0, 1+len(flow.Rules))
	steps = append(steps, placed{"Primary", flow.Primary})
	for i, r := range flow.Rules {
		steps = append(steps, placed{"Rules[" + strconv.Itoa(i) + "].Then", r.Then})
	}
	for _, s := range steps {
		if err := clash(s.where, s.step); err != nil {
			return err
		}
		oneOf, ok := s.step.(StepOneOf)
		if !ok {
			continue
		}
		for j, inner := range oneOf.Steps {
			if err := clash(s.where+".StepOneOf.Steps["+strconv.Itoa(j)+"]", inner); err != nil {
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
	if nilcheck.IsNil(ext.Authenticator) {
		return newConfigurationError("WithLoginFlow: "+where+".Authenticator must not be nil", nil)
	}
	if ext.KindLabel == "" {
		return newConfigurationError("WithLoginFlow: "+where+".KindLabel must not be empty", nil)
	}
	if ext.KindLabel.IsBuiltin() {
		return newConfigurationError("WithLoginFlow: "+where+".KindLabel must not collide with a built-in StepKind ("+ext.KindLabel.String()+")", nil)
	}
	if !ext.KindLabel.IsUserDefined() {
		return newConfigurationError("WithLoginFlow: "+where+".KindLabel must use a dotted prefix (e.g., \"myorg.factor\") so it cannot collide with future built-ins", nil)
	}
	return nil
}

// validateLocales rejects a [WithDefaultLocale] value that is not
// served by any registered bundle. The seed en / ja bundles are
// always available, so a default of "en" / "ja" never trips the
// check; embedders that override the default to a custom locale
// MUST register the matching bundle through [WithLocaleBundle].
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
	return newConfigurationError("WithDefaultLocale references a locale that is not registered through WithLocaleBundle or shipped as a seed bundle", nil)
}

// validateLoginFlowRequired covers the no-[LoginFlow] case.
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
// refused at construction alongside the other required wiring, from the
// existence stage of [config.validateRequired].
func (c *config) validateLoginFlowRequired() error {
	if c.loginFlowSet {
		return nil
	}
	for _, g := range c.grants {
		if g != grant.AuthorizationCode {
			continue
		}
		return ErrLoginFlowRequired
	}
	return nil
}

// recordBrowserSurface notes that a browser sign-in option was set outside
// [WithDefaults]; repeats are dropped.
func (c *config) recordBrowserSurface(name string) {
	if c.applyingDefaults || slices.Contains(c.browserSurfaceExplicit, name) {
		return
	}
	c.browserSurfaceExplicit = append(c.browserSurfaceExplicit, name)
}

// validateAuthorizationCodeGrantRequired refuses an explicit browser
// sign-in option combined with a grant set that has no /authorize
// endpoint. [WithGrants] replaces the defaults, so the option would
// otherwise be dropped without a trace. A login flow that is the claim
// source for a grant resolving end users (device code, CIBA) is
// legitimate without authorization_code and is not counted.
func (c *config) validateAuthorizationCodeGrantRequired() error {
	if grantsRequireAuthorizeEndpoint(c.grants) {
		return nil
	}
	loginFlowIsClaimSource := (nilcheck.IsNil(c.userStore) || c.userStoreDefaulted()) &&
		c.inferredUserStore() != nil &&
		grantsResolveEndUser(c.grants)
	var names []string
	for _, n := range c.browserSurfaceExplicit {
		if n == "WithLoginFlow" && loginFlowIsClaimSource {
			continue
		}
		names = append(names, n)
	}
	if len(names) == 0 {
		return nil
	}
	return newConfigurationError(
		"WithGrants leaves out authorization_code, which these options require: "+strings.Join(names, ", "),
		ErrAuthorizationCodeGrantRequired,
	)
}

// validateInteractions enforces uniqueness of [Interaction.Name]
// across the registered set so registration mistakes surface at [New]
// rather than the first chain run.
func (c *config) validateInteractions() error {
	if len(c.interactions) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(c.interactions))
	for i, ix := range c.interactions {
		if nilcheck.IsNil(ix) {
			return newConfigurationError("WithInteractions received nil Interaction at position "+strconv.Itoa(i), nil)
		}
		name := ix.Name()
		if name == "" {
			return newConfigurationError("WithInteractions: Interaction.Name must not be empty", nil)
		}
		// The built-ins register first and de-duplication keeps the
		// first entry, so a reused built-in name would never run.
		if name == authn.BuiltinConsentName || name == authn.BuiltinChooserName {
			return newConfigurationError("WithInteractions: Interaction.Name "+name+" is reserved for the built-in interaction", nil)
		}
		if _, dup := seen[name]; dup {
			return newConfigurationError("WithInteractions: duplicate Interaction.Name "+name, nil)
		}
		seen[name] = struct{}{}
	}
	return nil
}

// validateRegistration enforces the cross-cutting invariants of
// [WithDynamicRegistration] against the rest of the configuration.
func (c *config) validateRegistration() error {
	if c.dcr == nil {
		return nil
	}
	if nilcheck.IsNil(c.store.InitialAccessTokens()) {
		return newConfigurationError("WithDynamicRegistration requires the configured Store to provide a non-nil "+
			"InitialAccessTokens substore (the inmem, sql and dynamodb adapters ship one; the redis adapter does not — "+
			"route this substore to another backend through storeadapter/composite)", nil)
	}
	if nilcheck.IsNil(c.store.RegistrationAccessTokens()) {
		return newConfigurationError("WithDynamicRegistration requires the configured Store to provide a non-nil "+
			"RegistrationAccessTokens substore (the inmem, sql and dynamodb adapters ship one; the redis adapter does not — "+
			"route this substore to another backend through storeadapter/composite)", nil)
	}
	if _, ok := resolveClientRegistry(c.store); !ok {
		return newConfigurationError("Store does not expose ClientRegistry; dynamic registration requires a client backend with write access", nil)
	}
	for _, name := range c.dcr.OpenRegistrationDefaultScopes {
		if name == "" {
			return newConfigurationError("WithDynamicRegistration: OpenRegistrationDefaultScopes contains an empty entry", nil)
		}
		if _, ok := c.scopeIndex[name]; !ok {
			return newConfigurationError("WithDynamicRegistration: OpenRegistrationDefaultScopes contains unknown scope "+name, nil)
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
			return newConfigurationError("WithScope: Name must not be empty", nil)
		}
		if _, dup := c.scopeIndex[s.Name]; dup {
			return newConfigurationError("WithScope: duplicate scope "+s.Name, nil)
		}
		if isStandardScope(s.Name) && !s.Public {
			return newConfigurationError("standard OIDC scope "+s.Name+" cannot be registered with Public: false", nil)
		}
		c.scopeIndex[s.Name] = s
	}
	return nil
}

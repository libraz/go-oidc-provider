package op

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"strconv"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/proxy"
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

// validateAccessTokenFormat enforces the ADR 0024 fail-fast contract:
// when the global format or any per-audience override selects
// [AccessTokenFormatOpaque], the configured [Store] MUST expose a
// non-nil [store.OpaqueAccessTokenStore]. Embedders who request opaque
// tokens with no place to persist them get a build-time error rather
// than a runtime crash on the first issuance.
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

// validateAccessTokenRevocation enforces the ADR 0025 fail-fast
// contract on the JWT access-token revocation strategy:
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
	if ext.Authenticator == nil {
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
func isFAPI2Profile(p profile.Profile) bool {
	switch p {
	case profile.FAPI2Baseline, profile.FAPI2MessageSigning:
		return true
	case profile.FAPICIBA, profile.IGovHigh:
		return false
	}
	return false
}

// isFAPIProfile reports whether p is any FAPI-family profile (FAPI 2.0
// Baseline, FAPI 2.0 Message Signing, or FAPI Client-Initiated
// Backchannel Authentication). The wider predicate exists so the JAR
// verifier wiring can apply the RFC 9101 §10.8 strict reading
// (jti-anchored replay defence with no missing-jti opt-out) uniformly
// across every FAPI profile, not just the Web-side FAPI 2.0 family;
// FAPICIBA inherits the same mandate by reference.
func isFAPIProfile(p profile.Profile) bool {
	switch p {
	case profile.FAPI2Baseline, profile.FAPI2MessageSigning, profile.FAPICIBA:
		return true
	case profile.IGovHigh:
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
	return nil
}

// profileForcesDPoPNonce reports whether p mandates the RFC 9449 §8/§9
// nonce challenge flow. FAPI 2.0 Message Signing §5.3.4 requires the
// AS to issue a server-side DPoP nonce; FAPI-CIBA inherits the same
// posture by reference (FAPI-CIBA-ID1 §5). The future iGov High
// profile is still a placeholder and will land here when its
// constraint table graduates.
func profileForcesDPoPNonce(p profile.Profile) bool {
	switch p {
	case profile.FAPI2MessageSigning, profile.FAPICIBA:
		return true
	case profile.FAPI2Baseline, profile.IGovHigh:
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

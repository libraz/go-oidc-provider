package op

import (
	"log/slog"
	"slices"

	internallog "github.com/libraz/go-oidc-provider/internal/log"
	"github.com/libraz/go-oidc-provider/internal/redact"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// DefaultAccessTokenTTL is the lifetime applied to issued access
// tokens when the embedder does not call [WithAccessTokenTTL]. Five
// minutes sits comfortably under the 10-minute upper bound that
// FAPI 2.0 §3.1.9 imposes on profile-enabled deployments, so a
// caller who layers [WithProfile] on top of the defaults stays
// inside spec without further tuning.
//
// The canonical value lives in [timex.AccessTokenTTLDefault].
const DefaultAccessTokenTTL = timex.AccessTokenTTLDefault

// DefaultRefreshTokenTTL is the lifetime applied to issued refresh
// tokens when the embedder does not call [WithRefreshTokenTTL]. Thirty
// days mirrors the typical "long-lived but bounded" posture for
// authorization-code-derived refresh tokens; embedders facing
// stricter risk profiles can shorten it through the option.
//
// The canonical value lives in [timex.RefreshTokenTTLDefault]; this
// name is preserved for embedders that already reference the constant.
const DefaultRefreshTokenTTL = timex.RefreshTokenTTLDefault

// startupLog returns the logger for diagnostics emitted once while [New]
// runs: the supplied logger, else [slog.Default]. A config that skipped
// [config.applyDefaults] falls back to the operational logger.
func (c *config) startupLog() *slog.Logger {
	if c.startupLogger != nil {
		return c.startupLogger
	}
	return c.logger
}

// applyDefaults fills in optional fields with their library defaults.
func (c *config) applyDefaults() {
	if c.clock == nil {
		c.clock = timex.SystemClock
	}
	if c.logger == nil {
		// Same redaction wrapping as [WithLogger] applies to a supplied logger.
		c.startupLogger = slog.New(redact.WrapHandler(slog.Default().Handler()))
		c.logger = slog.New(internallog.DiscardHandler{})
		c.loggerDefaulted = true
	} else {
		c.startupLogger = c.logger
	}
	// auditLogger has no fall-back default of its own: when
	// [WithAuditLogger] is unset, [effectiveAuditLogger] returns the
	// operational logger installed above, whose discard handler drops
	// every record. Defaulting auditLogger here would pin it and stop
	// audit lines following a later-supplied [WithLogger] — the two
	// loggers stay structurally separate.
	if c.mountPrefix == "" {
		c.mountPrefix = "/oidc"
	}
	defaults := defaultEndpoints()
	c.endpoints = defaults.merge(c.endpoints)
	if c.interactionD == nil {
		// When neither a custom [interaction.Driver] nor a SPA shell
		// is configured the OP boots into a working HTML login
		// surface. With a SPA shell active the default falls away so
		// the embedder's SPA owns rendering and the JSON state
		// endpoints stay the only protocol surface.
		if !c.spaUISet {
			c.interactionD = interaction.HTMLDriver{}
		}
	}
	// Wrap the resolved driver with [interaction.TemplateOverlayDriver]
	// when the embedder configured a consent or chooser template and SPA
	// mode is not active. The overlay degrades to a passthrough for
	// prompt types whose template field is nil, so wrapping is safe even
	// when only one of the two templates is provided. Under SPA mode the
	// JSON state envelope owns both surfaces, so the overlay is not
	// composed in that path.
	if !c.spaUISet && (c.consentUISet || c.chooserUISet) {
		c.interactionD = interaction.TemplateOverlayDriver{
			Inner:           c.interactionD,
			ConsentTemplate: c.consentUI.Template,
			ChooserTemplate: c.chooserUI.Template,
			// Already normalized by the option site; an unset option
			// leaves the empty string, which the overlay reads as
			// "keep the default policy".
			ConsentCSP: c.consentUI.ContentSecurityPolicy,
			ChooserCSP: c.chooserUI.ContentSecurityPolicy,
		}
	}
	if c.chooserUIShadowedBySPA {
		c.startupLog().Warn(
			"WithChooserUI is configured but WithSPAUI is active; "+
				"the chooser template will not be rendered "+
				"(SPA owns the chooser UI)",
			"option", "WithChooserUI",
		)
	}
	c.resolveGrants()
	c.fillStandardScopes()
	c.applyRegistrationDefaults()
	if c.defaultLocale == "" {
		c.defaultLocale = LocaleEnglish
	}
	if c.accessTokenTTL == 0 {
		c.accessTokenTTL = DefaultAccessTokenTTL
	}
	if c.refreshTokenTTL == 0 {
		c.refreshTokenTTL = DefaultRefreshTokenTTL
	}
	c.applyProfileAnyOfDefaults()
}

// applyProfileAnyOfDefaults auto-enables the canonical default member
// of every disjunctive profile constraint ([profile.RequiredAnyOf])
// when the embedder did not already pick one. The canonical example
// is FAPI 2.0 §3.1.4's "DPoP OR mTLS" sender-constrained-token rule:
// when neither feature is configured, [profile.RequiredAnyOf] returns
// {{DPoP, MTLS}} and this fill-in selects DPoP because it has no
// infrastructure prerequisite (mTLS requires terminator passthrough
// of the client certificate). An embedder who wants mTLS calls
// [WithFeature](MTLS) and the loop here treats the AnyOf as already
// satisfied — DPoP is NOT added on top.
//
// The fill runs after every option has been applied, so the order in
// which the embedder lists [WithFeature] and [WithProfile] does not
// affect the outcome: an explicit MTLS opt-in suppresses the DPoP
// default regardless of whether it precedes or follows the profile.
//
// Profiles that mandate additional plumbing on top of DPoP (e.g.
// FAPI 2.0 Message Signing's WithDPoPNonceSource requirement) still
// surface their gating error from [config.validate] when the support
// is missing; the auto-enable only chooses the default sender-binding
// mechanism, not the surrounding wiring.
func (c *config) applyProfileAnyOfDefaults() {
	for _, p := range c.profiles {
		for _, anyOf := range profile.RequiredAnyOf(p) {
			c.fillAnyOfDefault(anyOf)
		}
	}
}

// fillAnyOfDefault appends the canonical default member of one
// disjunctive constraint when the embedder has not already enabled
// any member. Empty groups and groups whose first member is invalid
// are no-ops; the caller iterates over every group reported by
// [profile.RequiredAnyOf].
func (c *config) fillAnyOfDefault(anyOf []feature.Flag) {
	if len(anyOf) == 0 {
		return
	}
	for _, member := range anyOf {
		if featureEnabled(c.features, member) {
			return
		}
	}
	defaultFlag := anyOf[0]
	if !defaultFlag.IsValid() {
		return
	}
	c.features = append(c.features, defaultFlag)
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
		c.dcr.IATTTL = timex.RegistrationIATTTLDefault
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

// resolveGrants assembles the final grant set from the two ways an
// embedder can reach it: the wholesale [WithGrants] list and the
// per-grant opt-in options ([WithCIBA], [WithDeviceCodeGrant],
// [WithJWTBearerGrant]) that also wire the grant's collaborators.
//
// The base is the [WithGrants] list when it was supplied, and the
// authorization_code + refresh_token default otherwise. Per-grant
// opt-ins are then layered on top. Both halves matter:
//
//   - Layering rather than replacing means adding CIBA or the device
//     grant to an existing OP cannot silently withdraw the
//     authorization-code flow. Before this resolution ran here, the
//     opt-in options appended to an empty slice during option
//     application, which made the default fill-in below see a
//     non-empty set and skip — so an OP configured with nothing but
//     WithCIBA served the CIBA grant and nothing else.
//   - Resolving after every option has been applied makes the result
//     order-independent, matching the contract [WithProfile]'s
//     auto-enable already documents. [WithGrants] overwrites the
//     slice, so an opt-in applied before it used to be discarded and
//     the same pair of options produced different providers depending
//     on the order they were written in.
func (c *config) resolveGrants() {
	if !c.grantsSet {
		c.grants = []grant.Type{grant.AuthorizationCode, grant.RefreshToken}
	}
	for _, opt := range []struct {
		enabled bool
		grant   grant.Type
	}{
		{c.deviceCodeGrantEnabled, grant.DeviceCode},
		{c.cibaGrantEnabled, grant.CIBA},
		{c.jwtBearerGrant != nil, grant.JWTBearer},
	} {
		if !opt.enabled || slices.Contains(c.grants, opt.grant) {
			continue
		}
		c.grants = append(c.grants, opt.grant)
	}
}

// emitPartialWiringWarnings logs one warning per registered option whose
// runtime wiring is intentionally partial but still accepted at
// construction time. Options that would mislead embedders into believing
// a feature is live are rejected in [config.validate] instead of being
// warned here.
func (c *config) emitPartialWiringWarnings() {
	log := c.startupLog()
	if log == nil {
		return
	}
	if c.allowInsecureBackchannelLogoutForDev {
		log.Warn(
			"WithAllowInsecureBackchannelLogoutForDev admits plain-http "+
				"loopback URLs for backchannel_logout_uri and lets the "+
				"deliverer POST a signed logout token at a loopback "+
				"address; never enable this in production",
			"option", "WithAllowInsecureBackchannelLogoutForDev",
		)
	}
	if c.allowInsecureSharedSignalsPushForDev {
		log.Warn(
			"WithAllowInsecureSharedSignalsPushForDev admits plain-http "+
				"and loopback push endpoints for shared-signals streams and "+
				"lets the push worker POST security event tokens there; "+
				"never enable this in production",
			"option", "WithAllowInsecureSharedSignalsPushForDev",
		)
	}
	if c.allowLocalhostLoopback {
		log.Warn(
			"WithAllowLocalhostLoopback is a development option: it admits the "+
				"textual \"localhost\" host in redirect_uri and in the issuer, "+
				"whose resolution can be hijacked; never enable this in production",
			"option", "WithAllowLocalhostLoopback",
		)
	}
	if featureEnabled(c.features, feature.PKCE) {
		log.Warn(
			"WithFeature(feature.PKCE) has no effect: PKCE with S256 is always "+
				"available, and PKCE for confidential clients is required only "+
				"through WithProfile(profile.OAuth21) or a FAPI profile",
			"option", "WithFeature",
		)
	}
	c.warnUserStoreMismatch()
	c.infoMissingStoreCapabilities()
	c.warnSessionDurabilityMismatch()
	c.warnCaptchaOnScriptlessUI()
	c.warnMTLSOptionsWithoutFeature()
	c.warnEncryptionKidlessTrialCap()
	c.warnPKCENotRequired()
	c.warnNoLogger()
	c.warnUnenabledSeedGrants()
	c.logPrivateNetworkReach()
}

// warnPKCENotRequired reports an authorization-code OP that declared no
// profile requiring PKCE: a confidential client may then redeem a code
// without one, the OpenID Connect Core 1.0 shape.
func (c *config) warnPKCENotRequired() {
	if c.requirePKCE() || !slices.Contains(c.grants, grant.AuthorizationCode) {
		return
	}
	c.startupLog().Warn(
		"no security profile requires PKCE, so a confidential client may "+
			"redeem an authorization code without one; declare "+
			"op.WithProfile(profile.OAuth21) unless legacy clients need this",
		"option", "WithProfile",
	)
}

// warnSessionDurabilityMismatch reports an explicit Durable posture on a
// session store that says its sessions are volatile. The posture only
// labels audit events, so the declaration is kept (Redis with AOF is a
// legitimate case) and the mismatch is surfaced rather than rejected.
func (c *config) warnSessionDurabilityMismatch() {
	if !c.sessionDurabilityPostureSet || c.sessionDurabilityPosture != SessionDurabilityDurable {
		return
	}
	if durable, reported := c.sessionStoreDurable(); !reported || durable {
		return
	}
	c.startupLog().Warn(
		"WithSessionDurabilityPosture(SessionDurabilityDurable) is declared but the "+
			"session store reports that its sessions are on a volatile backend; "+
			"the posture only labels back-channel logout audit events",
		"option", "WithSessionDurabilityPosture",
	)
}

// warnMTLSOptionsWithoutFeature reports mTLS knobs configured on an OP
// that has no mTLS verifier to apply them.
//
// [buildMTLSVerifier] returns a nil verifier unless [feature.MTLS] is
// enabled, and every consumer reads nil as "mTLS off". The recorded
// [WithMTLSProxy] allow-list and [WithMTLSRootCAs] pool are then never
// read: no certificate is selected from the forwarded header, no chain
// is checked, and no cnf.x5t#S256 is stamped. The request still
// succeeds, so the deployment issues plain bearer tokens while its
// configuration says the tokens are certificate-bound — and
// [MTLSProxyConfig] reads the recorded value back unchanged, which is
// what makes the gap invisible from the embedder's side.
//
// Reported rather than rejected because both options are legitimately
// set ahead of the feature flag — a deployment staging its proxy
// allow-list before turning binding on, or sharing one option slice
// across environments that enable the feature selectively. Rejecting
// would break those without making any deployment safer than a line
// naming the missing flag does.
func (c *config) warnMTLSOptionsWithoutFeature() {
	if featureEnabled(c.features, feature.MTLS) {
		return
	}
	for _, o := range []struct {
		configured bool
		option     string
	}{
		{c.mtlsProxy.header != "" || len(c.mtlsProxy.trusted) > 0, "WithMTLSProxy"},
		{c.mtlsRootCAs != nil, "WithMTLSRootCAs"},
	} {
		if !o.configured {
			continue
		}
		c.startupLog().Warn(
			o.option+" is configured but the mTLS feature is not enabled, so the "+
				"OP builds no certificate verifier and never reads the value: "+
				"client certificates are ignored and access tokens are issued as "+
				"plain bearer tokens with no cnf.x5t#S256 confirmation. Add "+
				"WithFeature(feature.MTLS) to make the setting take effect",
			"option", o.option,
		)
	}
}

// warnCaptchaOnScriptlessUI reports a captcha challenge scheduled behind
// the built-in HTML interaction surface.
//
// [interaction.HTMLDriver] renders no client-side script, so it presents
// the captcha token field as a plain text input rather than mounting a
// provider widget. That keeps the challenge answerable — the alternative
// is an unfillable hidden field and a chain that aborts once the
// attempts run out — but it only produces a token the verifier accepts
// when the deployment's captcha is one a human can type. A widget-issued
// token (Turnstile, reCAPTCHA, hCaptcha) cannot be produced on this
// surface at all, and every request that reaches the challenge is
// refused for a reason no user can act on.
//
// The library cannot tell the two apart: [CaptchaVerifier] is opaque.
// The condition is therefore reported rather than rejected, so the
// deployments where a typed answer is the intended one keep working.
func (c *config) warnCaptchaOnScriptlessUI() {
	if !c.captchaScheduled() || !rendersWithoutScript(c.interactionD) {
		return
	}
	c.startupLog().Warn(
		"a StepCaptcha is scheduled in the LoginFlow but the interaction UI is the "+
			"built-in HTML driver, which renders no client-side script; the "+
			"token field is served as a plain text input, so a captcha whose "+
			"token comes from a browser widget cannot be answered there. "+
			"Configure WithSPAUI or WithInteractionDriver with a UI that "+
			"mounts the provider's widget",
		"step", string(StepKindCaptcha),
	)
}

// passkeyScheduled reports whether a passkey step can be put in front of
// a user through the compiled login flow.
func (c *config) passkeyScheduled() bool {
	for _, step := range c.loginFlowSteps() {
		if step.Kind() == StepKindPasskey {
			return true
		}
	}
	return false
}

// captchaScheduled reports whether the [LoginFlow] schedules a
// [StepCaptcha] through its rules.
func (c *config) captchaScheduled() bool {
	for _, step := range c.loginFlowSteps() {
		if step.Kind() == StepKindCaptcha {
			return true
		}
	}
	return false
}

// rendersWithoutScript reports whether d is the built-in HTML driver,
// possibly behind the library's own template overlay. A driver the
// library did not write is assumed to be script-capable: its output is
// unknowable here, and warning about every custom driver would train
// the reader to ignore the line.
func rendersWithoutScript(d interaction.Driver) bool {
	switch v := d.(type) {
	case interaction.HTMLDriver, *interaction.HTMLDriver:
		return true
	case interaction.TemplateOverlayDriver:
		return rendersWithoutScript(v.Inner)
	case *interaction.TemplateOverlayDriver:
		return v != nil && rendersWithoutScript(v.Inner)
	default:
		return false
	}
}

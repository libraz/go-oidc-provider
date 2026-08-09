package op

import (
	"log/slog"
	"slices"
	"time"

	internallog "github.com/libraz/go-oidc-provider/internal/log"
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
const DefaultAccessTokenTTL = 5 * time.Minute

// DefaultRefreshTokenTTL is the lifetime applied to issued refresh
// tokens when the embedder does not call [WithRefreshTokenTTL]. Thirty
// days mirrors the typical "long-lived but bounded" posture for
// authorization-code-derived refresh tokens; embedders facing
// stricter risk profiles can shorten it through the option.
//
// The canonical value lives in [timex.RefreshTokenTTLDefault]; this
// name is preserved for embedders that already reference the constant.
const DefaultRefreshTokenTTL = timex.RefreshTokenTTLDefault

// applyDefaults fills in optional fields with their library defaults.
func (c *config) applyDefaults() {
	if c.clock == nil {
		c.clock = timex.SystemClock
	}
	if c.logger == nil {
		c.logger = slog.New(internallog.DiscardHandler{})
	}
	// auditLogger has no fall-back default: when neither
	// [WithAuditLogger] nor [WithLogger] is set, [effectiveAuditLogger]
	// returns nil and the audit emitter collapses to a no-op. Setting
	// a default here would silently route audit lines into the
	// operational stream — which is the design rationale for keeping
	// the two loggers structurally separate.
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
		}
	}
	if c.chooserUIShadowedBySPA {
		c.logger.Warn(
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
// per-grant opt-in options ([WithCIBA], [WithDeviceCodeGrant]) that
// also wire the grant's collaborators.
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
	if c.logger == nil {
		return
	}
	if c.allowInsecureBackchannelLogoutForDev {
		c.logger.Warn(
			"WithAllowInsecureBackchannelLogoutForDev admits plain-http "+
				"loopback URLs for backchannel_logout_uri and disables "+
				"the SSRF gate on the deliverer; never enable this in "+
				"production",
			"option", "WithAllowInsecureBackchannelLogoutForDev",
		)
	}
	c.warnUserStoreMismatch()
}

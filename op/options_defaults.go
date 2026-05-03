package op

import (
	"log/slog"
	"time"

	internallog "github.com/libraz/go-oidc-provider/internal/log"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
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
//
//nolint:gochecknoglobals // re-export of the canonical timex value; var is required for cross-package alias.
var DefaultRefreshTokenTTL = timex.RefreshTokenTTLDefault

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
	if len(c.grants) == 0 {
		c.grants = []grant.Type{grant.AuthorizationCode, grant.RefreshToken}
	}
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

// emitPartialWiringWarnings logs one warning per registered option whose
// runtime wiring is still in flight. The warning is intentionally a log
// line and not a constructor error: the options have shipped, embedders
// already call them in working binaries, and the partial wiring does
// not produce wrong protocol output — it leaves SPA mounts unserved.
// Surfacing the gap through the configured logger lets operators notice
// the limitation in their boot logs without breaking existing call
// sites.
// The warnings are emitted at WARN so a discardHandler-backed logger
// (the library default when [WithLogger] is not called) drops them
// silently and only operators who opt in to logging see them.
func (c *config) emitPartialWiringWarnings() {
	if c.logger == nil {
		return
	}
	if c.spaUISet {
		c.logger.Warn(
			"WithSPAUI is partially wired: the Provider suppresses the default HTML driver, but the configured LoginMount/ConsentMount/LogoutMount and StaticDir are not yet served by op.New. Embedders must mount their SPA externally; JSON state endpoints under the configured mounts land in a follow-up release.",
			"option", "WithSPAUI",
		)
	}
	if c.consentUISet {
		c.logger.Warn(
			"WithConsentUI is registered but the supplied Template is not yet rendered by any handler. The option is a no-op until the consent-interaction wiring lands.",
			"option", "WithConsentUI",
		)
	}
	if c.chooserUISet {
		c.logger.Warn(
			"WithChooserUI is registered but the supplied Template is not yet rendered by any handler. The option is a no-op until the chooser-interaction HTML render wiring lands.",
			"option", "WithChooserUI",
		)
	}
}

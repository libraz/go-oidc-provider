package op

import (
	"strings"

	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// warnNoLogger reports an OP that will discard every request-time record:
// without [WithLogger] the operational logger is a discard handler, and
// without [WithAuditLogger] the audit stream rides on that same logger.
func (c *config) warnNoLogger() {
	if !c.loggerDefaulted || c.auditLogger != nil {
		return
	}
	c.startupLog().Warn(
		"neither WithLogger nor WithAuditLogger is configured, so request-time "+
			"operational logs and audit records are discarded; configure WithLogger "+
			"(or WithAuditLogger for audit records) to keep them",
		"option", "WithLogger",
	)
}

// warnUnenabledSeedGrants reports, once per client and grant, a static
// client seed that names a grant type the OP has not enabled. The seed is
// accepted, but every token request using that grant is refused with
// unsupported_grant_type.
func (c *config) warnUnenabledSeedGrants() {
	enabled := c.enabledGrantWires()
	for i := range c.staticClients {
		seed := &c.staticClients[i]
		for _, wire := range unenabledSeedGrants(seed, enabled) {
			c.startupLog().Warn(
				"static client "+seed.ID+" lists grant_type "+wire+
					" but the OP has not enabled that grant, so token requests using it are "+
					"refused with unsupported_grant_type; enable it with "+seedGrantActivation(wire),
				"client_id", seed.ID,
				"grant_type", wire,
			)
		}
	}
}

// unenabledSeedGrants returns the distinct grant types of seed that are
// absent from enabled, in seed order.
func unenabledSeedGrants(seed *store.Client, enabled map[string]struct{}) []string {
	var out []string
	seen := make(map[string]struct{}, len(seed.GrantTypes))
	for _, wire := range seed.GrantTypes {
		if _, dup := seen[wire]; dup {
			continue
		}
		seen[wire] = struct{}{}
		if _, ok := enabled[wire]; !ok {
			out = append(out, wire)
		}
	}
	return out
}

// enabledGrantWires returns the wire form of every grant the resolved
// configuration serves: the resolved grant set, the registered custom
// grants, and token exchange when it is registered.
func (c *config) enabledGrantWires() map[string]struct{} {
	out := make(map[string]struct{}, len(c.grants))
	for _, g := range c.grants {
		out[g.String()] = struct{}{}
	}
	for _, name := range customGrantNamesFor(c) {
		out[name] = struct{}{}
	}
	return out
}

// seedGrantActivation names the option that enables the grant with the
// given wire form.
func seedGrantActivation(wire string) string {
	if wire == TokenExchangeGrantType {
		return "RegisterTokenExchange(...)"
	}
	for _, g := range []grant.Type{
		grant.AuthorizationCode, grant.RefreshToken, grant.ClientCredentials,
		grant.DeviceCode, grant.CIBA, grant.JWTBearer,
	} {
		if g.String() == wire {
			return grantActivationOption(g)
		}
	}
	return "WithCustomGrant(...)"
}

// privateNetworkReach describes one option that lets an outbound fetch
// reach private-network addresses.
type privateNetworkReach struct {
	enabled bool
	option  string
	widens  string
	// callerDriven is true when an unauthenticated caller can choose the
	// URL the fetch targets.
	callerDriven bool
}

// privateNetworkReaches lists the private-network options with their state.
func (c *config) privateNetworkReaches() []privateNetworkReach {
	return []privateNetworkReach{
		{c.allowPrivateNetworkJWKS, "WithAllowPrivateNetworkJWKS", "the fetch of a relying party's jwks_uri", true},
		{c.allowPrivateNetworkJAR, "WithAllowPrivateNetworkJAR", "the fetch of a request_uri request object", true},
		{c.allowPrivateNetworkSector, "WithAllowPrivateNetworkSector", "the fetch of a sector_identifier_uri document", true},
		{
			c.allowPrivateNetworkCIMD, "WithAllowPrivateNetworkClientIDMetadata",
			"the fetch of a client ID metadata document (and admits plain http for client_id URLs)", true,
		},
		{
			c.backchannelAllowPrivateNetwork, "WithAllowPrivateNetworkBackchannel",
			"back-channel logout delivery to a relying party's backchannel_logout_uri", false,
		},
		{
			c.sharedSignalsAllowPrivateNetwork, "WithAllowPrivateNetworkSharedSignals",
			"push delivery of security event tokens to shared-signals receiver endpoints", false,
		},
	}
}

// unauthenticatedRegistrationSources names the enabled paths through which
// an unauthenticated caller can introduce a URL the OP will fetch.
func (c *config) unauthenticatedRegistrationSources() []string {
	var out []string
	if c.dcr != nil && c.dcr.Open {
		out = append(out, "open dynamic registration (RegistrationOption.Open)")
	}
	if c.cimd != nil {
		out = append(out, "Client ID Metadata Documents (WithClientIDMetadataDocuments)")
	}
	return out
}

// logPrivateNetworkReach logs one line per enabled private-network option
// naming what it widens. The line is a warning when the widened fetch can
// be aimed by an unauthenticated caller, and informational otherwise.
func (c *config) logPrivateNetworkReach() {
	sources := c.unauthenticatedRegistrationSources()
	for _, r := range c.privateNetworkReaches() {
		if !r.enabled {
			continue
		}
		if r.callerDriven && len(sources) > 0 {
			c.startupLog().Warn(
				r.option+" is enabled together with "+strings.Join(sources, " and ")+
					", so an unauthenticated caller can aim "+r.widens+
					" at loopback, link-local and private-network addresses (SSRF exposure); "+
					"drop the option, or require an Initial Access Token and restrict "+
					"ClientIDMetadataDocuments.Allow",
				"option", r.option,
			)
			continue
		}
		c.startupLog().Info(
			r.option+" is enabled: "+r.widens+
				" may reach loopback, link-local and private-network addresses",
			"option", r.option,
		)
	}
}

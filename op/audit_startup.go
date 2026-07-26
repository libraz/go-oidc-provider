package op

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/op/feature"
)

// emitStartupProfile records the constructed Provider's security
// posture as a single [AuditStartupProfile] event. It runs from [New]
// once validation has succeeded, so every value it reports is the one
// the Provider will actually serve with — a configuration that would
// have produced a different answer never reaches this point.
//
// The record names both what the embedder declared (profiles,
// features, grants) and what those declarations resolved to. Both
// halves are needed: the declaration alone does not say which
// sender-constraining mechanism won the DPoP/mTLS disjunction or
// which token TTL survived the profile cap, and the resolved policy
// alone does not say whether a strict value was chosen deliberately
// or inherited from a profile.
func (c *config) emitStartupProfile(ctx context.Context) {
	c.effectiveAuditEmitter().Emit(ctx, audit.Event{
		Name:    string(auditevent.AuditStartupProfile),
		Level:   audit.LevelInfo,
		Message: "provider constructed",
		Extras:  c.startupProfileExtras(),
	})
}

// startupProfileExtras builds the event payload. It is split from the
// emit call so tests can assert on the projection without wiring a
// logger, and so the field set stays readable as it grows.
func (c *config) startupProfileExtras() map[string]any {
	return map[string]any{
		"profiles": c.declaredProfileNames(),
		"features": c.declaredFeatureNames(),
		"grants":   c.declaredGrantNames(),

		"pkce_required":           c.requirePKCE(),
		"par_required":            c.requirePAR(),
		"nonce_required":          c.requireNonce(),
		"state_or_nonce_required": c.requireStateOrNonce(),

		"sender_constrained": c.senderConstraintLabel(),
		// An empty slice means no profile narrowed the set, i.e. every
		// method a client registers is accepted.
		"client_auth_methods": c.startupClientAuthMethods(),

		"access_token_ttl_seconds":     int64(c.accessTokenTTL.Seconds()),
		"access_token_format":          c.accessTokenFormat.String(),
		"refresh_token_ttl_seconds":    int64(c.refreshTokenTTL.Seconds()),
		"refresh_grace_period_seconds": int64(c.resolvedRefreshGrace().Seconds()),

		"dpop_nonce_required":                 c.startupDPoPNonceRequired(),
		"signed_request_object_required":      c.requireSignedRequestObject(),
		"signed_backchannel_request_required": c.requireSignedBackchannelRequest(),
		"jarm_required":                       c.requireJARMResponseMode(),
		"signed_introspection_required":       c.requireSignedIntrospection(),
	}
}

// declaredProfileNames projects [config.profiles] onto its canonical
// wire identifiers, preserving the order the embedder declared them.
// Declaration order is kept rather than sorted because a reader
// comparing two deployments' records wants to see the configuration
// as it was written.
func (c *config) declaredProfileNames() []string {
	out := make([]string, 0, len(c.profiles))
	for _, p := range c.profiles {
		out = append(out, p.String())
	}
	return out
}

// declaredFeatureNames projects [config.features] onto its canonical
// wire identifiers. The slice includes flags a profile auto-enabled,
// which is the point: it is the resolved feature set, not the literal
// [WithFeature] call list.
func (c *config) declaredFeatureNames() []string {
	out := make([]string, 0, len(c.features))
	for _, f := range c.features {
		out = append(out, f.String())
	}
	return out
}

// declaredGrantNames projects [config.grants] onto the RFC wire form
// of each grant_type, including the defaults [config.applyDefaults]
// supplied when the embedder called no grant option at all.
func (c *config) declaredGrantNames() []string {
	out := make([]string, 0, len(c.grants))
	for _, g := range c.grants {
		out = append(out, g.String())
	}
	return out
}

// startupClientAuthMethods returns the profile-narrowed client
// authentication set, or an empty slice when no active profile
// restricts it. The empty slice is deliberate: a nil would serialise
// as a missing field and read as "unknown" rather than "unrestricted".
func (c *config) startupClientAuthMethods() []string {
	names := c.profileAllowedAuthMethodNames()
	if names == nil {
		return []string{}
	}
	return names
}

// senderConstraintLabel describes how access tokens are bound to their
// holder. It reports "" when bearer tokens remain legal, and otherwise
// the mechanism(s) the deployment can actually satisfy — the profile
// constraint is a disjunction (DPoP OR mTLS), so which arm is live is
// a property of the feature set rather than of the profile.
func (c *config) senderConstraintLabel() string {
	if !c.requireSenderConstrainedTokens() {
		return ""
	}
	dpop := featureEnabled(c.features, feature.DPoP)
	mtls := featureEnabled(c.features, feature.MTLS)
	switch {
	case dpop && mtls:
		return "dpop+mtls"
	case dpop:
		return "dpop"
	case mtls:
		return "mtls"
	}
	// Unreachable while a profile is active: the validator rejects a
	// sender-constraining profile whose disjunctive requirement is
	// unmet. Reported rather than assumed away so a regression in that
	// gate is visible in the audit stream instead of silent.
	return "unsatisfied"
}

// resolvedRefreshGrace returns the grace window the token endpoint
// will apply, in wall-clock terms. [config.effectiveRefreshGrace]
// speaks the exchanger's sentinel dialect (0 = "use the default",
// negative = "explicit zero"), which is the wrong shape for an
// operator reading a duration out of an audit record.
func (c *config) resolvedRefreshGrace() time.Duration {
	switch grace := c.effectiveRefreshGrace(); {
	case grace < 0:
		return 0
	case grace == 0:
		return refresh.GraceTTLDefault
	default:
		return grace
	}
}

// startupDPoPNonceRequired reports whether the deployment will
// challenge clients for an RFC 9449 §8 server-supplied nonce. The
// mandate is profile-driven but only bites when DPoP is the active
// binding mechanism, which mirrors the condition the construction-time
// validator applies.
func (c *config) startupDPoPNonceRequired() bool {
	if !featureEnabled(c.features, feature.DPoP) {
		return false
	}
	for _, p := range c.profiles {
		if profileForcesDPoPNonce(p) {
			return true
		}
	}
	return false
}

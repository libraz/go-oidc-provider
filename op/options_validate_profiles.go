package op

import (
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cibaendpoint"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// isFAPI2Profile reports whether p is one of the FAPI 2.0 family
// profiles. Centralising the check lets future first-party / FAPI
// interactions extend the predicate without scattering profile
// enumerations across the option layer.
func isFAPI2Profile(p profile.Profile) bool {
	switch p {
	case profile.FAPI2Baseline, profile.FAPI2MessageSigning:
		return true
	case profile.Baseline, profile.FAPICIBA:
		return false
	}
	return false
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
	return c.validateProfileTiming(p, enabled)
}

// validateProfileTiming checks the [profile.Profile] MUST clauses that
// bound a TTL or a window: the max access-token TTL, the PAR lifetime
// ceiling, the DPoP nonce-source requirement, and the FAPI 2.0 refresh-
// grace cap. Extracted from [config.validateProfile] so the outer
// function stays under the linter's complexity budget; the checks run
// in the same order.
func (c *config) validateProfileTiming(p profile.Profile, enabled map[feature.Flag]struct{}) error {
	if maxTTL := profile.MaxAccessTokenTTL(p); maxTTL > 0 && c.accessTokenTTL > maxTTL {
		return &Error{
			Code: codeConfiguration,
			Description: "WithProfile " + p.String() +
				" caps WithAccessTokenTTL at " + maxTTL.String() +
				"; got " + c.accessTokenTTL.String(),
		}
	}
	if ceiling := profile.PARLifetimeCeiling(p); ceiling > 0 && c.parLifetime >= ceiling {
		return &Error{
			Code: codeConfiguration,
			Description: "WithProfile " + p.String() +
				" requires WithPARLifetime below " + ceiling.String() +
				"; got " + c.parLifetime.String(),
		}
	}
	if p == profile.FAPICIBA {
		if err := c.validateFAPICIBAExpiry(); err != nil {
			return err
		}
	}
	if profileForcesDPoPNonce(p) && hasDPoPFeature(enabled) && c.dpopNonces == nil {
		return &Error{
			Code: codeConfiguration,
			Description: "WithProfile " + p.String() +
				" requires WithDPoPNonceSource when WithFeature(DPoP) is active",
		}
	}
	// The bound is the window the profile itself resolves to when the
	// option is absent, not a strict zero. FAPI 2.0 §3.1.7 argues for
	// the tightest window a deployment can run, but a FAPI 2.0
	// deployment that configures nothing already runs
	// [refresh.GraceTTLDefault] — see [config.effectiveRefreshGrace]
	// for why that default cannot be narrowed. Rejecting every
	// non-zero value would therefore refuse configurations STRICTER
	// than the one the OP applies, pushing an embedder that asked for
	// a five-second window back onto the sixty-second default.
	if isFAPI2Profile(p) && c.refreshGracePeriodSet &&
		c.refreshGracePeriod > refresh.GraceTTLDefault {
		return &Error{
			Code: codeConfiguration,
			Description: "WithProfile " + p.String() +
				" caps WithRefreshGracePeriod at " +
				refresh.GraceTTLDefault.String() + "; got " +
				c.refreshGracePeriod.String(),
		}
	}
	return nil
}

// validateFAPICIBAExpiry rejects a configured CIBA default or maximum
// above the FAPI-CIBA cap. /bc-authorize enforces the cap only on a
// client-supplied requested_expiry; the default path issues whatever
// the configuration resolves to.
func (c *config) validateFAPICIBAExpiry() error {
	limit := cibaendpoint.FAPICIBAMaxExpiry
	for _, v := range []struct {
		option string
		value  time.Duration
	}{
		{"WithCIBADefaultExpiresIn", c.cibaDefaultExpiresIn},
		{"WithCIBAMaxExpiresIn", c.cibaMaxExpiresIn},
	} {
		if v.value > limit {
			return &Error{
				Code: codeConfiguration,
				Description: "WithProfile " + profile.FAPICIBA.String() +
					" caps " + v.option + " at " + limit.String() +
					"; got " + v.value.String(),
			}
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
	case grant.JWTBearer:
		return "WithJWTBearerGrant(...)"
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

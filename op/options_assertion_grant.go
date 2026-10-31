package op

import (
	"net/url"
	"slices"
	"strconv"

	"github.com/libraz/go-oidc-provider/op/grant"
)

// WithJWTBearerGrant enables the RFC 7523 §2.1 JWT bearer grant
// (urn:ietf:params:oauth:grant-type:jwt-bearer) with the trust
// declaration in g. The option:
//
//   - adds [grant.JWTBearer] to the resolved grant set on top of the
//     default or [WithGrants] set, regardless of option order, and
//     advertises it in grant_types_supported;
//   - is checked at [New], after every option has run: Issuers must be
//     non-empty, ResolveSubject non-nil, each Issuer non-empty, unique
//     and different from the OP issuer, exactly one of JWKSURI (https)
//     and JWKS set, AllowedClients non-empty, and a UserStore
//     configured, since every redeemed subject is confirmed through it.
//
// A client still has to list the grant type in its own grant_types.
// Listing [grant.JWTBearer] in [WithGrants] without this option fails
// [New]: the grant has nothing to verify assertions against.
//
// The jwt-bearer grant type is reserved whether or not this option is
// used, so [WithCustomGrant] under that name fails [New].
//
// The option may be supplied at most once; a repeat fails [New].
//
// Stable since v1.5.
func WithJWTBearerGrant(g JWTBearerGrant) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithJWTBearerGrant"); err != nil {
			return err
		}
		c.jwtBearerGrant = cloneJWTBearerGrant(g)
		return nil
	})
}

// cloneJWTBearerGrant deep-copies g so the caller mutating its slices
// after [New] cannot change the trust set at runtime.
func cloneJWTBearerGrant(g JWTBearerGrant) *JWTBearerGrant {
	out := &JWTBearerGrant{ResolveSubject: g.ResolveSubject}
	if g.Issuers != nil {
		out.Issuers = make([]AssertionIssuer, len(g.Issuers))
		for i, iss := range g.Issuers {
			iss.JWKS = slices.Clone(iss.JWKS)
			iss.AllowedClients = slices.Clone(iss.AllowedClients)
			out.Issuers[i] = iss
		}
	}
	return out
}

// WithIDJAGIssuance enables issuing Identity Assertion JWT Authorization
// Grants through RFC 8693 token exchange: a request with
// requested_token_type urn:ietf:params:oauth:token-type:id-jag and an ID
// token this OP issued as subject_token is admitted by p and answered
// with a signed ID-JAG. Without this option such a request is refused
// with invalid_request.
//
// The option enables the token-exchange grant type on its own; it does
// not require [RegisterTokenExchange]. p MUST be non-nil, and the option
// may be supplied at most once.
//
// Experimental: tracks an IETF draft, so the surface MAY change in a
// minor release on a wire-incompatible draft bump.
func WithIDJAGIssuance(p IDJAGIssuancePolicy) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithIDJAGIssuance"); err != nil {
			return err
		}
		if isNilLike(p) {
			return newConfigurationError("WithIDJAGIssuance requires a non-nil IDJAGIssuancePolicy", nil)
		}
		c.idjagIssuancePolicy = p
		return nil
	})
}

// validateJWTBearerGrant enforces the [WithJWTBearerGrant] trust
// declaration once every option has run, so the OP-issuer comparison
// holds whichever order [WithIssuer] and the grant option were written
// in. Listing [grant.JWTBearer] in [WithGrants] without the option is
// rejected here too, the same shape [config.validateCIBAGrant] takes.
func (c *config) validateJWTBearerGrant() error {
	g := c.jwtBearerGrant
	if g == nil {
		if slices.Contains(c.grants, grant.JWTBearer) {
			return newConfigurationError(
				"grant.JWTBearer is enabled through WithGrants but WithJWTBearerGrant(...) "+
					"is not configured; the grant needs trusted issuers and a subject resolver", nil,
			)
		}
		return nil
	}
	if len(g.Issuers) == 0 {
		return newConfigurationError("WithJWTBearerGrant requires at least one AssertionIssuer", nil)
	}
	if g.ResolveSubject == nil {
		return newConfigurationError("WithJWTBearerGrant requires a non-nil ResolveSubject", nil)
	}
	seen := make(map[string]struct{}, len(g.Issuers))
	for i, iss := range g.Issuers {
		if err := c.validateAssertionIssuer(i, iss); err != nil {
			return err
		}
		if _, dup := seen[iss.Issuer]; dup {
			return newConfigurationError(
				"WithJWTBearerGrant: duplicate Issuer "+strconv.Quote(iss.Issuer), nil,
			)
		}
		seen[iss.Issuer] = struct{}{}
	}
	if isNilLike(c.store) {
		// validateRequired has already failed; avoid dereferencing a nil store.
		return nil
	}
	if isNilLike(c.effectiveUserStore()) {
		return newConfigurationError(
			"WithJWTBearerGrant requires a UserStore: every subject ResolveSubject "+
				"returns is confirmed through it before a token is issued", nil,
		)
	}
	return nil
}

// validateAssertionIssuer checks one [AssertionIssuer] entry; i is its
// position, quoted in the error so a long issuer list stays debuggable.
func (c *config) validateAssertionIssuer(i int, iss AssertionIssuer) error {
	prefix := "WithJWTBearerGrant: Issuers[" + strconv.Itoa(i) + "]"
	switch {
	case iss.Issuer == "":
		return newConfigurationError(prefix+".Issuer must not be empty", nil)
	case iss.Issuer == c.issuer:
		return newConfigurationError(prefix+".Issuer must not equal the OP issuer", nil)
	case !iss.Profile.valid():
		return newConfigurationError(prefix+".Profile is not a defined AssertionProfile", nil)
	case (iss.JWKSURI == "") == (len(iss.JWKS) == 0):
		return newConfigurationError(prefix+" must set exactly one of JWKSURI and JWKS", nil)
	case iss.JWKSURI != "" && !isHTTPSURL(iss.JWKSURI):
		return newConfigurationError(prefix+".JWKSURI must be an absolute https URL", nil)
	case len(iss.AllowedClients) == 0:
		return newConfigurationError(prefix+".AllowedClients must name at least one client_id", nil)
	case slices.Contains(iss.AllowedClients, ""):
		return newConfigurationError(prefix+".AllowedClients must not contain an empty client_id", nil)
	}
	return nil
}

// isHTTPSURL reports whether raw parses as an absolute https URL with a
// host.
func isHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

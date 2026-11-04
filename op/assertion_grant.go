package op

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/assertiongrant"
)

// JWTBearerGrant declares the RFC 7523 §2.1 JWT bearer grant: which
// assertion issuers the OP trusts and how a verified assertion maps to a
// local subject. Pass it to [WithJWTBearerGrant].
//
// The token endpoint authenticates the client (a "none" client is
// refused), requires it to be listed in the issuer's
// [AssertionIssuer.AllowedClients], verifies the assertion against the
// issuer's keys, calls ResolveSubject, and confirms the subject through
// the configured UserStore before issuing an access token. No refresh
// token and no ID token are issued.
//
// Things a deployment must plan for:
//
//   - Every assertion's jti is single-use, in both profiles. A client
//     whose access token expires obtains a fresh assertion (a fresh
//     ID-JAG under [AssertionProfileIDJAG]) rather than replaying the old
//     one.
//   - Replay is detected through [store.ConsumedJTIStore]. A deployment
//     running several OP nodes MUST share that substore across them;
//     otherwise each node accepts the same assertion once and the replay
//     window is the assertion's lifetime.
//   - Issued access tokens are not backed by a grant record, so
//     [Provider.RevokeSubject] does not reach them. ResolveSubject and
//     the UserStore check stop the next issuance; a token already issued
//     lives out its normal TTL.
//   - Discovery advertises the grant type but never the trusted issuers.
//
// Stable since v1.5.
type JWTBearerGrant struct {
	// Issuers is the closed set of trusted assertion issuers. It MUST be
	// non-empty, and no two entries may share an Issuer.
	Issuers []AssertionIssuer

	// ResolveSubject maps a verified assertion to the local subject the
	// access token is issued for. It is required.
	//
	// Return [ErrUnknownAssertionSubject] when the assertion is valid but
	// names no provisioned account; the token endpoint answers
	// access_denied. Any other error, and an empty subject with a nil
	// error, answers server_error. A returned subject that the UserStore
	// does not know also answers access_denied.
	//
	// Called from the request goroutine; it MUST be safe for concurrent
	// use.
	ResolveSubject func(ctx context.Context, a AssertionSubject) (subject string, err error)
}

// AssertionIssuer is one trusted assertion issuer of a [JWTBearerGrant].
//
// Stable since v1.5.
type AssertionIssuer struct {
	// Issuer is matched exactly against the assertion's iss claim. It
	// MUST be non-empty and MUST NOT equal the OP's own issuer: an
	// assertion this OP minted for itself is not a cross-domain grant.
	Issuer string

	// JWKSURI is the https URL of the issuer's JWK Set. Exactly one of
	// JWKSURI and JWKS is set. Fetching follows the same network policy
	// as client jwks_uri, including [WithAllowPrivateNetwork] ([OutboundJWKS]).
	JWKSURI string

	// JWKS is the issuer's JWK Set inline, in the same JSON
	// representation as [store.Client.JWKs]. Exactly one of JWKSURI and
	// JWKS is set.
	JWKS []byte

	// AllowedClients lists the client_ids permitted to redeem this
	// issuer's assertions. It MUST be non-empty; an empty list is not
	// read as "every client".
	//
	// Under [AssertionProfileJWT] the assertion carries no binding to a
	// client, so any listed client holding a leaked assertion can redeem
	// it. Keep the list to the clients that are meant to act for this
	// issuer.
	AllowedClients []string

	// Profile selects the assertion profile the issuer's assertions are
	// verified against. The zero value is [AssertionProfileJWT].
	Profile AssertionProfile
}

// AssertionProfile selects how an [AssertionIssuer]'s assertions are
// verified.
//
// Stable since v1.5.
type AssertionProfile int

const (
	// AssertionProfileJWT is the plain RFC 7523 profile: typ absent or
	// "JWT", aud naming the OP issuer or the token endpoint URL, and a
	// mandatory single-use jti.
	//
	// Stable since v1.5.
	AssertionProfileJWT AssertionProfile = iota

	// AssertionProfileIDJAG is the Identity Assertion JWT Authorization
	// Grant profile (draft-ietf-oauth-identity-assertion-authz-grant):
	// typ "oauth-id-jag+jwt", aud naming the OP issuer only, a client_id
	// claim equal to the authenticated client, requested scope within
	// the scope claim, and any cnf matching the request's binding.
	//
	// Experimental: tracks an IETF draft, so the profile MAY change in a
	// minor release on a wire-incompatible draft bump.
	AssertionProfileIDJAG
)

// valid reports whether p is one of the defined profiles.
func (p AssertionProfile) valid() bool {
	switch p {
	case AssertionProfileJWT, AssertionProfileIDJAG:
		return true
	default:
		return false
	}
}

// AssertionSubject is the verified assertion handed to
// [JWTBearerGrant.ResolveSubject].
//
// Stable since v1.5.
type AssertionSubject struct {
	// Issuer is the assertion's iss, one of the configured
	// [AssertionIssuer.Issuer] values.
	Issuer string

	// Subject is the assertion's sub, verbatim.
	Subject string

	// ClientID is the authenticated client redeeming the assertion.
	ClientID string

	// Claims is the full verified claim set. It is read-only; claims a
	// profile defines beyond the RFC 7523 set (email under ID-JAG, for
	// instance) are read from here.
	Claims map[string]any
}

// ErrUnknownAssertionSubject is the sentinel
// [JWTBearerGrant.ResolveSubject] returns when a valid assertion names
// no provisioned account. The token endpoint maps it to access_denied.
//
// Stable since v1.5.
var ErrUnknownAssertionSubject = assertiongrant.ErrUnknownSubject

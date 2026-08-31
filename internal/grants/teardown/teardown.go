// Package teardown owns the retirement of credentials the OP issued
// under a grant.
//
// Every endpoint that has to make a credential stop working — the token
// endpoint's replay cascades and its post-mint cleanups, /revoke's
// RFC 7009 §2.1 cascade — routes through [Revoker] rather than calling
// the substores itself. Two properties motivate the single owner:
//
//   - The blast radius is stated in the type. A [Scope] is either
//     grant-wide or names the individual credentials one exchange
//     produced, so a caller cannot accidentally retire a sibling
//     exchange's still-valid access token by reaching for the
//     grant-keyed store method that happened to be at hand.
//   - The [store.AccessTokenRevocationStrategy] dispatch is closed
//     inside the type. Callers never branch on the strategy, so the
//     JWT half of a cascade cannot drift between the sites that run it
//     and the opaque half — which is strategy-independent, because an
//     opaque access token is a store row whatever the JWT strategy
//     says — cannot be forgotten at one site and applied at another.
//
// The refresh chain walk itself is NOT here: retiring a replayed
// rotation chain needs the parent-pointer walk and the audit vocabulary
// that live on the refresh exchanger. A caller that retires a replayed
// chain runs that first, then hands the resolved grant to
// [Revoker.Run] for the access-token classes.
package teardown

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/op/store"
)

// class is the bitmask of credential classes a [Scope] covers.
type class uint8

const (
	// classAccessTokens covers both access-token shapes: the JWT
	// access tokens the active revocation strategy describes and the
	// rows of the opaque access-token substore.
	classAccessTokens class = 1 << iota
	// classRefresh covers refresh tokens.
	classRefresh
)

// width is how far a [Scope] reaches: over a whole grant, or over the
// individual credentials the caller names.
type width uint8

const (
	widthNone width = iota
	widthGrant
	widthToken
)

// Scope names the credentials one teardown retires. Construct it with
// [WholeGrant], [AccessTokensOfGrant] or [IssuedCredentials]; the zero
// value retires nothing, which makes an unset scope a no-op rather
// than an accidental grant-wide sweep.
type Scope struct {
	// grantID keys every grant-wide rung. Empty means the grant could
	// not be resolved, which [Revoker.Run] reports rather than treating
	// as "nothing to retire".
	grantID string

	// accessTokenID and refreshToken name the individual credentials a
	// token-wide scope retires. Both are the wire values the OP handed
	// out (or would have handed out); the substores hash them as their
	// contracts require.
	accessTokenID string
	refreshToken  string

	width   width
	classes class
}

// WholeGrant returns the scope covering every credential issued under
// grantID: access tokens in both shapes and the grant's refresh tokens.
// It is the scope a confirmed compromise earns — RFC 9700 §2.2.2 for a
// replayed refresh token, RFC 6749 §4.1.2 for a replayed authorization
// code.
func WholeGrant(grantID string) Scope {
	return Scope{
		grantID: grantID,
		width:   widthGrant,
		classes: classAccessTokens | classRefresh,
	}
}

// AccessTokensOfGrant returns the scope covering every access token
// issued under grantID, in both shapes, and no refresh token. It is
// what a caller uses when it has already retired the refresh side
// through a path this package does not own (a chain walk from the
// replayed node, a /revoke chain revocation).
func AccessTokensOfGrant(grantID string) Scope {
	return Scope{
		grantID: grantID,
		width:   widthGrant,
		classes: classAccessTokens,
	}
}

// IssuedCredentials returns the scope covering only the credentials
// named by accessTokenID and refreshToken — the ones a single exchange
// produced — and nothing else issued under their grant. An empty value
// skips that class.
//
// This is the scope every post-mint cleanup owes. A grant is reused
// across exchanges for the same (subject, client) pair, so retiring
// grant-wide after an exchange failed mid-flight would take down the
// live credentials of earlier successful exchanges: the caller only
// ever holds the right to retire what it just minted.
func IssuedCredentials(accessTokenID, refreshToken string) Scope {
	return Scope{
		accessTokenID: accessTokenID,
		refreshToken:  refreshToken,
		width:         widthToken,
		classes:       classAccessTokens | classRefresh,
	}
}

// Surface names the substore rung a [Failure] came from. The values are
// a stable enum so an audit consumer can pre-aggregate them.
const (
	SurfaceJWTAccessTokens    = "jwt_access_tokens"
	SurfaceOpaqueAccessTokens = "opaque_access_tokens"
	SurfaceRefreshTokens      = "refresh_tokens"
)

// Failure reports one rung of a teardown that did not run.
type Failure struct {
	// Surface is one of the Surface* constants.
	Surface string
	// Err is the substore error.
	Err error
}

// Outcome reports what a teardown could not do. The zero value means
// every rung in scope completed.
type Outcome struct {
	// Failures holds one entry per rung that reported a transport
	// fault.
	Failures []Failure

	// UnresolvedGrant reports that a grant-wide teardown ran with no
	// grant to key on. Nothing was retired, and a caller MUST NOT read
	// it as "there was nothing to retire": it is the one state in
	// which the OP confirmed a compromise and retired nothing.
	UnresolvedGrant bool
}

// Complete reports whether every rung in scope ran.
func (o Outcome) Complete() bool {
	return len(o.Failures) == 0 && !o.UnresolvedGrant
}

// Revoker retires grant-issued credentials. All substore fields are
// optional: a nil substore means the deployment does not run that
// credential shape, and its rung is skipped.
type Revoker struct {
	// RefreshTokens retires refresh tokens.
	RefreshTokens store.RefreshTokenStore

	// OpaqueAccessTokens retires opaque access-token rows. The rung is
	// independent of Strategy: the strategy describes how a *JWT*
	// access token is made to stop verifying, and says nothing about a
	// substore row that is read on every introspection.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// AccessTokens and GrantRevocations back the JWT rung; which one
	// is consulted is decided by Strategy alone, inside this type.
	AccessTokens     store.AccessTokenRegistry
	GrantRevocations store.GrantRevocationStore

	// Strategy selects the JWT access-token revocation mechanism.
	Strategy store.AccessTokenRevocationStrategy

	// Now is the instant a grant tombstone records as its RevokedAt,
	// and TombstoneRetention is how long past Now the tombstone
	// outlives the longest access token issued under the grant.
	Now                time.Time
	TombstoneRetention time.Duration

	// Reason is the stable label written onto a grant tombstone so an
	// operator can tell a replay cascade from a client-driven revoke.
	Reason string
}

// Run retires everything in scope and reports what it could not
// retire. It never fails the request on the caller's behalf: each rung
// is attempted independently of the others, so one unreachable
// substore cannot suppress the retirement the remaining substores can
// still perform.
func (r Revoker) Run(ctx context.Context, s Scope) Outcome {
	switch s.width {
	case widthGrant:
		return r.runGrant(ctx, s)
	case widthToken:
		return r.runToken(ctx, s)
	case widthNone:
		return Outcome{}
	default:
		return Outcome{}
	}
}

// runGrant retires every credential of the classes in scope under
// s.grantID. An empty grant id retires nothing and is reported: it is
// the difference between "the grant held no credentials" and "the OP
// never found out which grant to clear".
func (r Revoker) runGrant(ctx context.Context, s Scope) Outcome {
	if s.grantID == "" {
		return Outcome{UnresolvedGrant: true}
	}
	var out Outcome
	if s.classes&classAccessTokens != 0 {
		if err := endpointsupport.RevokeJWTAccessTokensByGrant(ctx, endpointsupport.JWTGrantCascadeOpts{
			AccessTokens:       r.AccessTokens,
			GrantRevocations:   r.GrantRevocations,
			RevocationStrategy: r.Strategy,
		}, s.grantID, r.Now, r.TombstoneRetention, r.Reason); err != nil {
			out.add(SurfaceJWTAccessTokens, err)
		}
		if r.OpaqueAccessTokens != nil {
			if _, err := r.OpaqueAccessTokens.RevokeByGrant(ctx, s.grantID); err != nil {
				out.add(SurfaceOpaqueAccessTokens, err)
			}
		}
	}
	if s.classes&classRefresh != 0 && r.RefreshTokens != nil {
		if err := r.RefreshTokens.RevokeByGrant(ctx, s.grantID); err != nil {
			out.add(SurfaceRefreshTokens, err)
		}
	}
	return out
}

// runToken retires the individually named credentials. No JWT rung
// runs: a JWT access token that never reached the client is not a
// credential anyone holds, and the grant-keyed mechanisms the strategy
// offers cannot express "this one token" without taking the whole
// grant with it.
func (r Revoker) runToken(ctx context.Context, s Scope) Outcome {
	var out Outcome
	if s.classes&classAccessTokens != 0 && s.accessTokenID != "" && r.OpaqueAccessTokens != nil {
		if err := r.OpaqueAccessTokens.RevokeByID(ctx, s.accessTokenID); err != nil {
			out.add(SurfaceOpaqueAccessTokens, err)
		}
	}
	if s.classes&classRefresh != 0 && s.refreshToken != "" && r.RefreshTokens != nil {
		if err := r.RefreshTokens.RevokeChain(ctx, s.refreshToken); err != nil {
			out.add(SurfaceRefreshTokens, err)
		}
	}
	return out
}

func (o *Outcome) add(surface string, err error) {
	o.Failures = append(o.Failures, Failure{Surface: surface, Err: err})
}

// Package revocation owns the retirement of credentials the OP issued
// under a grant, and the checks that tell a verifier whether one has been
// retired.
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
// Refresh rotation chains are retired by [Retire] and [RetireRecord],
// which walk the parent pointers ([FindRoot]) and fall back to the grant;
// the refresh exchanger keeps only the audit vocabulary for a replayed
// chain. Its caller then hands the resolved grant to [Revoker.Run] for the
// access-token classes.
//
// The read side shares the same strategy dispatch: [JWTAccessTokenRevoked]
// is what /introspect, /userinfo and token exchange consult before
// accepting a JWT access token.
package revocation

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	// classIssuance closes the grant to further issuance: a grant
	// tombstone refusing the grant's refresh chains and unredeemed codes,
	// written under every strategy whenever the substore is wired. Under
	// the grant-tombstone strategy the same tombstone also retires the
	// grant's JWT access tokens.
	classIssuance
)

// width is how far a [Scope] reaches: over a whole grant, or over the
// individual credentials the caller names.
type width uint8

const (
	widthNone width = iota
	widthGrant
	widthChain
	widthToken
	widthJTI
)

// Scope names the credentials one teardown retires. Construct it with
// [WholeGrant], [CompromisedGrantAccessTokens], [AccessTokensOfGrant],
// [OpaqueAccessTokensOfChain], [IssuedCredentials] or [JWTAccessTokenByJTI]; the zero value
// retires nothing, which makes an unset scope a no-op rather than an
// accidental grant-wide sweep.
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

	// chainID names the refresh chain a chain-wide scope retires.
	chainID string

	// jti and expiresAt name the one JWT access token a JTI scope
	// retires: its identifier and its own "exp".
	jti       string
	expiresAt time.Time

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
		classes: classAccessTokens | classRefresh | classIssuance,
	}
}

// CompromisedGrantAccessTokens returns the scope covering every access
// token issued under grantID, in both shapes, and closing the grant to
// further issuance, but retiring no refresh token itself. It is the
// access-token half of a replay cascade whose refresh side the caller
// already retired through a chain walk this package does not own.
func CompromisedGrantAccessTokens(grantID string) Scope {
	return Scope{
		grantID: grantID,
		width:   widthGrant,
		classes: classAccessTokens | classIssuance,
	}
}

// AccessTokensOfGrant returns the scope covering every access token
// issued under grantID, in both shapes, and nothing else: the grant's
// other refresh chains and unredeemed codes keep redeeming. It is the
// RFC 7009 §2.1 cascade of revoking one refresh token, whose own chain
// the caller has already retired.
func AccessTokensOfGrant(grantID string) Scope {
	return Scope{
		grantID: grantID,
		width:   widthGrant,
		classes: classAccessTokens,
	}
}

// OpaqueAccessTokensOfChain returns the scope covering the opaque access
// tokens minted from one refresh chain of grantID, which a rotation
// retires before minting the next. The grant is shared by every session
// of one subject on one client, so this leaves the other sessions' tokens
// alone. It widens to every opaque access token of the grant when chainID
// is empty (a chain written before chains were recorded) or the substore
// cannot revoke by chain: over-revoking is the safe direction.
func OpaqueAccessTokensOfChain(grantID, chainID string) Scope {
	return Scope{
		grantID: grantID,
		chainID: chainID,
		width:   widthChain,
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

// JWTAccessTokenByJTI returns the scope covering the single JWT access
// token identified by jti, issued under grantID and expiring at expiresAt.
// It is the RFC 7009 revocation of one presented JWT: under the
// grant-tombstone strategy it writes a per-JTI denylist row rather than a
// grant tombstone, so the grant's other tokens keep verifying. The row
// outlives expiresAt by [ClockSkewAllowance].
func JWTAccessTokenByJTI(jti, grantID string, expiresAt time.Time) Scope {
	return Scope{
		grantID:   grantID,
		jti:       jti,
		expiresAt: expiresAt,
		width:     widthJTI,
		classes:   classAccessTokens,
	}
}

// Surface names the substore rung a [Failure] came from. The values are
// a stable enum so an audit consumer can pre-aggregate them.
const (
	SurfaceJWTAccessTokens    = "jwt_access_tokens"
	SurfaceOpaqueAccessTokens = "opaque_access_tokens"
	SurfaceRefreshTokens      = "refresh_tokens"
	SurfaceGrantIssuance      = "grant_issuance"
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

	// JTIPersisted reports that a [JWTAccessTokenByJTI] scope wrote a
	// revocation row. It is false under the none strategy and when no
	// substore backs the active strategy, where the token keeps
	// verifying until its own "exp".
	JTIPersisted bool
}

// Complete reports whether every rung in scope ran.
func (o Outcome) Complete() bool {
	return len(o.Failures) == 0 && !o.UnresolvedGrant
}

// Err folds an incomplete Outcome into one error naming every rung that
// did not run. It is nil when the Outcome is [Outcome.Complete].
func (o Outcome) Err() error {
	if o.UnresolvedGrant {
		return errors.New("grant could not be resolved")
	}
	errs := make([]error, len(o.Failures))
	for i, f := range o.Failures {
		errs[i] = fmt.Errorf("%s: %w", f.Surface, f.Err)
	}
	return errors.Join(errs...)
}

// ClockSkewAllowance is the slack added past a token's expiry before its
// revocation record may be dropped, for a verifier whose clock trails the
// OP's.
const ClockSkewAllowance = 5 * time.Minute

// TombstoneRetention returns how long past its RevokedAt a grant
// tombstone must survive: the access-token TTL (one hour when unset)
// plus [ClockSkewAllowance].
func TombstoneRetention(accessTokenTTL time.Duration) time.Duration {
	if accessTokenTTL <= 0 {
		accessTokenTTL = time.Hour
	}
	return accessTokenTTL + ClockSkewAllowance
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

// NewRevoker returns a Revoker over the given substores. now stamps grant
// tombstones, accessTokenTTL sizes their retention through
// [TombstoneRetention], and reason labels them.
func NewRevoker(
	refreshTokens store.RefreshTokenStore,
	opaqueAccessTokens store.OpaqueAccessTokenStore,
	accessTokens store.AccessTokenRegistry,
	grantRevocations store.GrantRevocationStore,
	strategy store.AccessTokenRevocationStrategy,
	accessTokenTTL time.Duration,
	now time.Time,
	reason string,
) Revoker {
	return Revoker{
		RefreshTokens:      refreshTokens,
		OpaqueAccessTokens: opaqueAccessTokens,
		AccessTokens:       accessTokens,
		GrantRevocations:   grantRevocations,
		Strategy:           strategy,
		Now:                now.UTC(),
		TombstoneRetention: TombstoneRetention(accessTokenTTL),
		Reason:             reason,
	}
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
	case widthChain:
		return r.runChain(ctx, s)
	case widthToken:
		return r.runToken(ctx, s)
	case widthJTI:
		return r.runJTI(ctx, s)
	case widthNone:
		return Outcome{}
	default:
		return Outcome{}
	}
}

// RevokeGrant retires every credential issued under grantID and then
// deletes the grant record. The record is deleted only when every rung
// completed, so a partial teardown leaves the grant live for a retry; a
// record that is already gone counts as deleted.
func (r Revoker) RevokeGrant(ctx context.Context, grants store.GrantStore, grantID string) error {
	if err := r.Run(ctx, WholeGrant(grantID)).Err(); err != nil {
		return err
	}
	if err := grants.Delete(ctx, grantID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("delete grant: %w", err)
	}
	return nil
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
		r.revokeGrantAccessTokens(ctx, s, &out)
	}
	if r.owesIssuanceClosure(s) {
		if err := r.GrantRevocations.RevokeGrant(ctx, r.issuanceTombstone(s.grantID)); err != nil {
			out.add(SurfaceGrantIssuance, err)
		}
	}
	if s.classes&classRefresh != 0 && r.RefreshTokens != nil {
		if err := r.RefreshTokens.RevokeByGrant(ctx, s.grantID); err != nil {
			out.add(SurfaceRefreshTokens, err)
		}
	}
	return out
}

// revokeGrantAccessTokens runs the JWT and opaque access-token rungs of a
// grant teardown, recording each failure on out.
func (r Revoker) revokeGrantAccessTokens(ctx context.Context, s Scope, out *Outcome) {
	if err := RevokeJWTAccessTokensByGrant(ctx, JWTGrantCascadeOpts{
		AccessTokens:       r.AccessTokens,
		GrantRevocations:   r.GrantRevocations,
		RevocationStrategy: r.Strategy,
	}, s.grantID, r.Now, r.TombstoneRetention, r.Reason, s.classes&classIssuance == 0); err != nil {
		out.add(SurfaceJWTAccessTokens, err)
	}
	if r.OpaqueAccessTokens != nil {
		if _, err := r.OpaqueAccessTokens.RevokeByGrant(ctx, s.grantID); err != nil {
			out.add(SurfaceOpaqueAccessTokens, err)
		}
	}
}

// owesIssuanceClosure reports whether runGrant must write the issuance
// tombstone itself because the JWT access-token rung did not.
func (r Revoker) owesIssuanceClosure(s Scope) bool {
	if s.classes&classIssuance == 0 || r.GrantRevocations == nil {
		return false
	}
	return s.classes&classAccessTokens == 0 || !r.jwtRungClosesIssuance()
}

// jwtRungClosesIssuance reports whether the JWT access-token rung already
// writes the grant tombstone that closes issuance: only the grant-tombstone
// strategy (and any strategy the JWT rung treats like it) with a wired
// substore does. Every other strategy still owes the closure record, which
// the token endpoint consults after persisting so a credential minted while
// the teardown ran cannot outlive it.
func (r Revoker) jwtRungClosesIssuance() bool {
	switch r.Strategy {
	case store.RevocationStrategyJTIRegistry, store.RevocationStrategyNone:
		return false
	default:
		return r.GrantRevocations != nil
	}
}

// issuanceTombstone is the grant tombstone closing grantID to issuance, with
// the same RevokedAt, retention and reason the JWT rung writes, so GC
// reclaims it on the same schedule whichever rung wrote it.
func (r Revoker) issuanceTombstone(grantID string) store.GrantTombstone {
	return store.GrantTombstone{
		GrantID:   grantID,
		RevokedAt: r.Now,
		ExpiresAt: r.Now.Add(r.TombstoneRetention),
		Reason:    r.Reason,
	}
}

// runChain retires the opaque access tokens of one refresh chain. No JWT
// rung runs: the grant-keyed mechanisms the strategy offers cannot express
// one chain, and a rotation leaves a chain's JWT access tokens to expire.
func (r Revoker) runChain(ctx context.Context, s Scope) Outcome {
	if s.grantID == "" {
		return Outcome{UnresolvedGrant: true}
	}
	if r.OpaqueAccessTokens == nil {
		return Outcome{}
	}
	var err error
	if chains, ok := r.OpaqueAccessTokens.(store.OpaqueAccessTokenChainRevoker); ok && s.chainID != "" {
		_, err = chains.RevokeByChain(ctx, s.grantID, s.chainID)
	} else {
		_, err = r.OpaqueAccessTokens.RevokeByGrant(ctx, s.grantID)
	}
	var out Outcome
	if err != nil {
		out.add(SurfaceOpaqueAccessTokens, err)
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

// runJTI retires one JWT access token by its identifier under the active
// strategy. Store faults are reported as a [SurfaceJWTAccessTokens] failure.
func (r Revoker) runJTI(ctx context.Context, s Scope) Outcome {
	persisted, err := revokeJWTAccessTokenByJTI(ctx, JWTGrantCascadeOpts{
		AccessTokens:       r.AccessTokens,
		GrantRevocations:   r.GrantRevocations,
		RevocationStrategy: r.Strategy,
	}, s.jti, s.grantID, s.expiresAt.Add(ClockSkewAllowance).UTC())
	out := Outcome{JTIPersisted: persisted}
	if err != nil {
		out.add(SurfaceJWTAccessTokens, err)
	}
	return out
}

func (o *Outcome) add(surface string, err error) {
	o.Failures = append(o.Failures, Failure{Surface: surface, Err: err})
}

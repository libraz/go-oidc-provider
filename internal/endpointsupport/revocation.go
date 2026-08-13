package endpointsupport

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// JWTRevocationOpts bundles the substores and strategy the shared JWT
// revocation helper consults.
type JWTRevocationOpts struct {
	AccessTokens       store.AccessTokenRegistry
	GrantRevocations   store.GrantRevocationStore
	Clients            store.ClientStore
	RevocationStrategy store.AccessTokenRevocationStrategy
}

// RequireJTIFor reports whether an access-token verifier built for
// strategy MUST reject a token carrying no "jti" claim. It is the
// single place the answer is decided so the four endpoints that verify
// JWT access tokens (/userinfo, /introspect, /revoke, token exchange)
// cannot drift apart on it.
//
// Every strategy other than [store.RevocationStrategyNone] has at least
// one revocation path that can only be answered through the jti, and
// [JWTAccessTokenRevoked] reports "not revoked" when it cannot answer:
//
//   - [store.RevocationStrategyJTIRegistry] keys the whole lookup on
//     the jti, so an empty one finds no row and reads as live.
//   - [store.RevocationStrategyGrantTombstone] answers a grant-bound
//     token from its "gid" claim, but a grantless one — a
//     client_credentials token carries no grant — is covered only by
//     the jti denylist row /revocation wrote for it.
//
// Under None no per-token state is consulted at all, so demanding a jti
// would reject tokens without protecting anything.
func RequireJTIFor(strategy store.AccessTokenRevocationStrategy) bool {
	return strategy != store.RevocationStrategyNone
}

// JWTAccessTokenRevoked reports whether claims should be treated as
// revoked under opts.RevocationStrategy. The second return reports
// whether the lookup succeeded; callers decide how a lookup failure is
// surfaced on the wire (inactive vs 5xx vs challenge).
//
// Strategy semantics:
//   - RevocationStrategyNone: never revoked, lookup succeeded.
//   - RevocationStrategyJTIRegistry: consult AccessTokens.Find(jti).
//   - RevocationStrategyGrantTombstone: consult
//     GrantRevocations.IsRevoked(grantID, jti, iat) whenever
//     GrantRevocations is present, then fall back to the JTI registry
//     for a grantless token when the tombstone substore reported it
//     live (the legacy migration window).
//
// Every strategy except None first requires the client the token was
// issued to still to be registered; see [clientDeleted].
//
// A missing JTI row is accepted so directly-constructed test tokens and
// external-issuer registries do not flip the contract. A substore error
// returns (false, false).
func JWTAccessTokenRevoked(
	ctx context.Context,
	opts JWTRevocationOpts,
	claims *tokens.AccessTokenClaims,
) (revoked, ok bool) {
	if opts.RevocationStrategy == store.RevocationStrategyNone {
		// The strategy is a declaration that no per-token state is
		// consulted, so the client probe belongs behind it too.
		return false, true
	}
	gone, resolved := clientDeleted(ctx, opts.Clients, claims.ClientID)
	if !resolved {
		return false, false
	}
	if gone {
		return true, true
	}
	switch opts.RevocationStrategy {
	case store.RevocationStrategyNone:
		return false, true
	case store.RevocationStrategyJTIRegistry:
		return jwtAccessTokenRevokedByJTI(ctx, opts.AccessTokens, claims)
	default:
		return jwtAccessTokenRevokedByTombstone(ctx, opts, claims)
	}
}

// clientDeleted reports whether the client named by the token's
// client_id claim has left the registry. The second return reports
// whether the question could be answered at all.
//
// This is what makes a client deletion reach a JWT access token. The
// other two mechanisms cannot: a grant tombstone is keyed on grant_id
// and deleting a client yields no list of grant IDs to write tombstones
// for, and a client_credentials token carries no grant at all, so no
// per-grant cascade could ever cover it. Deriving the answer from the
// client_id the token already carries needs no enumeration, no new
// substore, and no write on the delete path.
//
// The inference is only available here because the token arrived
// signed by the OP's own key: the OP issued it, so the client existed
// at issuance, and its absence now means it was removed. That is a
// stronger reading than a missing JTI row, which can simply mean the
// deployment records no rows.
//
// A nil registry or an empty client_id skips the probe rather than
// failing closed — a token minted outside the registry is not evidence
// of a deletion. A lookup error other than [store.ErrNotFound] is
// reported as unresolved so the caller applies its own posture.
func clientDeleted(ctx context.Context, clients store.ClientStore, clientID string) (gone, resolved bool) {
	if clients == nil || clientID == "" {
		return false, true
	}
	if _, err := clients.GetClient(ctx, clientID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return true, true
		}
		return false, false
	}
	return false, true
}

func jwtAccessTokenRevokedByTombstone(
	ctx context.Context,
	opts JWTRevocationOpts,
	claims *tokens.AccessTokenClaims,
) (revoked, ok bool) {
	if opts.GrantRevocations != nil {
		// The substore evaluates its two inputs independently: the JTI
		// denylist keyed on the token's jti and the grant tombstone keyed
		// on its "gid" private claim. Both are handed over unconditionally
		// so a grantless access token -- client_credentials mints one with
		// no "gid" -- is still closed by the denylist row /revocation
		// wrote for it. Gating the whole call on a non-empty GrantID would
		// leave that row unread.
		got, err := opts.GrantRevocations.IsRevoked(
			ctx,
			claims.GrantID,
			claims.JTI,
			time.Unix(claims.IssuedAt, 0).UTC(),
		)
		if err != nil {
			return false, false
		}
		if got {
			return true, true
		}
		if claims.GrantID != "" {
			// A grant-bound token is fully described by the tombstone
			// substore, so the registry fallback below does not apply.
			return false, true
		}
	}
	if opts.AccessTokens == nil {
		return false, true
	}
	return jwtAccessTokenRevokedByJTI(ctx, opts.AccessTokens, claims)
}

func jwtAccessTokenRevokedByJTI(
	ctx context.Context,
	reg store.AccessTokenRegistry,
	claims *tokens.AccessTokenClaims,
) (revoked, ok bool) {
	if reg == nil {
		return false, true
	}
	rec, err := reg.Find(ctx, claims.JTI)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, true
		}
		return false, false
	}
	return rec != nil && rec.Revoked, true
}

// JWTGrantCascadeOpts bundles the substores and strategy the shared JWT
// grant-cascade helper consults.
type JWTGrantCascadeOpts struct {
	AccessTokens       store.AccessTokenRegistry
	GrantRevocations   store.GrantRevocationStore
	RevocationStrategy store.AccessTokenRevocationStrategy
}

// RevokeJWTAccessTokensByGrant applies the JWT access-token cascade for
// one grant under opts.RevocationStrategy.
//
// Strategy semantics:
//   - RevocationStrategyNone: no-op.
//   - RevocationStrategyJTIRegistry: call AccessTokens.RevokeByGrant.
//   - RevocationStrategyGrantTombstone: write a GrantTombstone with the
//     supplied (now, retention, reason). When GrantRevocations is nil,
//     fall back to the JTI registry so partially migrated deployments
//     keep the cascade semantics they already had.
//
// Store errors are returned to the caller. Each endpoint decides whether its
// user-visible contract is fail-closed (for example Grant Management revoke)
// or best-effort (for example browser logout), while sharing the same cascade
// implementation.
func RevokeJWTAccessTokensByGrant(
	ctx context.Context,
	opts JWTGrantCascadeOpts,
	grantID string,
	now time.Time,
	retention time.Duration,
	reason string,
) error {
	switch opts.RevocationStrategy {
	case store.RevocationStrategyNone:
		return nil
	case store.RevocationStrategyJTIRegistry:
		if opts.AccessTokens != nil {
			_, err := opts.AccessTokens.RevokeByGrant(ctx, grantID)
			return err
		}
		return nil
	default:
		if opts.GrantRevocations != nil && grantID != "" {
			return opts.GrantRevocations.RevokeGrant(ctx, store.GrantTombstone{
				GrantID:   grantID,
				RevokedAt: now,
				ExpiresAt: now.Add(retention),
				Reason:    reason,
			})
		}
		if opts.AccessTokens != nil {
			_, err := opts.AccessTokens.RevokeByGrant(ctx, grantID)
			return err
		}
		return nil
	}
}

// RevokeJWTAccessTokenByJTI revokes one JWT access token under
// opts.RevocationStrategy. Under GrantTombstone it writes a per-JTI
// denylist row (not a grant tombstone); when GrantRevocations is nil it
// falls back to AccessTokens.RevokeByJTI for the migration window.
//
// The helper intentionally swallows store errors; callers keep their
// wire-level success posture and rely on audit / retries for
// observability.
func RevokeJWTAccessTokenByJTI(
	ctx context.Context,
	opts JWTGrantCascadeOpts,
	jti, grantID string,
	expiresAt time.Time,
) error {
	switch opts.RevocationStrategy {
	case store.RevocationStrategyNone:
		return nil
	case store.RevocationStrategyJTIRegistry:
		if opts.AccessTokens != nil {
			return opts.AccessTokens.RevokeByJTI(ctx, jti)
		}
		return nil
	default:
		if opts.GrantRevocations != nil {
			return opts.GrantRevocations.RevokeJTI(ctx, store.RevokedJTI{
				JTI:       jti,
				GrantID:   grantID,
				ExpiresAt: expiresAt,
			})
		}
		if opts.AccessTokens != nil {
			return opts.AccessTokens.RevokeByJTI(ctx, jti)
		}
		return nil
	}
}

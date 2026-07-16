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
	RevocationStrategy store.AccessTokenRevocationStrategy
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
//     GrantRevocations.IsRevoked(grantID, jti, iat) when both grantID
//     and GrantRevocations are present; otherwise fall back to the JTI
//     registry for the legacy migration window.
//
// A missing JTI row is accepted so directly-constructed test tokens and
// external-issuer registries do not flip the contract. A substore error
// returns (false, false).
func JWTAccessTokenRevoked(
	ctx context.Context,
	opts JWTRevocationOpts,
	claims *tokens.AccessTokenClaims,
) (revoked, ok bool) {
	switch opts.RevocationStrategy {
	case store.RevocationStrategyNone:
		return false, true
	case store.RevocationStrategyJTIRegistry:
		return jwtAccessTokenRevokedByJTI(ctx, opts.AccessTokens, claims)
	default:
		return jwtAccessTokenRevokedByTombstone(ctx, opts, claims)
	}
}

func jwtAccessTokenRevokedByTombstone(
	ctx context.Context,
	opts JWTRevocationOpts,
	claims *tokens.AccessTokenClaims,
) (revoked, ok bool) {
	if claims.GrantID != "" && opts.GrantRevocations != nil {
		got, err := opts.GrantRevocations.IsRevoked(
			ctx,
			claims.GrantID,
			claims.JTI,
			time.Unix(claims.IssuedAt, 0).UTC(),
		)
		if err != nil {
			return false, false
		}
		return got, true
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

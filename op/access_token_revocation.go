package op

import "github.com/libraz/go-oidc-provider/op/store"

// AccessTokenRevocationStrategy selects the persistence shape behind
// JWT access-token revocation. It is a type alias of
// [store.AccessTokenRevocationStrategy] so the public option layer
// and the internal handlers can converge on a single enum without
// internal/* taking a dependency on op/.
//
// The strategy is fixed at [New] time and applies uniformly to every
// JWT access token minted by that provider. The opaque access-token
// path ([WithAccessTokenFormat] with [AccessTokenFormatOpaque]) is
// intrinsically per-token in storage and is unaffected by this enum.
//
// The primary axis the strategy controls is **whether the OP writes a
// row to its store on every JWT AT issuance**. Embedders who want to
// keep the issuance hot path stateless pick
// [RevocationStrategyGrantTombstone] (the default) or
// [RevocationStrategyNone]; embedders who want a per-AT audit trail
// pick [RevocationStrategyJTIRegistry].
//
// Stable since v1.0.
type AccessTokenRevocationStrategy = store.AccessTokenRevocationStrategy

// RevocationStrategyGrantTombstone is the default JWT access-token
// revocation strategy.
//
//	Writes per AT issuance:    0
//	Writes per grant revoke:   1 (tombstone row)
//	Writes per single-AT revoke: 1 (denylist row, RFC 7009)
//	Steady-state row count:    O(revoked grants + revoked JTIs)
//
// The OP embeds a "gid" private claim (the GrantID) in every issued
// JWT AT and consults a small per-grant tombstone table at
// verification. Cascades (logout, code-replay, refresh rotation)
// write one row per revoked grant rather than one row per AT under
// that grant. Suitable for the vast majority of deployments: the
// issuance hot path is a pure compute path, and revocation still
// fully covers RFC 6749 §4.1.2, RFC 6819 §5.2.1.1, RFC 7009, and
// OIDC RP-Initiated Logout 1.0 §5. Conformant with FAPI 2.0 SP
// §5.3.2.2.
const RevocationStrategyGrantTombstone = store.RevocationStrategyGrantTombstone

// RevocationStrategyJTIRegistry preserves the per-JTI registry model.
//
//	Writes per AT issuance:    1 (shadow row)
//	Writes per grant revoke:   N (one per AT in grant — UPDATE)
//	Writes per single-AT revoke: 1 (UPDATE on existing row)
//	Steady-state row count:    O(issuance_rate × AT_TTL)
//
// Every issued AT is shadowed by an [store.AccessTokenRecord];
// revocation flips the row's Revoked column. Conformant with
// FAPI 2.0 SP §5.3.2.2. Pin this strategy when per-AT audit trails
// are a regulatory requirement and the issuance write throughput is
// acceptable.
const RevocationStrategyJTIRegistry = store.RevocationStrategyJTIRegistry

// RevocationStrategyNone disables server-side JWT revocation.
//
//	Writes per AT issuance:    0
//	Writes per revocation call: 0 (returns 200 idempotently)
//	Steady-state row count:    0 for JWT AT
//
// JWT ATs live until exp; /revocation returns 200 (RFC 7009 §2.2
// idempotent) but is a no-op; /userinfo and /introspection skip the
// revocation check. /end_session terminates the session and deletes
// refresh tokens but does NOT invalidate outstanding JWT ATs — they
// remain valid until exp. Suitable for stateless deployments that
// accept the RFC 6749 §4.1.2 "SHOULD revoke (when possible)" wiggle.
//
// Rejected at [New] under any FAPI profile (FAPI 2.0 Security
// Profile §5.3.2.2 mandates server-side revocation).
const RevocationStrategyNone = store.RevocationStrategyNone

// WithAccessTokenRevocationStrategy selects how the OP persists JWT
// access-token revocation state. The default is
// [RevocationStrategyGrantTombstone] (no store writes at issuance,
// O(revoked grants) at the rest).
//
// The opaque AT path ([WithAccessTokenFormat] with
// [AccessTokenFormatOpaque]) is unaffected: opaque tokens are
// intrinsically per-token in storage because verification needs the
// row.
//
// Unknown values are rejected at construction time. FAPI profiles
// reject [RevocationStrategyNone] at [New] (FAPI 2.0 Security Profile
// §5.3.2.2 mandates server-side revocation); see
// [profile.RequiresAccessTokenRevocation].
//
// Stable since v1.0.
func WithAccessTokenRevocationStrategy(s AccessTokenRevocationStrategy) Option {
	return optionFunc(func(c *config) error {
		if !s.IsValid() {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithAccessTokenRevocationStrategy received an unknown AccessTokenRevocationStrategy value",
			}
		}
		c.atRevocation = s
		return nil
	})
}

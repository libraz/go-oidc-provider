package store

import "fmt"

// AccessTokenRevocationStrategy selects the persistence shape behind
// JWT access-token revocation. The type lives in this package
// so internal handlers can reference it without taking a dependency
// on the op public package; the public alias
// [op.AccessTokenRevocationStrategy] re-exports it for embedders.
//
// The strategy is fixed at op.New time and applies uniformly to every
// JWT access token minted by that provider. The opaque access-token
// path is intrinsically per-token in storage and is unaffected by
// this enum.
//
// The primary axis the strategy controls is **whether the OP writes a
// row to its store on every JWT AT issuance**. Embedders who want to
// keep the issuance hot path stateless pick GrantTombstone (the
// default) or None; embedders who want a per-AT audit trail pick
// JTIRegistry.
type AccessTokenRevocationStrategy int

const (
	// RevocationStrategyGrantTombstone is the default.
	//
	//   Writes per AT issuance:    0
	//   Writes per grant revoke:   1 (tombstone row)
	//   Writes per single-AT revoke: 1 (denylist row, RFC 7009)
	//   Steady-state row count:    O(revoked grants + revoked JTIs)
	//
	// The OP embeds a "gid" private claim (the GrantID) in every
	// issued JWT AT and consults a small per-grant tombstone table
	// at verification. Cascades (logout, code-replay, refresh
	// rotation) write one row per revoked grant rather than one row
	// per AT under that grant. Suitable for the vast majority of
	// deployments: the issuance hot path is a pure compute path,
	// and revocation still fully covers RFC 6749 §4.1.2,
	// RFC 6819 §5.2.1.1, RFC 7009, and OIDC RP-Initiated Logout 1.0
	// §5. Conformant with FAPI 2.0 SP §5.3.2.2.
	RevocationStrategyGrantTombstone AccessTokenRevocationStrategy = iota

	// RevocationStrategyJTIRegistry preserves the model.
	//
	//   Writes per AT issuance:    1 (shadow row)
	//   Writes per grant revoke:   N (one per AT in grant — UPDATE)
	//   Writes per single-AT revoke: 1 (UPDATE on existing row)
	//   Steady-state row count:    O(issuance_rate × AT_TTL)
	//
	// Every issued AT is shadowed by an [AccessTokenRecord];
	// revocation flips the row's Revoked column. Conformant with
	// FAPI 2.0 SP §5.3.2.2. Pin this strategy when per-AT audit
	// trails are a regulatory requirement and the issuance write
	// throughput is acceptable.
	RevocationStrategyJTIRegistry

	// RevocationStrategyNone disables server-side JWT revocation.
	//
	//   Writes per AT issuance:    0
	//   Writes per revocation call: 0 (returns 200 idempotently)
	//   Steady-state row count:    0 for JWT AT
	//
	// JWT ATs live until exp; /revocation returns 200 (RFC 7009
	// §2.2 idempotent) but is a no-op; /userinfo and /introspection
	// skip the revocation check. /end_session terminates the
	// session and deletes refresh tokens but does NOT invalidate
	// outstanding JWT ATs — they remain valid until exp. Suitable
	// for stateless deployments that accept the RFC 6749 §4.1.2
	// "SHOULD revoke (when possible)" wiggle.
	//
	// Rejected at op.New under any FAPI profile (FAPI 2.0 Security
	// Profile §5.3.2.2 mandates server-side revocation).
	RevocationStrategyNone
)

// IsValid reports whether s is one of the documented constants. The
// option layer rejects unknown values at construction time so a caller
// passing AccessTokenRevocationStrategy(99) gets a fail-fast error
// instead of a silent fall-through to the default.
func (s AccessTokenRevocationStrategy) IsValid() bool {
	switch s {
	case RevocationStrategyGrantTombstone,
		RevocationStrategyJTIRegistry,
		RevocationStrategyNone:
		return true
	}
	return false
}

// String returns a stable human-readable identifier for the strategy
// suitable for diagnostics, audit lines, and error messages. The
// values match the constant names without the "RevocationStrategy"
// prefix so log readers can pattern-match on the strategy axis without
// re-implementing the enum.
//
// Unknown values stringify as "AccessTokenRevocationStrategy(<int>)"
// so a regression in the option-layer validator surfaces in
// audit / log lines without crashing.
func (s AccessTokenRevocationStrategy) String() string {
	switch s {
	case RevocationStrategyGrantTombstone:
		return "GrantTombstone"
	case RevocationStrategyJTIRegistry:
		return "JTIRegistry"
	case RevocationStrategyNone:
		return "None"
	}
	return fmt.Sprintf("AccessTokenRevocationStrategy(%d)", int(s))
}

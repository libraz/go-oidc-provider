package store

import (
	"context"
	"time"
)

// GrantTombstone is the persistent record of a revoked grant (ADR 0025).
// The OP writes one row the moment a grant is revoked; verification of a
// JWT access token consults the row keyed by the access token's "gid"
// private claim. The rule "revoked iff iat <= RevokedAt" defends against
// the tombstone-after-mint race where a fresh access token minted in the
// same wall-clock instant as the [GrantRevocationStore.RevokeGrant] call
// must still be rejected.
//
// The struct is defensively cloned on every Save / Find roundtrip in the
// reference implementation so callers cannot mutate the stored row by
// holding on to a returned pointer.
type GrantTombstone struct {
	// GrantID is the [Grant.ID] this tombstone applies to. The field is
	// the primary key of the substore's tombstone table.
	GrantID string

	// RevokedAt is the wall-clock instant at which the cascade ran. The
	// verifier rejects every JWT access token whose iat is less than or
	// equal to this value; tokens minted strictly after the tombstone
	// are accepted (the issuance path independently refuses to mint
	// under a tombstoned grant, so this rule is defence in depth).
	RevokedAt time.Time

	// ExpiresAt bounds the row's lifetime. Embedders compute it as
	// max(RevokedAt + max_AT_TTL + grace) so any access token issued
	// before the cascade is guaranteed to have expired before its
	// tombstone disappears. [GrantRevocationStore.GC] drops rows whose
	// ExpiresAt is strictly before the supplied cutoff; the zero time
	// is treated as "no expiry" and is never collected.
	ExpiresAt time.Time

	// Reason is a free-form audit hint -- typically one of
	// "code_replay", "logout", "operator", or the empty string. The
	// store does NOT validate the value; it is stored verbatim so an
	// audit log can recover the cascade trigger without consulting a
	// second substore.
	Reason string
}

// RevokedJTI records a single JWT access token revoked through the
// RFC 7009 /revocation endpoint by jti (ADR 0025). The store keeps one
// row per direct access-token revocation (rare in practice; cascades use
// [GrantTombstone]).
//
// The struct is defensively cloned on every Save / Find roundtrip in the
// reference implementation so callers cannot mutate the stored row by
// holding on to a returned pointer.
type RevokedJTI struct {
	// JTI is the access token's RFC 7519 jti claim. The field is the
	// primary key of the substore's denylist table; the JTI is a
	// non-secret claim so backends store it verbatim (no hash-on-store
	// contract applies, unlike bearer secrets).
	JTI string

	// GrantID is the [Grant.ID] the access token descended from,
	// preserved for audit. The verifier consults the denylist before the
	// tombstone, so this field does NOT participate in the lookup; it is
	// recoverable so cascade tooling can reconstruct the affected grant
	// without re-decoding the original token.
	GrantID string

	// ExpiresAt bounds the row's lifetime. Embedders typically compute
	// it as max(token_exp + grace) so the denylist row outlives the
	// access token by at least one grace window.
	// [GrantRevocationStore.GC] drops rows whose ExpiresAt is strictly
	// before the supplied cutoff; the zero time is treated as "no
	// expiry" and is never collected.
	ExpiresAt time.Time
}

// GrantRevocationStore is the substore for the grant-tombstone JWT
// access-token revocation strategy (ADR 0025). It belongs to the
// transactional cluster: a [GrantRevocationStore.RevokeGrant] /
// [GrantRevocationStore.RevokeJTI] call accompanies the underlying grant
// or refresh-token write, and the operations MUST commit atomically so a
// partial failure cannot leave a still-redeemable tombstone next to a
// freshly-rotated grant.
//
// Backends MAY satisfy this interface with two physical tables (one per
// row shape) or a unified table with a discriminator column; either
// approach satisfies the contract as long as
// [GrantRevocationStore.IsRevoked] honours the precedence rule (JTI
// denylist first, then grant tombstone) and the
// "revoked iff iat <= RevokedAt" semantics on tombstone matches.
//
// Backends that never enable the grant-tombstone strategy MAY return
// nil from the [Store.GrantRevocations] accessor; the library detects
// the nil at op.New construction time and rejects the strategy when its
// substore is missing.
type GrantRevocationStore interface {
	// RevokeGrant tombstones t.GrantID. The call MUST be idempotent: a
	// second call with the same GrantID extends BOTH RevokedAt and
	// ExpiresAt to the max(existing, supplied) value. Advancing
	// RevokedAt covers ATs minted under a Grant the OP has reused
	// across repeat /authorize flows after an earlier cascade — those
	// ATs carry a fresh iat that lies after the original cascade but
	// before the next one, so the verifier's "iat <= RevokedAt" rule
	// only catches them once a follow-up cascade pushes RevokedAt past
	// their iat. The idempotency surface mirrors the cascade order in
	// internal/tokenendpoint and internal/endsession: each handler runs
	// the cascade once per request, and concurrent cascades against
	// the same GrantID converge on the latest RevokedAt rather than
	// drift backwards.
	RevokeGrant(ctx context.Context, t GrantTombstone) error

	// RevokeJTI denylists a single JWT access token by its jti. The call
	// MUST be idempotent: a second call against the same JTI is a no-op
	// (the existing row's ExpiresAt is left unchanged). Used only by
	// the RFC 7009 single-AT revocation path; cascades use
	// [GrantRevocationStore.RevokeGrant].
	RevokeJTI(ctx context.Context, r RevokedJTI) error

	// IsRevoked reports whether the access token identified by
	// (grantID, jti, iat) is revoked. The implementation MUST consult
	// the JTI denylist first (cheap, small) and only then the grant
	// tombstone keyed by grantID; the tombstone match rule is
	// "revoked iff !iat.After(tombstone.RevokedAt)" -- equivalently,
	// iat <= RevokedAt. A missing entry is (false, nil); a typed error
	// is permitted only for transport faults. A revoked entry is
	// (true, nil); transport-fault callers (userinfo, introspection)
	// treat (false, err) as fatal and deny the request rather than
	// re-introducing a cascade gap.
	//
	// Empty grantID skips the tombstone check (the legacy fallback
	// path); empty jti skips the denylist check (the mint-refusal path
	// where the OP has not yet allocated a JTI).
	IsRevoked(ctx context.Context, grantID, jti string, iat time.Time) (bool, error)

	// GC drops every tombstone and denylist row whose ExpiresAt is
	// strictly before cutoff and returns the total number of rows
	// removed. The zero time is treated as "no expiry" and is never
	// collected; callers that need the original behaviour (drop
	// everything) supply an explicit far-future cutoff. Embedders
	// typically call GC from a periodic sweeper; the library's
	// reference wiring runs it inside the same loop that sweeps codes
	// and PAR records.
	GC(ctx context.Context, cutoff time.Time) (int, error)
}

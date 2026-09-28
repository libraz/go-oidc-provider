package store

import (
	"context"
	"time"
)

// AccessTokenRecord is the persistent shadow of an issued JWT access
// token. Access tokens themselves stay self-contained on the wire (RFC
// 9068); the record carries only what the OP needs to revoke or
// introspect them after the fact (RFC 6749 §4.1.2 code-replay
// revocation, RFC 6819 §5.2.1.1 detection invariant).
//
// Records are append-mostly: [AccessTokenRegistry.Register] stores the
// row at issuance, [AccessTokenRegistry.RevokeByJTI] /
// [AccessTokenRegistry.RevokeByGrant] flip [Revoked] to true, and the
// periodic [AccessTokenRegistry.GC] sweeper drops rows whose
// [ExpiresAt] is past the supplied cutoff.
type AccessTokenRecord struct {
	// JTI is the access token's RFC 7519 jti claim. The library
	// generates a fresh 256-bit identifier per token; backends key the
	// row directly on this value.
	JTI string

	// GrantID is the [Grant.ID] the token descends from. Empty for
	// grants that have no authorize-side record (e.g.
	// client_credentials, where the wiring layer synthesises an
	// identifier so [AccessTokenRegistry.RevokeByGrant] can still
	// cascade).
	GrantID string

	// Subject is the OP-internal stable identifier of the end-user, or
	// empty when the token represents a non-user grant
	// (client_credentials).
	Subject string

	// ClientID identifies the client to which the token was issued.
	ClientID string

	// Scopes lists the scopes bound to the token at issuance. The slice
	// MAY be nil for tokens issued without scope (some legacy flows).
	Scopes []string

	// IssuedAt is the wall-clock time at which the token was minted.
	// Backends MUST persist it verbatim so the record's ordering can
	// be reconstructed after rotation (RFC 6749 §6).
	IssuedAt time.Time

	// ExpiresAt is the wall-clock expiry of the access token. The
	// periodic [AccessTokenRegistry.GC] sweeper uses it to drop expired
	// rows; verifiers consult it as a defence-in-depth check on top of
	// the JWT's own exp claim.
	ExpiresAt time.Time

	// Revoked is true when the record has been retired via
	// [AccessTokenRegistry.RevokeByJTI] or
	// [AccessTokenRegistry.RevokeByGrant]. Verifiers (userinfo,
	// introspection, revocation) treat a Revoked record as absent.
	Revoked bool
}

// AccessTokenRegistry is the substore for the JWT access-token shadow
// rows. The substore belongs to the atomic-routing cluster so issued-token
// registration, grants, refresh tokens, and revocation cascades share one
// backend consistency domain in composite deployments. Register itself MUST
// be atomic for a single JTI; the OP runtime does not require a cross-substore
// [Transactional] transaction.
//
// Backends MUST satisfy this interface with a marked-revoked list:
// [AccessTokenRegistry.RevokeByJTI] and [AccessTokenRegistry.RevokeByGrant]
// flip [AccessTokenRecord.Revoked] rather than removing the row, and
// [AccessTokenRegistry.Find] MUST keep returning the record — with
// Revoked set — until [AccessTokenRegistry.GC] is entitled to drop it
// at [AccessTokenRecord.ExpiresAt]. A backend that deletes on
// revocation instead defeats revocation silently: the shared JWT
// access-token verifier (userinfo, introspection, RFC 7009 revocation,
// the code-replay cascade) treats a missing record as "not revoked",
// not as "revoked", because deletion is indistinguishable from a
// record that was never registered.
type AccessTokenRegistry interface {
	// Register persists rec. It MUST return [ErrAlreadyExists] if a
	// record with the same JTI already exists; the JTI is generated
	// with crypto/rand so the collision path is reachable only by
	// implementation bugs.
	Register(ctx context.Context, rec AccessTokenRecord) error

	// Find returns the record identified by jti, or (nil, nil) when no
	// such record exists. Returning a typed [ErrNotFound] is also
	// permitted; the library treats both shapes as "absent". A record
	// retired by [AccessTokenRegistry.RevokeByJTI] or
	// [AccessTokenRegistry.RevokeByGrant] is not "absent": Find MUST
	// keep returning it, with Revoked true, until GC is entitled to
	// drop it. Callers (userinfo, introspection) inspect Revoked
	// before honouring the token.
	Find(ctx context.Context, jti string) (*AccessTokenRecord, error)

	// RevokeByJTI marks the record identified by jti as revoked; it
	// MUST NOT remove the row (see the interface doc). It MUST be
	// idempotent: a second call against the same jti returns nil. A
	// missing record is not an error (returning nil mirrors the RFC
	// 7009 §2.2 idempotency posture; the revocation endpoint returns
	// 200 either way).
	RevokeByJTI(ctx context.Context, jti string) error

	// RevokeByGrant marks every record whose [AccessTokenRecord.GrantID]
	// equals grantID as revoked, returning the number of rows touched;
	// it MUST NOT remove the rows (see the interface doc). Used by the
	// code-replay cascade (RFC 6749 §4.1.2): when the OP detects a
	// replayed authorization code it revokes every access token derived
	// from the same grant alongside the refresh-token chain. A missing
	// grant is not an error (returning (0, nil) is
	// appropriate when no rows match).
	RevokeByGrant(ctx context.Context, grantID string) (int, error)

	// GC drops every record whose [AccessTokenRecord.ExpiresAt] is
	// strictly before cutoff and returns the number of rows removed.
	// The library never calls GC itself; scheduling it — from a
	// periodic sweeper alongside the other substores' own GC methods,
	// or otherwise — is the embedder's responsibility.
	GC(ctx context.Context, cutoff time.Time) (int, error)
}

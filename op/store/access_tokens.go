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
// Backends MAY satisfy this interface with a positive list (revocation
// removes the row) or a marked-revoked list (revocation flips a
// column). The reference implementation in
// [github.com/libraz/go-oidc-provider/op/storeadapter/inmem] uses the
// marked-revoked variant because it makes the "revoked at" timestamp
// recoverable for audit; either approach satisfies the contract as
// long as [AccessTokenRegistry.Find] returns nil (or a record with
// [AccessTokenRecord.Revoked] = true) for retired entries.
type AccessTokenRegistry interface {
	// Register persists rec. It MUST return [ErrAlreadyExists] if a
	// record with the same JTI already exists; the JTI is generated
	// with crypto/rand so the collision path is reachable only by
	// implementation bugs.
	Register(ctx context.Context, rec AccessTokenRecord) error

	// Find returns the record identified by jti, or (nil, nil) when no
	// such record exists. Returning a typed [ErrNotFound] is also
	// permitted; the library treats both shapes as "absent". The
	// returned record's Revoked flag MAY be true; callers (userinfo,
	// introspection) inspect it before honouring the token.
	Find(ctx context.Context, jti string) (*AccessTokenRecord, error)

	// RevokeByJTI marks the record identified by jti as revoked. It
	// MUST be idempotent: a second call against the same jti returns
	// nil. A missing record is not an error (returning nil mirrors the
	// RFC 7009 §2.2 idempotency posture; the revocation endpoint
	// returns 200 either way).
	RevokeByJTI(ctx context.Context, jti string) error

	// RevokeByGrant marks every record whose [AccessTokenRecord.GrantID]
	// equals grantID as revoked, returning the number of rows touched.
	// Used by the code-replay cascade (RFC 6749 §4.1.2): when the OP
	// detects a replayed authorization code it revokes every access
	// token derived from the same grant alongside the refresh-token
	// chain. A missing grant is not an error (returning (0, nil) is
	// appropriate when no rows match).
	RevokeByGrant(ctx context.Context, grantID string) (int, error)

	// GC drops every record whose [AccessTokenRecord.ExpiresAt] is
	// strictly before cutoff and returns the number of rows removed.
	// Embedders typically call this from a periodic sweeper; the
	// library's reference wiring runs it inside the same loop that
	// sweeps codes and PAR records.
	GC(ctx context.Context, cutoff time.Time) (int, error)
}

package store

import (
	"context"
	"time"
)

// OpaqueAccessToken is the persistent record of an opaque access token
// (ADR 0024). It mirrors the shape of [AccessTokenRecord] (ADR 0013) and
// adds the cnf thumbprints required to re-verify sender-constrained
// proofs at the boundaries the OP serves (userinfo, introspection,
// revocation).
//
// Backends MUST treat [OpaqueAccessToken.ID] as a bearer secret: persist
// a SHA-256 digest, never the raw bytes. The hash-on-store contract
// documented at the package level applies verbatim; the inmem reference
// in [github.com/libraz/go-oidc-provider/op/storeadapter/inmem] hashes
// via SHA-256 without a pepper, intentionally trading the additional
// defence for transparency in tests. SQL adapters HMAC the digest with
// an out-of-DB pepper when one is supplied.
type OpaqueAccessToken struct {
	// ID is the opaque identifier (32 bytes from crypto/rand,
	// base64url-encoded without padding) handed to the client. The
	// implementation MUST hash this value before persisting and MUST
	// NOT store the raw form. Find / RevokeByID hash the presented
	// id and look up by digest.
	ID string

	// GrantID is the [Grant.ID] the token descends from. Empty for
	// grants that have no authorize-side record (client_credentials
	// synthesises one upstream so the cascade still works).
	GrantID string

	// Subject is the OP-internal stable identifier of the end-user, or
	// empty for non-user grants (client_credentials).
	Subject string

	// ClientID identifies the issuing client. Same-client-only
	// introspection is enforced by the wiring layer (ADR 0024 §S.8) so
	// the ClientID stored here is the gate.
	ClientID string

	// Scope lists the scopes bound at issuance.
	Scope []string

	// Audience is the RFC 8707 resource indicator the token is bound
	// to, or the OP's issuer URL when the request omitted resource.
	// Resource indicators are immutable across a refresh-token rotation
	// chain (RFC 8707 §2.2) so the field is stable for the lifetime
	// of the token's grant.
	Audience string

	// ACR is the authentication context class reference mirrored from
	// the originating authentication so introspection can project it.
	ACR string

	// AMR lists the authentication methods used at issuance, mirrored
	// for introspection.
	AMR []string

	// AuthTime is the wall-clock instant of the originating user
	// authentication (RFC 7519 auth_time semantics), mirrored so
	// introspection can project it.
	AuthTime time.Time

	// DPoPJKT is the RFC 7638 SHA-256 thumbprint of the DPoP key the
	// access token is bound to (RFC 9449 §6.1). The encoding mirrors
	// [RefreshToken.DPoPJKT]: base64url, no padding. Empty means the
	// token is bearer; non-empty means every use of the token through
	// OP-served boundaries (userinfo, introspection) MUST present a
	// matching proof.
	DPoPJKT string

	// MTLSCertThumbprint is the RFC 8705 §3.1 SHA-256 thumbprint of
	// the client certificate the access token is bound to. The
	// encoding mirrors [RefreshToken.MTLSCertThumbprint]: base64url,
	// no padding. Empty means the token is not mTLS-bound; non-empty
	// means every use MUST present a client cert whose DER bytes hash
	// to this value.
	//
	// MTLSCertThumbprint and DPoPJKT are mutually exclusive in
	// practice; the wire format keeps the fields independent so a
	// future release that admits dual binding does not need a contract
	// change.
	MTLSCertThumbprint string

	// IssuedAt is the wall-clock time at which the token was minted.
	IssuedAt time.Time

	// ExpiresAt is the wall-clock expiry of the access token. The
	// periodic [OpaqueAccessTokenStore.GC] sweeper uses it to drop
	// expired rows; verifiers (introspection, userinfo) consult it
	// alongside [Revoked] before honouring the token.
	ExpiresAt time.Time

	// Revoked is true after [OpaqueAccessTokenStore.RevokeByID] or
	// [OpaqueAccessTokenStore.RevokeByGrant]. Backends MAY delete
	// revoked rows instead of marking them; either approach satisfies
	// the contract as long as subsequent Find calls return either
	// [ErrNotFound] or a record whose Revoked flag is true.
	Revoked bool
}

// OpaqueAccessTokenStore is the substore for opaque access tokens
// (ADR 0024). It belongs to the transactional cluster: a Save call
// accompanies a grant write or refresh-token rotation, and the two
// operations MUST commit atomically so a partially-issued wire token
// cannot leave a credential the OP does not remember.
//
// Backends MAY satisfy this interface with a positive list (revocation
// removes the row) or a marked-revoked list (revocation flips a
// column). The reference implementation in
// [github.com/libraz/go-oidc-provider/op/storeadapter/inmem] uses the
// marked-revoked variant so audit metadata stays recoverable; either
// approach satisfies the contract as long as [OpaqueAccessTokenStore.Find]
// returns [ErrNotFound] or a record with [OpaqueAccessToken.Revoked] = true
// for retired entries.
//
// Backends that never enable [op.WithAccessTokenFormat] (.../Opaque) MAY
// return nil from the [Store.OpaqueAccessTokens] accessor; the library
// detects the nil at op.New construction time and rejects opaque-format
// options that have no place to persist.
type OpaqueAccessTokenStore interface {
	// Save persists a freshly issued opaque token. Implementations MUST
	// hash the raw [OpaqueAccessToken.ID] (SHA-256, ideally HMAC'd with
	// a server-side pepper) before storage and MUST NOT persist the raw
	// value; see the package doc for the hash-on-store contract. Save
	// MUST return [ErrAlreadyExists] when a record whose hashed ID
	// collides with an existing row already exists. The collision path
	// is reachable only by implementation bugs (256-bit entropy on the
	// raw id keeps the birthday probability below 1e-30) so the call
	// site treats it as fatal.
	Save(ctx context.Context, tok *OpaqueAccessToken) error

	// Find returns the live record identified by id, or
	// (nil, [ErrNotFound]) when absent. Implementations MUST hash the
	// presented id, look up by digest, and compare against the stored
	// hash in constant time. A revoked or expired record MAY be
	// returned; callers (userinfo, introspection) inspect Revoked /
	// ExpiresAt themselves so audit metadata remains recoverable.
	Find(ctx context.Context, id string) (*OpaqueAccessToken, error)

	// RevokeByID marks the record identified by id as revoked. The call
	// MUST be idempotent: a missing record returns nil so the
	// revocation endpoint stays aligned with RFC 7009 §2.2. A second
	// call against the same id is a no-op.
	RevokeByID(ctx context.Context, id string) error

	// RevokeByGrant marks every record whose
	// [OpaqueAccessToken.GrantID] equals grantID as revoked, returning
	// the number of rows the call flipped. Used by the code-replay
	// cascade (RFC 6749 §4.1.2) and by refresh-rotation cleanup. A
	// missing grant is not an error (returning (0, nil) is appropriate
	// when no rows match).
	RevokeByGrant(ctx context.Context, grantID string) (int, error)

	// GC drops every record whose [OpaqueAccessToken.ExpiresAt] is
	// strictly before cutoff and returns the number of rows removed.
	// Embedders typically call GC from a periodic sweeper; the
	// library's reference wiring runs it inside the same loop that
	// sweeps codes and PAR records.
	GC(ctx context.Context, cutoff time.Time) (int, error)
}

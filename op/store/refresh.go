package store

import (
	"context"
	"time"
)

// RefreshToken is the persistent record of a refresh token (RFC 6749 §1.5,
// §6) including the rotation chain used to detect replay (RFC 9700 §2.2.2).
//
// Refresh tokens in this library are always rotated: each successful refresh
// consumes the presented token and issues a new one whose ParentID points at
// its predecessor. Replay of a previously consumed token is detected by the
// non-nil ConsumedAt field; the library responds by revoking the entire
// rotation chain via [RefreshTokenStore.RevokeChain].
type RefreshToken struct {
	// ID is the opaque identifier (generated with crypto/rand) exposed to
	// the client as the refresh_token parameter. The storage layer stores
	// this verbatim or, in security-sensitive backends, stores a hash.
	ID string

	// ClientID identifies the client to which the token was issued. The
	// token endpoint rejects refreshes by any other client.
	ClientID string

	// Subject is the OP-internal stable identifier of the end-user.
	Subject string

	// SubjectPublic is true when Subject is already the public wire
	// subject for this client and MUST NOT be passed through the OP's
	// subject projector again during refresh rotation. Built-in
	// authorization, device, and CIBA flows store the internal subject
	// and leave this false; custom-grant / token-exchange refresh chains
	// set it because their subject comes from an already-issued token.
	SubjectPublic bool

	// GrantID points at the [Grant] record that captures the user's
	// consent for this token's scopes.
	GrantID string

	// Scope lists the scopes bound to the refresh token. A refresh request
	// MAY narrow this list but MUST NOT widen it.
	Scope []string

	// Resource is the RFC 8707 resource indicator this refresh-token
	// chain is bound to. Empty means the originating grant omitted the
	// parameter and rotated access tokens should continue using the OP's
	// default audience path.
	Resource string

	// Origin records which grant family created the refresh chain. The
	// value is informational for storage adapters and audit tooling; the
	// token endpoint uses the concrete context fields below for runtime
	// decisions so unknown / legacy origins remain refreshable.
	Origin RefreshTokenOrigin

	// AuthTime is the authentication instant that should be reproduced on
	// refresh-derived id_tokens and opaque-token metadata. Zero means the
	// originating flow had no end-user authentication timestamp or the
	// row predates this field.
	AuthTime time.Time

	// ACR and AMR are the authentication context values that should be
	// reproduced on refresh-derived id_tokens. Empty values are omitted.
	ACR string
	AMR []string

	// AuthorizationDetails captures the RFC 9396 authorization_details
	// bound to this refresh chain. The token endpoint echoes it on refresh
	// responses and copies it onto JWT access tokens.
	AuthorizationDetails []map[string]any

	// AccessTokenExtra carries non-standard JWT access-token claims that
	// must survive refresh rotation. It is primarily used by custom grants
	// such as token exchange to preserve delegation metadata ("act").
	// Built-in authorization, device, and CIBA flows leave it nil.
	AccessTokenExtra map[string]any

	// ParentID is the ID of the refresh token that this token replaces, or
	// nil if the token is the root of a rotation chain. Backends use the
	// parent pointer to walk the chain when [RefreshTokenStore.RevokeChain]
	// is called after a replay detection.
	ParentID *string

	// ConsumedAt is non-nil after the token has been rotated. The library
	// treats a refresh request bearing a token with a non-nil ConsumedAt
	// as a replay attempt.
	ConsumedAt *time.Time

	// ExpiresAt is the wall-clock expiry of the refresh token. Backends
	// MAY garbage-collect rows where ExpiresAt is in the past, but only
	// after retaining them long enough for replay detection (the recommended
	// floor is the access-token lifetime).
	ExpiresAt time.Time

	// CreatedAt is the wall-clock time at which the record was first
	// persisted. It is supplied by the caller.
	CreatedAt time.Time

	// DPoPJKT is the RFC 7638 SHA-256 thumbprint of the DPoP key the
	// access token paired with this refresh token was bound to (RFC
	// 9449 §6 / §6.1). Empty means the chain is bearer; subsequent
	// refresh requests then need not present a DPoP proof. Non-empty
	// means every refresh request MUST present a proof whose JWK
	// thumbprint equals this value, and the rotated access token is
	// re-bound to the same thumbprint.
	DPoPJKT string

	// MTLSCertThumbprint is the RFC 8705 §3.1 SHA-256 thumbprint of
	// the client certificate the access token paired with this
	// refresh token was bound to. The encoding mirrors the cnf
	// claim: base64url, no padding. Empty means the chain is not
	// mTLS-bound; non-empty means every refresh request MUST present
	// a client cert whose DER bytes hash to this value, and the
	// rotated access token is re-bound to the same thumbprint.
	//
	// MTLSCertThumbprint and DPoPJKT are mutually exclusive in
	// practice: a chain is bound by one method or neither, never
	// both. The wire format keeps the fields independent so a future
	// release that admits dual binding does not need a contract
	// change.
	MTLSCertThumbprint string

	// Nonce is the OpenID Connect Core 1.0 §3.1.2.1 nonce value the
	// client supplied at the originating authorization request. The
	// token endpoint copies it onto every id_token issued under this
	// chain, including id_tokens minted via refresh-token rotation:
	// OIDC Core §12 requires the rotated id_token to preserve the
	// original nonce. Empty when the originating request omitted the
	// parameter (a non-OIDC chain or a profile that does not require
	// nonce); the id_token claim is then omitted on the wire.
	Nonce string

	// Revoked is true when the record was retired via
	// [RefreshTokenStore.RevokeChain] (typically after a replay was
	// detected on a sibling). The library distinguishes "consumed by
	// rotation" (grace-window eligible per RFC 9700 §2.2.2) from
	// "revoked due to chain compromise" (no grace) using this flag.
	// Backends that delete revoked rows instead of marking them are
	// equally compliant; the field exists so backends that retain
	// rows for audit can still be queried without surfacing revoked
	// records as grace-eligible.
	Revoked bool
}

// RefreshTokenOrigin names the grant family that created a refresh-token
// chain. Empty means "legacy / unknown" and is accepted for records persisted
// before the field existed.
type RefreshTokenOrigin string

const (
	// RefreshOriginAuthCode identifies refresh chains created by the
	// authorization-code grant.
	RefreshOriginAuthCode RefreshTokenOrigin = "authcode"
	// RefreshOriginCustomGrant identifies refresh chains created by custom
	// grants, including token exchange.
	RefreshOriginCustomGrant RefreshTokenOrigin = "custom_grant"
	// RefreshOriginDeviceCode identifies refresh chains created by the
	// device authorization grant.
	RefreshOriginDeviceCode RefreshTokenOrigin = "device_code"
	// RefreshOriginCIBA identifies refresh chains created by CIBA.
	RefreshOriginCIBA RefreshTokenOrigin = "ciba"
)

// RefreshTokenStore is the substore for refresh_token records. It belongs to
// the atomic-routing cluster so rotation, access-token registration, grant
// updates, and revocation cascades share one backend consistency domain in
// composite deployments.
//
// Implementations are responsible for two cross-cutting invariants:
//
//   - Rotation: Consume MUST be a single-record compare-and-set, and Save
//     with a non-nil ParentID MUST preserve the parent/root links supplied by
//     the caller so replay cascades can later revoke the whole chain. The OP
//     runtime does not require a cross-substore [Transactional] transaction.
//   - Replay detection: if a Consume call observes a ConsumedAt that is
//     already non-nil, the backend MUST return [ErrAlreadyConsumed]. The
//     library will then call [RefreshTokenStore.RevokeChain] with the
//     replayed token's chain root to invalidate every descendant.
type RefreshTokenStore interface {
	// Save persists a freshly issued refresh token. The implementation
	// MUST hash [RefreshToken.ID] (SHA-256, ideally HMAC'd with a
	// server-side pepper) before persisting and MUST NOT store the raw
	// value; see the package doc for the hash-on-store contract. Save
	// MUST return [ErrAlreadyExists] if a record whose hashed ID
	// collides with an existing row already exists.
	Save(ctx context.Context, token *RefreshToken) error

	// Find returns the refresh token identified by id without consuming
	// it. The implementation MUST hash the presented id and look up the
	// resulting digest, comparing against the stored hash in constant
	// time. It MUST return [ErrNotFound] when no such record exists.
	Find(ctx context.Context, id string) (*RefreshToken, error)

	// Consume atomically marks the refresh token as consumed and returns
	// the resulting record. The implementation MUST hash the presented
	// id and look up the resulting digest. It MUST return [ErrNotFound]
	// when the record is absent, [ErrAlreadyConsumed] when the record's
	// ConsumedAt was already set on entry, and a non-nil error if the
	// compare-and-set fails. When returning ErrAlreadyConsumed,
	// implementations MUST also return the consumed record if it is still
	// available so callers can recover the chain root for replay
	// revocation. The returned record's ConsumedAt MUST be non-nil on
	// success.
	Consume(ctx context.Context, id string) (*RefreshToken, error)

	// RevokeChain revokes every refresh token in the rotation chain whose
	// root is rootID, including rootID itself. It is invoked after a
	// successful replay detection (RFC 9700 §2.2.2). Implementations MAY
	// choose between deleting the rows and marking them consumed; either
	// approach satisfies the contract as long as subsequent Find calls
	// return [ErrNotFound] or records whose ConsumedAt is non-nil.
	RevokeChain(ctx context.Context, rootID string) error

	// RevokeByGrant revokes every refresh token whose [RefreshToken.GrantID]
	// equals grantID, regardless of which chain root it descends from. It
	// is invoked when a sibling artefact tied to the same grant — e.g.
	// the authorization code that produced the chain — is observed to be
	// replayed (RFC 6749 §4.1.2). The contract is identical to
	// [RefreshTokenStore.RevokeChain]: implementations MAY delete or mark
	// the rows, and a missing grant is not an error (returning nil is
	// appropriate when no rows match).
	RevokeByGrant(ctx context.Context, grantID string) error
}

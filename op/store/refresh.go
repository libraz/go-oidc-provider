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

	// GrantID points at the [Grant] record that captures the user's
	// consent for this token's scopes.
	GrantID string

	// Scope lists the scopes bound to the refresh token. A refresh request
	// MAY narrow this list but MUST NOT widen it.
	Scope []string

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
}

// RefreshTokenStore is the substore for refresh_token records. It belongs to
// the transactional cluster: rotation is "consume the old token + persist the
// new token + update the grant" and the three operations must commit
// atomically to avoid leaving an unconsumed token behind on partial failure.
//
// Implementations are responsible for two cross-cutting invariants:
//
//   - Rotation: every Save with a non-nil ParentID MUST occur in the same
//     transaction as the Consume of that ParentID. The library guarantees
//     this on the call site, but backends MUST NOT silently allow the
//     pattern to be split across transactions.
//   - Replay detection: if a Consume call observes a ConsumedAt that is
//     already non-nil, the backend MUST return [ErrAlreadyConsumed]. The
//     library will then call [RefreshTokenStore.RevokeChain] with the
//     replayed token's chain root to invalidate every descendant.
type RefreshTokenStore interface {
	// Save persists a freshly issued refresh token. It MUST return
	// [ErrAlreadyExists] if a record with the same ID already exists.
	Save(ctx context.Context, token *RefreshToken) error

	// Find returns the refresh token identified by id without consuming
	// it. It MUST return [ErrNotFound] when no such record exists.
	Find(ctx context.Context, id string) (*RefreshToken, error)

	// Consume atomically marks the refresh token as consumed and returns
	// the resulting record. It MUST return [ErrNotFound] when the record
	// is absent, [ErrAlreadyConsumed] when the record's ConsumedAt was
	// already set on entry, and a non-nil error if the compare-and-set
	// fails. The returned record's ConsumedAt MUST be non-nil on success.
	Consume(ctx context.Context, id string) (*RefreshToken, error)

	// RevokeChain revokes every refresh token in the rotation chain whose
	// root is rootID, including rootID itself. It is invoked after a
	// successful replay detection (RFC 9700 §2.2.2). Implementations MAY
	// choose between deleting the rows and marking them consumed; either
	// approach satisfies the contract as long as subsequent Find calls
	// return [ErrNotFound] or records whose ConsumedAt is non-nil.
	RevokeChain(ctx context.Context, rootID string) error
}

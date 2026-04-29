package store

import (
	"context"
	"time"
)

// AuthorizationCode is the persistent record of an authorization_code issued
// at the authorization endpoint and exchanged at the token endpoint
// (RFC 6749 §4.1.2, OpenID Connect Core 1.0 §3.1.3).
//
// Authorization codes are single-use: once a code is exchanged it MUST never
// succeed again, even if the same client retries. Backends enforce that
// invariant in [AuthorizationCodeStore.Consume].
type AuthorizationCode struct {
	// ID is the opaque identifier exposed to the client as the "code"
	// parameter. It is generated with crypto/rand and is the natural
	// primary key of the record.
	ID string

	// ClientID identifies the registered client that requested the code.
	// The token endpoint rejects exchanges where the authenticated client
	// does not match.
	ClientID string

	// Subject is the OP-internal stable identifier of the end-user that
	// authenticated when the code was issued.
	Subject string

	// GrantID points at the [Grant] record that captures the user's
	// consent. Multiple authorization codes for the same (subject, client)
	// share a GrantID when the consent has been remembered.
	GrantID string

	// RedirectURI is the redirect_uri presented at the authorization
	// endpoint. The token endpoint rejects exchanges where the client
	// presents a different URI (RFC 6749 §4.1.3).
	RedirectURI string

	// Scope lists the scopes the user consented to for this code.
	Scope []string

	// CodeChallenge is the PKCE challenge sent at the authorization
	// endpoint (RFC 7636 §4.2). Empty if PKCE was not used.
	CodeChallenge string

	// CodeChallengeMethod is the PKCE transformation that produced
	// CodeChallenge ("S256" or "plain", though "plain" is rejected by
	// policy in this library).
	CodeChallengeMethod string

	// Nonce is the nonce parameter the client supplied at the
	// authorization endpoint (OpenID Connect Core 1.0 §3.1.2.1). The
	// token endpoint copies it into the issued ID Token's nonce claim.
	Nonce string

	// State is the state parameter the client supplied at the
	// authorization endpoint. It is stored for audit purposes; the token
	// endpoint does not echo it.
	State string

	// DPoPJKT is the SHA-256 thumbprint of the DPoP key the client
	// committed to at the authorization endpoint via the RFC 9449 §10
	// "dpop_jkt" parameter. Empty when the client did not commit to a
	// key. The token endpoint enforces the binding: when DPoPJKT is
	// non-empty, an inbound DPoP proof MUST carry the same thumbprint;
	// when empty the DPoP proof's own thumbprint stands in (the proof
	// itself binds the access token).
	DPoPJKT string

	// ExpiresAt is the wall-clock time at which the code becomes invalid
	// regardless of consumption status. Backends MAY garbage-collect rows
	// where ExpiresAt is in the past.
	ExpiresAt time.Time

	// ConsumedAt is non-nil after a successful exchange. The library
	// treats a non-nil ConsumedAt as proof of replay and aborts the
	// exchange with [ErrAlreadyConsumed].
	ConsumedAt *time.Time

	// CreatedAt is the wall-clock time at which the record was first
	// persisted. It is supplied by the caller; the storage layer never
	// reads the wall clock itself.
	CreatedAt time.Time
}

// AuthorizationCodeStore is the substore for authorization_code records.
// It is part of the transactional cluster: backends that serve it implement
// [Transactional] so that the token endpoint can consume the code, persist
// the resulting refresh token, and update the grant in a single atomic
// operation (RFC 6749 §10.5).
type AuthorizationCodeStore interface {
	// Save persists a freshly issued authorization code. The
	// implementation MUST hash [AuthorizationCode.ID] (SHA-256, ideally
	// HMAC'd with a server-side pepper) before persisting and MUST NOT
	// store the raw value; see the package doc for the hash-on-store
	// contract. Save MUST return [ErrAlreadyExists] if a record whose
	// hashed ID collides with an existing row already exists; the
	// library treats that as a fatal randomness or clock fault.
	Save(ctx context.Context, code *AuthorizationCode) error

	// Find returns the authorization code identified by id without
	// consuming it. The implementation MUST hash the presented id and
	// look up the resulting digest, comparing against the stored hash
	// in constant time. It MUST return [ErrNotFound] when no such
	// record exists. Find is exposed for diagnostics and for handlers
	// that need to validate parameters before opening a transaction;
	// the authoritative single-use check lives in
	// [AuthorizationCodeStore.Consume].
	Find(ctx context.Context, id string) (*AuthorizationCode, error)

	// Consume atomically marks the authorization code as consumed and
	// returns the record. The implementation MUST hash the presented id
	// and look up the resulting digest. It MUST return [ErrNotFound] if
	// no such record exists, [ErrAlreadyConsumed] if the record's
	// ConsumedAt was already set on entry, and a non-nil error if the
	// underlying compare-and-set fails. After a successful Consume the
	// returned record's ConsumedAt MUST be non-nil so that callers can
	// audit the consumption time.
	Consume(ctx context.Context, id string) (*AuthorizationCode, error)
}

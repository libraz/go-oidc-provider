package store

import (
	"context"
	"time"
)

// InitialAccessToken is a single-use registration credential issued by
// op.Provider.IssueInitialAccessToken (RFC 7591 §3) and presented as a
// Bearer credential at the dynamic client registration endpoint. The
// token's secret value never reaches storage; backends store [HashedValue]
// instead, and verification is performed by hashing the presented bearer
// and comparing the digest in constant time.
//
// IATs are authoritatively single-use by default ([MaxUses] == 0 means
// "treated as 1") but operators MAY mint multi-use IATs for tenant
// onboarding flows that issue several clients from the same invitation.
// The [Uses] counter is incremented atomically by
// [InitialAccessTokenStore.IncrementUses]; non-atomic implementations
// would admit replay races against the single-use guarantee.
type InitialAccessToken struct {
	// ID is the opaque public identifier for the IAT. It is *not* the
	// bearer secret; the secret is hashed into HashedValue. The library
	// uses ID for revocation lookups and audit logs.
	ID string

	// HashedValue is the SHA-256 hash (hex-encoded) of the secret bearer
	// value. Verification is constant-time: the library hashes the
	// presented bearer and compares against HashedValue.
	HashedValue string

	// MaxUses is the consumption ceiling; zero means single-use (1).
	// Uses is the running counter incremented by IncrementUses. The
	// library rejects when the post-increment Uses would exceed
	// MaxUses (so a MaxUses=1 IAT permits exactly one successful
	// registration).
	MaxUses int

	// Uses is the running consumption counter. The library never sets
	// it directly on Put; it is incremented by IncrementUses after a
	// successful registration.
	Uses int

	// AllowedScopes constrains the scopes a client registered via this
	// IAT may request (RFC 7591 §2 freedom). Empty means no IAT-level
	// scope filter (the request is still validated against the OP's
	// global scope registry).
	AllowedScopes []string

	// Tag is an operator-supplied identifier surfaced in audit logs
	// (for example "tenant-acme-2026-04"). Opaque to the library.
	Tag string

	// ExpiresAt is the wall-clock time at which the IAT becomes
	// invalid regardless of remaining uses. Backends MAY garbage-
	// collect rows where ExpiresAt is in the past, but the reference
	// in-memory implementation deliberately does not -- production
	// backends typically run a sweeper.
	ExpiresAt time.Time

	// CreatedAt is the wall-clock time at which the IAT was first
	// persisted. Supplied by the caller.
	CreatedAt time.Time
}

// InitialAccessTokenStore is the persistence contract for RFC 7591
// Initial Access Tokens. Backends MUST implement [IncrementUses]
// atomically; non-atomic implementations admit replay races against
// the single-use guarantee.
//
// Hashing of the bearer secret is the library's responsibility, not the
// backend's: callers compute the SHA-256 digest of the presented bearer
// and pass the hex-encoded string to [GetByHash]. Backends do not need
// to know how the digest was produced.
type InitialAccessTokenStore interface {
	// Put persists t. It MUST return [ErrAlreadyExists] if a token
	// with the same ID is already present.
	Put(ctx context.Context, t *InitialAccessToken) error

	// GetByHash returns the IAT whose HashedValue matches hash. It
	// MUST return [ErrNotFound] when no row matches. Backends MUST
	// scope the lookup strictly to HashedValue equality; the library
	// does not pass partial matches.
	//
	// Unlike the expiry-gating lookups elsewhere in this package
	// ([PushedAuthRequestStore.Find], [SessionStore.Find]), GetByHash
	// MUST return a matching row whose ExpiresAt has passed rather than
	// reporting it absent. The library applies the expiry gate itself,
	// because the registration endpoint tells a client whose token
	// lapsed something different from one presenting a token that never
	// existed, and emits a different audit event for each. A backend
	// that filters here collapses the two, leaving an operator unable
	// to tell an expired credential from a forged one.
	GetByHash(ctx context.Context, hash string) (*InitialAccessToken, error)

	// IncrementUses atomically increments the Uses counter for the
	// IAT identified by id and returns the new value. The library
	// calls it after a successful registration; a Uses > MaxUses
	// condition surfaces as [ErrConflict] so the caller can mark the
	// attempt as a replay race. IncrementUses MUST return [ErrNotFound]
	// when the IAT is absent.
	IncrementUses(ctx context.Context, id string) (newUses int, err error)

	// Delete removes the IAT (used by op.Provider.RevokeInitialAccessToken
	// and by the GC sweep for expired tokens). It MUST return
	// [ErrNotFound] when no row matches.
	Delete(ctx context.Context, id string) error
}

// RegistrationAccessToken is the per-client bearer credential issued
// by RFC 7591 §3.2.1 and used to authenticate the RFC 7592 management
// endpoints. There is at most one active RAT per client_id; PUT
// /register/{client_id} rotates it.
//
// As with [InitialAccessToken], the secret value is never stored: the
// backend persists only [HashedValue].
type RegistrationAccessToken struct {
	// ClientID is the natural primary key. There is at most one
	// active RAT per client_id; PUT-based rotation upserts the row.
	ClientID string

	// HashedValue is the SHA-256 hash (hex-encoded) of the secret
	// bearer value. Verification is constant-time at the library
	// layer.
	HashedValue string

	// CreatedAt is the wall-clock time at which the RAT was first
	// persisted. Rotation overwrites this value with the time of the
	// rotation, since the previous RAT is revoked atomically.
	CreatedAt time.Time
}

// RegistrationAccessTokenStore is the persistence contract for RATs.
// Backends MUST scope [GetByClientID] strictly to ClientID equality;
// the library does not pass partial matches.
//
// PUT-based rotation is the common case and is modelled as an upsert
// in [Put] rather than a separate Update method, so that the rotation
// path can be a single round trip.
type RegistrationAccessTokenStore interface {
	// Put inserts or replaces the RAT for the client. PUT is an
	// upsert because metadata-update rotation is the common case.
	Put(ctx context.Context, t *RegistrationAccessToken) error

	// GetByClientID returns the active RAT for clientID. It MUST
	// return [ErrNotFound] when no row matches.
	GetByClientID(ctx context.Context, clientID string) (*RegistrationAccessToken, error)

	// Delete removes the RAT for clientID. Used by DELETE
	// /register/{client_id} and by client deletion side-effects. It
	// MUST return [ErrNotFound] when no row matches.
	Delete(ctx context.Context, clientID string) error
}

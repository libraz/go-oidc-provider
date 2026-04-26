package store

import (
	"context"
	"time"
)

// Grant represents the persisted consent that a subject has given to a
// client. It survives across authorization codes and refresh tokens so that
// the library can decide whether a re-prompt is required when the same
// (subject, client) pair returns with the same scopes.
//
// A Grant is keyed by ID for direct lookup and by (Subject, ClientID) for
// renewal lookup. The library never assumes there is at most one grant per
// (subject, client); backends MAY store multiple historical grants if they
// wish, in which case [GrantStore.FindBySubjectClient] returns the active
// one and Delete is invoked when consent is revoked.
type Grant struct {
	// ID is the opaque grant identifier (generated with crypto/rand) used
	// as the foreign key from [AuthorizationCode] and [RefreshToken].
	ID string

	// Subject is the OP-internal stable identifier of the end-user.
	Subject string

	// ClientID identifies the client that received the consent.
	ClientID string

	// Scope lists the scopes the user consented to. The library uses this
	// list to decide whether a fresh authorization request requires a
	// re-prompt; a request whose scopes are a subset of Scope can be
	// satisfied silently when policy allows.
	Scope []string

	// Claims captures any per-claim consent the user has expressed beyond
	// scope-level grants (for example, individual claims requested via
	// the OpenID Connect Core 1.0 §5.5 "claims" parameter). The map is
	// opaque to the library aside from null/non-null checks.
	Claims map[string]any

	// CreatedAt is the wall-clock time at which the grant was first
	// recorded. Supplied by the caller.
	CreatedAt time.Time

	// UpdatedAt is the wall-clock time of the most recent modification.
	// Supplied by the caller; backends MUST persist it verbatim rather
	// than substituting a server-side now() value.
	UpdatedAt time.Time
}

// GrantStore is the substore for persisted consent. It belongs to the
// transactional cluster because grant updates accompany authorization-code
// exchanges and refresh-token rotations.
type GrantStore interface {
	// Save persists a new grant or replaces an existing one. Save MUST
	// return [ErrAlreadyExists] if used in insert mode and the ID is
	// already present; backends that perform upsert MAY treat Save as
	// idempotent.
	Save(ctx context.Context, g *Grant) error

	// Find returns the grant identified by id. It MUST return
	// [ErrNotFound] when no such grant exists.
	Find(ctx context.Context, id string) (*Grant, error)

	// FindBySubjectClient returns the active grant for the given
	// (subject, clientID) pair, or [ErrNotFound] if none exists. Backends
	// that store historical grants MUST return the most recent active
	// one; revoked grants MUST NOT be returned.
	FindBySubjectClient(ctx context.Context, subject, clientID string) (*Grant, error)

	// Delete revokes the grant identified by id. It MUST return
	// [ErrNotFound] if no such grant exists. Backends MAY soft-delete or
	// hard-delete; the library only requires that subsequent Find and
	// FindBySubjectClient calls treat the grant as absent.
	Delete(ctx context.Context, id string) error
}

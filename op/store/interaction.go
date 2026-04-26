package store

import (
	"context"
	"time"
)

// Interaction is the persistent record of an in-progress UI interaction:
// the server-side state that survives across the redirects between the OP
// and the user's browser while consent, account-chooser, or step-up
// authentication screens are presented. The library never inspects RawState;
// it is opaque content owned by the [github.com/libraz/go-oidc-provider/op/interaction.Driver]
// implementation.
//
// Interactions are explicitly NOT part of the transactional cluster. They
// are recoverable single-operation state -- losing a row means the user is
// asked to log in again, not that a security boundary is breached -- and
// holding them in a backend separate from the persistent store lets
// operators pin them to a fast ephemeral tier (Redis, DynamoDB TTL) without
// jeopardising replay protection on tokens.
type Interaction struct {
	// ID is the opaque interaction identifier (generated with crypto/rand)
	// stored in the OP cookie and used as the lookup key.
	ID string

	// ClientID identifies the client whose authorization request triggered
	// the interaction.
	ClientID string

	// Step is a short string naming the current step in the UI flow (for
	// example "consent", "chooser", "passkey"). The library uses Step to
	// decide which Driver hook to invoke when the user returns from the
	// browser.
	Step string

	// RawState is the serialised state owned by the Driver implementation.
	// It is opaque to the library. Drivers MAY use any encoding (JSON,
	// gob, protobuf) provided they round-trip safely.
	RawState []byte

	// ExpiresAt is the wall-clock time at which the interaction becomes
	// invalid. Backends MAY garbage-collect rows where ExpiresAt is in
	// the past; the recommended floor is the authorization-request idle
	// timeout (typically one hour).
	ExpiresAt time.Time

	// CreatedAt is the wall-clock time at which the record was first
	// persisted. Supplied by the caller.
	CreatedAt time.Time

	// UpdatedAt is the wall-clock time of the most recent modification.
	// Supplied by the caller.
	UpdatedAt time.Time
}

// InteractionStore is the substore for in-progress UI interactions. It is
// explicitly NOT part of the transactional cluster: backends that route
// interactions to a different physical store (for example, persistent
// records in MySQL but interactions in Redis) are correct by design.
type InteractionStore interface {
	// Save persists a new interaction or replaces an existing one. Save
	// MUST return [ErrAlreadyExists] if used in insert mode and the ID is
	// already present; backends that perform upsert MAY treat Save as
	// idempotent.
	Save(ctx context.Context, i *Interaction) error

	// Find returns the interaction identified by id, or [ErrNotFound]
	// when no such interaction exists. Find MUST NOT return expired
	// interactions; a record whose ExpiresAt has passed MUST be treated
	// as absent.
	Find(ctx context.Context, id string) (*Interaction, error)

	// Delete removes the interaction identified by id. It MUST return
	// [ErrNotFound] when no such interaction exists. Backends MAY
	// hard-delete or mark the row deleted as long as subsequent Find
	// calls return [ErrNotFound].
	Delete(ctx context.Context, id string) error
}

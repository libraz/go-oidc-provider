package store

import (
	"bytes"
	"context"
	"time"
)

// Interaction is the persistent record of an in-progress UI interaction:
// the server-side state that survives across the redirects between the OP
// and the user's browser while consent, account-chooser, or step-up
// authentication screens are presented.
//
// Interactions are explicitly NOT part of the atomic-routing cluster. They
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

	// RawState is the library's serialised authorization-request state.
	// The library is its sole producer and consumer: it encodes the
	// validated request, the progress of the authentication chain, and
	// the completion intent, and it is never handed to an
	// [github.com/libraz/go-oidc-provider/op/interaction.Driver] hook.
	// The encoding is a library implementation detail and MAY change
	// between releases.
	//
	// RawState is opaque TO THE STORE — which is not the same as
	// unread by the library. A backend MUST persist the byte slice
	// verbatim and MUST return exactly those bytes from Find, because
	// the value doubles as the optimistic-concurrency version that
	// [InteractionStateEqual] compares on behalf of
	// [InteractionStoreCAS.CompareAndSwap] and
	// [InteractionStoreCAS.DeleteIfUnchanged]. Any transformation that
	// preserves meaning but not bytes — re-encoding the JSON,
	// reordering object members, adding or stripping whitespace, a
	// lossy character-set round trip — makes every compare-and-swap
	// fail with [ErrConflict] and strands the authorization request.
	// A backend whose column type cannot hold arbitrary bytes MUST
	// apply a byte-exact reversible encoding (base64, hex) rather than
	// re-serialising the content.
	//
	// A nil slice and an empty slice denote the same version: the
	// comparison treats them as equal.
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
// explicitly NOT part of the atomic-routing cluster: backends that route
// interactions to a different physical store (for example, persistent
// records in MySQL but interactions in Redis) are correct by design. Stores
// used by the browser authorization-code flow must additionally implement
// [InteractionStoreCAS].
type InteractionStore interface {
	// Save persists a new interaction or replaces an existing one. Save
	// MUST return [ErrAlreadyExists] if used in insert mode and the ID is
	// already present; backends that perform upsert MAY treat Save as
	// idempotent.
	Save(ctx context.Context, i *Interaction) error

	// Find returns the interaction identified by id, or [ErrNotFound]
	// when no such interaction exists. Find MUST NOT return expired
	// interactions; a record whose ExpiresAt has passed MUST be treated
	// as absent. The returned [Interaction.RawState] MUST be the bytes
	// that were persisted, unchanged. A successful return MUST carry a
	// non-nil record: (nil, nil) is not a legal result (see the package
	// doc's "Find-style methods never return (nil, nil)").
	Find(ctx context.Context, id string) (*Interaction, error)

	// Delete removes the interaction identified by id. It MUST return
	// [ErrNotFound] when no such interaction exists or when the record
	// has expired, applying the same absent-or-expired rule as
	// [InteractionStore.Find] and [InteractionStoreCAS.DeleteIfUnchanged].
	// Naming the expired case is what keeps the result independent of
	// reclamation: a backend answering from physical presence alone
	// returns nil for a record whose ExpiresAt has passed and
	// [ErrNotFound] for that same record once a sweep or a TTL eviction
	// has removed it, so the caller observes collection timing rather
	// than interaction state. Backends MAY hard-delete or mark the row
	// deleted as long as subsequent Find calls return [ErrNotFound], and
	// MAY reclaim an expired record while reporting [ErrNotFound] for it.
	Delete(ctx context.Context, id string) error
}

// InteractionStoreCAS is the capability required by the authorization
// endpoint to make a terminal interaction immutable before it starts durable
// grant, PAR, code, and session writes. CompareAndSwap replaces previous with
// next only when the stored record still has the same ID and RawState as
// previous.
//
// Implementations MUST perform the comparison and replacement atomically.
// They MUST return [ErrNotFound] when the record is absent or expired, and
// [ErrConflict] when the ID exists but its RawState no longer matches. The
// successful replacement MUST preserve the normal [InteractionStore.Save]
// expiry semantics.
type InteractionStoreCAS interface {
	InteractionStore

	CompareAndSwap(ctx context.Context, previous, next *Interaction) error

	// DeleteIfUnchanged removes previous only when its RawState is still the
	// current optimistic-concurrency version.
	DeleteIfUnchanged(ctx context.Context, previous *Interaction) error
}

// InteractionStateEqual reports whether two interaction snapshots identify
// the same optimistic-concurrency version. It is exported so adapters can
// share the exact comparison contract without duplicating it.
func InteractionStateEqual(previous, current *Interaction) bool {
	return previous != nil &&
		current != nil &&
		previous.ID == current.ID &&
		bytes.Equal(previous.RawState, current.RawState)
}

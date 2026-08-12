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

	// AuthTime is the wall-clock time at which the user most recently
	// authenticated for this grant. The token endpoint copies it into
	// the auth_time claim of issued ID tokens (OpenID Connect Core
	// 1.0 §2). Empty time signals "no recorded authentication" and the
	// claim is omitted.
	AuthTime time.Time

	// ACR is the Authentication Context Class Reference (OpenID
	// Connect Core 1.0 §2) the originating authentication satisfied.
	// The token endpoint copies it into the acr claim of issued ID
	// tokens; OIDC Core §12 requires that refresh-token-derived ID
	// tokens carry the same acr as the original. Empty when the
	// underlying authenticator did not assert a class.
	ACR string

	// AMR lists the Authentication Methods References (RFC 8176 §2)
	// recorded at the originating authentication. The token endpoint
	// copies the slice verbatim into the amr claim of issued ID
	// tokens; OIDC Core §12 requires the same set across refreshes.
	AMR []string

	// AuthorizationDetails captures the RFC 9396 authorization_details
	// the user consented to, as the decoded JSON array of objects (each
	// carrying a "type" the OP accepted). The library validates the
	// structure and the per-type shape before persisting; backends store
	// the slice verbatim. The token endpoint and introspection echo it,
	// and a refresh reproduces it from the grant. Nil when the grant
	// carried no authorization_details.
	AuthorizationDetails []map[string]any

	// CreatedAt is the wall-clock time at which the grant was first
	// recorded. Supplied by the caller.
	CreatedAt time.Time

	// UpdatedAt is the wall-clock time of the most recent modification.
	// Supplied by the caller; backends MUST persist it verbatim rather
	// than substituting a server-side now() value.
	UpdatedAt time.Time
}

// GrantClientPage is one keyset-paginated page of distinct client IDs that
// currently hold an active grant for a subject. ClientIDs use the backend's
// stable ascending client-ID order and never contain duplicates. NextCursor
// is empty when the page is exhausted; otherwise callers pass it unchanged
// to the next [GrantStore.ListClientIDsBySubject] call.
type GrantClientPage struct {
	ClientIDs  []string
	NextCursor string
}

// GrantSubjectPage is one keyset-paginated page of distinct subjects that
// currently hold an active grant for a client. Subjects use the backend's
// stable ascending subject order and never contain duplicates. NextCursor is
// empty when the page is exhausted; otherwise callers pass it unchanged to
// the next [GrantSubjectLister.ListSubjectsByClient] call.
type GrantSubjectPage struct {
	Subjects   []string
	NextCursor string
}

// GrantStore is the substore for persisted consent. It belongs to the
// atomic-routing cluster because grant updates accompany authorization-code
// exchanges, refresh-token rotations, and revocation cascades.
//
// Back-channel logout fan-out needs one more, bounded enumeration method that
// only interactive OPs exercise; it lives on the [GrantClientLister] extension
// rather than here so machine-to-machine backends need not implement it.
type GrantStore interface {
	// Save persists a new grant or replaces an existing one. Save MUST
	// return [ErrAlreadyExists] if used in insert mode and the ID is
	// already present; backends that perform upsert MAY treat Save as
	// idempotent.
	//
	// A grant is amended rather than replaced: a repeat authorization
	// adds scopes, authorization details, and a fresh authentication
	// context to what the record already holds, so the OP reads the
	// grant and writes it back inside one transaction. Backends MUST
	// make that cycle safe against a concurrent one — by locking the
	// row for the duration, or by rejecting a write whose basis has
	// changed with [ErrConflict]. A backend that does neither lets one
	// authorization drop the scope the other just recorded, while both
	// users are told their consent was stored.
	Save(ctx context.Context, g *Grant) error

	// Find returns the grant identified by id. It MUST return
	// [ErrNotFound] when no such grant exists.
	Find(ctx context.Context, id string) (*Grant, error)

	// FindBySubjectClient returns the active grant for the given
	// (subject, clientID) pair, or [ErrNotFound] if none exists. Backends
	// that store historical grants MUST return the most recent active
	// one; revoked grants MUST NOT be returned.
	FindBySubjectClient(ctx context.Context, subject, clientID string) (*Grant, error)

	// ListBySubject returns every active grant the subject currently
	// holds. The library uses the complete records for revocation and
	// grant-management cascades. Back-channel logout uses the bounded
	// ListClientIDsBySubject view instead.
	//
	// Returning an empty slice (with a nil error) is the correct
	// response when the subject holds no grants. Backends that store
	// historical grants MUST return only active records, mirroring the
	// [GrantStore.FindBySubjectClient] contract; revoked grants MUST
	// NOT appear in the result. Order is unspecified.
	ListBySubject(ctx context.Context, subject string) ([]*Grant, error)

	// Delete revokes the grant identified by id. It MUST return
	// [ErrNotFound] if no such grant exists. Backends MAY soft-delete or
	// hard-delete; the library only requires that subsequent Find and
	// FindBySubjectClient calls treat the grant as absent.
	Delete(ctx context.Context, id string) error

	// HasAny reports whether the substore contains at least one
	// persisted grant record. The library calls it once at op.New as
	// part of the pairwise immutability gate: switching the active
	// subject-issuance strategy on a non-empty grant store would
	// reassign already-issued "sub" values, breaking the OIDC Core
	// 1.0 §5.7 stability promise. Backends MAY implement it as a
	// bounded query (SELECT 1 ... LIMIT 1) rather than a full count
	// because the library only branches on the boolean.
	//
	// Implementations that soft-delete revoked grants SHOULD include
	// soft-deleted rows in the count: the gate cares about whether
	// the OP has ever issued a sub, not whether the grant is still
	// valid.
	HasAny(ctx context.Context) (bool, error)
}

// GrantClientLister extends [GrantStore] with the bounded, keyset-paginated
// audience enumeration that OpenID Connect Back-Channel Logout 1.0 fan-out
// needs. The OP requires it only when a grant mounts the browser authorize
// endpoint — the same condition that mounts /end_session and requires
// [Transactional] and [InteractionStoreCAS]. Backends serving only
// non-interactive grants (client_credentials, device_code, CIBA) never mount
// /end_session and need not implement it; the library detects support via a
// runtime type assertion and rejects the interactive configuration at op.New
// when it is absent.
type GrantClientLister interface {
	GrantStore

	// ListClientIDsBySubject returns at most limit distinct client IDs for
	// the subject, strictly after cursor in the backend's stable ascending
	// client-ID order. limit MUST be positive. Implementations MUST bound the
	// backend result set to limit+1 rows (or an equivalent native cursor
	// operation) so callers can detect another page without materialising
	// every grant.
	//
	// This audience-oriented view is separate from [GrantStore.ListBySubject]
	// because a subject can have many historical grant rows for one client.
	// Back-channel logout uses it to cap both database work and ClientStore
	// lookups before resolving delivery targets. Do not implement it by
	// calling ListBySubject and slicing the materialised result, because that
	// defeats the method's resource bound.
	ListClientIDsBySubject(ctx context.Context, subject, cursor string, limit int) (GrantClientPage, error)
}

// GrantSubjectLister extends [GrantStore] with the bounded, keyset-paginated
// subject enumeration needed when deleting a client. The registration
// endpoint uses this optional view to snapshot back-channel logout targets
// before the client's grants are removed. Backends that do not support direct
// deletion fan-out may omit it and retain the registration endpoint's delete
// hook as their fallback.
type GrantSubjectLister interface {
	GrantStore

	// ListSubjectsByClient returns at most limit distinct subjects for the
	// client, strictly after cursor in the backend's stable ascending
	// subject order. limit MUST be positive. Implementations MUST bound
	// backend work to limit+1 rows (or use an equivalent native cursor) so
	// callers can detect another page without materialising every grant.
	ListSubjectsByClient(ctx context.Context, clientID, cursor string, limit int) (GrantSubjectPage, error)
}

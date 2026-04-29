package store

import (
	"context"
	"time"
)

// Session is the persistent representation of an OP session: the server-side
// state behind the cookie that proves an end-user is currently authenticated
// at the OP. It is consulted whenever the library needs to decide whether a
// fresh authorization request can be served without re-authenticating the
// user (OpenID Connect Core 1.0 §3.1.2.1, prompt=none semantics).
//
// Sessions support the multi-account chooser pattern: a single browser may
// hold several authenticated subjects in a chooser group identified by
// ChooserGroupID, with one of them designated the active account. The
// library's UX treats the chooser group as a stable browsing context across
// account additions and switches.
type Session struct {
	// ID is the opaque session identifier (generated with crypto/rand)
	// stored in the OP cookie alongside the chooser group.
	ID string

	// Subject is the OP-internal stable identifier of the authenticated
	// end-user. Empty Subject is reserved for chooser-group bookkeeping
	// records and is not currently used by the library.
	Subject string

	// AuthTime is the wall-clock time at which the user was last
	// authenticated. It is the value the library copies into the auth_time
	// claim of issued ID Tokens (OpenID Connect Core 1.0 §2). Supplied by
	// the caller.
	AuthTime time.Time

	// AMR lists the Authentication Methods References (RFC 8176) used at
	// AuthTime. Order is significant: the library passes the slice through
	// to ID Token issuance verbatim.
	AMR []string

	// ACR is the Authentication Context Class Reference (OpenID Connect
	// Core 1.0 §2) the session satisfies. Empty if no specific class was
	// requested or asserted.
	ACR string

	// ChooserGroupID groups sessions that belong to the same browser-side
	// account chooser. Multiple sessions sharing a ChooserGroupID
	// represent the accounts a user has signed in to in this browser; the
	// library exposes the group via the multi-account chooser flow
	// described in 002-product-design §A.9.
	ChooserGroupID string

	// ExpiresAt is the absolute wall-clock expiry of the session.
	// Backends MAY garbage-collect rows where ExpiresAt is in the past.
	ExpiresAt time.Time

	// CreatedAt is the wall-clock time at which the session was first
	// persisted. Supplied by the caller.
	CreatedAt time.Time

	// UpdatedAt is the wall-clock time of the most recent modification
	// (typically a Touch). Supplied by the caller.
	UpdatedAt time.Time
}

// SessionStore is the substore for OP sessions. It is a volatile substore
// outside the transactional cluster: session writes (Save / Touch / Delete)
// are NOT coordinated with token-endpoint commits, and the OP tolerates
// session loss as a normal "user re-logs-in" event rather than a
// security incident.
//
// Embedders MAY route SessionStore to a fast cache (Redis, Memcached) via
// [op/storeadapter/composite] without violating any library invariant.
// See [ADR 0014](../../docs/adr/0014-sessions-out-of-tx-cluster.md) for
// the rationale and the future re-entry path if a feature later requires
// Session-in-tx semantics.
type SessionStore interface {
	// Save persists a new session or replaces an existing one. Save MUST
	// return [ErrAlreadyExists] if used in insert mode and the ID is
	// already present; backends that perform upsert MAY treat Save as
	// idempotent.
	Save(ctx context.Context, s *Session) error

	// Find returns the session identified by id, or [ErrNotFound] when
	// none exists. Find MUST NOT return expired sessions: a record whose
	// ExpiresAt has passed MUST be treated as absent. Backends MAY rely
	// on a background sweep to delete the row, but Find MUST honour
	// ExpiresAt regardless of sweep state.
	Find(ctx context.Context, id string) (*Session, error)

	// Touch extends the session's idle timer by setting ExpiresAt and
	// UpdatedAt to the supplied values atomically. It MUST return
	// [ErrNotFound] if the session does not exist or has expired. The
	// caller is responsible for computing the new ExpiresAt; backends do
	// not read the wall clock.
	Touch(ctx context.Context, id string, expiresAt, updatedAt time.Time) error

	// Delete removes the session identified by id. It MUST return
	// [ErrNotFound] when no such session exists. Backends MAY hard-delete
	// or mark the row deleted as long as subsequent Find calls return
	// [ErrNotFound].
	Delete(ctx context.Context, id string) error

	// ListByChooserGroup returns every non-expired session whose
	// ChooserGroupID matches groupID. It is the lookup the multi-account
	// flow needs to enumerate the accounts in a browser's chooser
	// (002-product-design §A.9). Order is unspecified; callers that need
	// stable ordering MUST sort the result themselves.
	//
	// Returning an empty slice (with a nil error) is the correct response
	// when no sessions exist for groupID. Backends MUST NOT include
	// records whose ExpiresAt has passed, mirroring [SessionStore.Find].
	ListByChooserGroup(ctx context.Context, groupID string) ([]*Session, error)
}

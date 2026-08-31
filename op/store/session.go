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
	// library exposes the group via the multi-account chooser flow.
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
// outside the atomic-routing cluster: session writes (Save / Touch / Delete)
// are NOT coordinated with token-endpoint commits, and the OP tolerates
// session loss as a normal "user re-logs-in" event rather than a
// security incident.
//
// Embedders MAY route SessionStore to a fast cache (Redis, Memcached) via
// [op/storeadapter/composite] without violating any library invariant.
//
// # Rotation is not atomic
//
// The library's session-fixation defence rotates a session ID by issuing
// a fresh record (Save) and then removing the prior record (Delete).
// SessionStore implementations are NOT required to make the pair atomic:
// embedders MUST tolerate a transient interval where two distinct session
// IDs reference the same Subject / ChooserGroupID until the Delete lands.
// Concurrent rotations of the same prior session ID MUST resolve
// deterministically — either every Save succeeds with a distinct new ID
// (and the prior record is eventually deleted by one of the racers, with
// repeat Deletes returning [ErrNotFound]) or one Save wins and the others
// surface a wrapped store error. Backends MUST NOT silently produce two
// new IDs that point at a single underlying record, and MUST NOT leave
// the prior record live indefinitely after at least one rotation has
// committed Save.
//
// # Back-channel logout delivery integrity
//
// Embedders who require OIDC Back-Channel Logout 1.0 delivery
// integrity for every initiated logout MUST route SessionStore to a
// durable backend; volatile placement (the recommended hot/cold
// default) delivers BCL on a best-effort basis bounded by the
// volatile tier's eviction / failover behaviour. A session evicted
// between establishment and /end_session silently removes the rows
// the back-channel coordinator would walk, narrowing OIDC
// Back-Channel Logout 1.0 §2.7's best-effort floor to zero. The
// [github.com/libraz/go-oidc-provider/op.AuditBCLNoSessionsForSubject]
// audit event surfaces the gap when it actually fires; declare
// the chosen posture through
// [github.com/libraz/go-oidc-provider/op.WithSessionDurabilityPosture]
// so the audit signal carries the embedder's intent.
type SessionStore interface {
	// Save persists a new session or replaces an existing one. Save MUST
	// return [ErrAlreadyExists] if used in insert mode and the ID is
	// already present; backends that perform upsert MAY treat Save as
	// idempotent.
	//
	// Replacement holds for a record that is already past its ExpiresAt
	// too. Backends MAY decline to store such a record — every read path
	// filters it out anyway — but after Save returns nil, a Find on that
	// ID MUST NOT resolve whatever the ID held before. Dropping the
	// write outright is equivalent only when the ID held nothing live.
	// The distinction is what an embedder relies on to end a session out
	// of band: a silent no-op answers nil and leaves the subject signed
	// in for the next prompt=none authorization.
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
	//
	// Those two fields are the whole of the write. Every other field,
	// and every secondary index derived from one, MUST still hold what
	// the last committed write left there — a backend that implements
	// the extension by reading the record, patching the two fields and
	// storing the whole thing back would undo a step-up's ACR or an
	// account switch's ChooserGroupID that landed in between, silently
	// and with a nil error. A backend that cannot narrow the write that
	// far MAY answer [ErrConflict] when it finds the record changed
	// under it; what it MUST NOT do is write the stale snapshot.
	//
	// Touch is idempotent: repeating it with the values the record
	// already carries MUST succeed. A backend deciding from an
	// affected-row count has to tell "nothing changed" from "no such
	// row", since an OP whose clock has second granularity computes the
	// same ExpiresAt for two requests inside one second.
	Touch(ctx context.Context, id string, expiresAt, updatedAt time.Time) error

	// Delete removes the session identified by id. It MUST return
	// [ErrNotFound] when no such session exists or when the record has
	// expired, applying the same absent-or-expired rule as
	// [SessionStore.Touch]. Naming the expired case is what keeps the
	// result independent of reclamation: a backend answering from
	// physical presence alone returns nil for a record whose ExpiresAt
	// has passed and [ErrNotFound] for that same record once a sweep or
	// a TTL eviction has removed it, so the caller observes collection
	// timing rather than session state. Backends MAY hard-delete or mark
	// the row deleted as long as subsequent Find calls return
	// [ErrNotFound], and MAY reclaim an expired record while reporting
	// [ErrNotFound] for it.
	Delete(ctx context.Context, id string) error

	// ListByChooserGroup returns every non-expired session whose
	// ChooserGroupID matches groupID. It is the lookup the multi-account
	// flow needs to enumerate the accounts in a browser's chooser.
	// Order is unspecified; callers that need stable ordering MUST sort
	// the result themselves.
	//
	// Returning an empty slice (with a nil error) is the correct response
	// when no sessions exist for groupID. Backends MUST NOT include
	// records whose ExpiresAt has passed, mirroring [SessionStore.Find].
	ListByChooserGroup(ctx context.Context, groupID string) ([]*Session, error)
}

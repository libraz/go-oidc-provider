package store

import (
	"context"
	"time"
)

// User is the persistent representation of an end-user owned by the
// embedding application. The OP only reads it: registration, password
// resets, and profile edits all happen outside the library through the
// embedding application's own UI and management plane.
//
// The struct carries the small subset of profile data the library
// actually consumes (subject, claim source, last-update timestamp).
// Embedders typically project it from a richer "users" table — only the
// fields below are observed by go-oidc-provider, so backends are free
// to ignore unused columns.
type User struct {
	// Subject is the OP-internal stable identifier that becomes the
	// "sub" claim of issued tokens. It MUST be globally unique within
	// the OP and stable across the user's lifetime.
	Subject string

	// Claims is the universe of known claim values for this subject.
	// The library projects it through internal/userinfo to release
	// only the names the granted scopes authorise.
	//
	// Backends MAY return a fresh map on every call; the library
	// treats the value as read-only.
	Claims map[string]any

	// UpdatedAt is the wall-clock time of the most recent change to
	// any field in Claims. The library copies it into the
	// "updated_at" claim when the "profile" scope is granted.
	UpdatedAt time.Time
}

// UserStore is the substore for end-user records. It is read-only from
// the library's perspective: write paths live in the embedding
// application. The OP queries it at:
//
//   - /userinfo, to assemble the response after bearer validation;
//   - the token endpoint, to embed claims in id_token bodies;
//   - administrative endpoints (e.g. session list), to render names.
//
// UserStore is intentionally outside the atomic-routing cluster: the
// OP never writes to it during a grant exchange, so coupling it to the
// authorization-code transaction would pessimise hot paths without
// improving safety.
type UserStore interface {
	// FindBySubject returns the user record identified by sub. It MUST
	// return [ErrNotFound] when no such user exists; any other non-nil
	// error indicates a backend fault.
	FindBySubject(ctx context.Context, sub string) (*User, error)
}

// UserPasswordStore extends [UserStore] with the lookups the built-in
// PrimaryPassword Step requires: username→subject resolution and
// password-hash retrieval. The split lets passkey-only deployments
// implement only [UserStore] without carrying a password column.
//
// Implementations MUST:
//
//   - Apply identical normalisation to both [UserStore.FindBySubject]
//     and [FindByUsername] so a successful login produces the same
//     subject regardless of which lookup path enrolled it (e.g.
//     case-fold the username consistently).
//   - Return [ErrNotFound] when the username does not resolve, never a
//     placeholder User; the orchestrator distinguishes "unknown user"
//     from "wrong password" and surfaces a single invalid-credentials
//     prompt either way.
//   - Return the encoded hash bytes verbatim from [ReadPasswordHash];
//     the library treats the slice as a UTF-8 PHC string
//     ($argon2id$...) and verifies it with constant-time comparison.
//     Returning a hash for a subject that has no password set is a
//     [ErrNotFound] case.
//
// The interface is intentionally read-only: enrolment, password
// resets, and rehash-on-login workflows live outside the OP because
// they touch operational concerns (email delivery, audit hooks, MFA
// re-prompting) the library does not model.
type UserPasswordStore interface {
	UserStore

	// FindByUsername returns the user record identified by the
	// embedder's chosen username convention (email address, login
	// handle, employee ID, ...). The library passes the value the SPA
	// submits verbatim; implementations are responsible for any
	// case-folding or trimming. It MUST return [ErrNotFound] when no
	// such user exists.
	//
	// The lookup MUST be single-valued: a username resolves to at most
	// one subject, and the directory is responsible for enforcing that
	// on the write path. Two entries sharing a username make a login
	// non-deterministic — the same credentials would issue tokens for
	// one subject or the other depending on which row the lookup
	// surfaced.
	FindByUsername(ctx context.Context, username string) (*User, error)

	// ReadPasswordHash returns the PHC-encoded password hash for the
	// subject (e.g. "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>").
	// It MUST return [ErrNotFound] when the subject exists but has no
	// password credential set (e.g. passkey-only account); the
	// orchestrator surfaces the same invalid-credentials prompt as a
	// hash-mismatch so the response is enumeration-safe.
	ReadPasswordHash(ctx context.Context, subject string) ([]byte, error)
}

package store

import (
	"context"
	"errors"
	"time"
)

// ErrPasswordHashUpdateUnsupported is returned by a
// [UserPasswordHashUpdater] that cannot persist a new hash for this
// subject (for example a store that wraps several backends and whose
// user backend is not an updater). The library then keeps the legacy
// hash and logs once.
//
// Stable since v1.5.
var ErrPasswordHashUpdateUnsupported = errors.New("store: password hash update unsupported")

// User is the persistent representation of an end-user owned by the
// embedding application. The OP only reads it, apart from the optional
// rehash write-back of a legacy password hash ([UserPasswordHashUpdater]):
// registration, password resets, and profile edits all happen outside the
// library through the embedding application's own UI and management plane.
//
// The struct carries the small subset of profile data the library
// actually consumes (subject, claim source, last-update timestamp).
// Embedders typically project it from a richer "users" table — only the
// fields below are observed by go-oidc-provider, so backends are free
// to ignore unused columns.
type User struct {
	// Subject is the OP-internal stable identifier that becomes the
	// "sub" claim of issued tokens. It MUST be globally unique within
	// the OP, stable across the user's lifetime, and never reassigned
	// to another user (OpenID Connect Core §2). RPs key accounts on it,
	// so it cannot be changed later: use an opaque value such as a
	// random UUID. An email address or username changes, and an
	// auto-increment row id discloses the user count and can be reissued.
	Subject string

	// Claims is the universe of known claim values for this subject.
	// The library projects it through internal/userinfo to release
	// only the names the granted scopes authorise.
	//
	// Standard claims carry the JSON type OpenID Connect Core §5.1
	// gives them (email_verified a bool, updated_at a number, address
	// an object, the rest strings); one of another type is not released.
	// Building the map with [StandardClaims.Map] gets the types right
	// by construction.
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
// the library's perspective, except for the optional rehash write-back of
// a legacy password hash ([UserPasswordHashUpdater]): all other write
// paths live in the embedding application. The OP queries it at:
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
	//
	// Returning [ErrNotFound] for a soft-deleted or disabled user is the
	// supported way to stop it: the token endpoint then refuses a refresh
	// with invalid_grant and tears down the grant, and [UserPasswordStore]'s
	// FindByUsername must likewise return [ErrNotFound] so login fails. To
	// revoke tokens already issued at once, call op.Provider.RevokeSubject.
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
//     Other encodings (e.g. bcrypt) are accepted only through
//     PrimaryPassword.LegacySchemes (see op.BcryptHashScheme).
//     Returning a hash for a subject that has no password set is a
//     [ErrNotFound] case.
//
// The interface reads only: enrolment and password resets live outside
// the OP because they touch operational concerns (email delivery, audit
// hooks, MFA re-prompting) the library does not model. The one write the
// OP performs is the optional [UserPasswordHashUpdater] rehash of a
// legacy hash.
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

	// ReadPasswordHash returns the stored password hash for the subject:
	// a PHC-encoded argon2id string (e.g.
	// "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>"), or, when
	// PrimaryPassword.LegacySchemes is set, the legacy encoding exactly as
	// stored (e.g. a bcrypt "$2a$", "$2b$" or "$2y$" hash) until the
	// password is rewritten. It MUST return [ErrNotFound] when the subject exists but has no
	// password credential set (e.g. passkey-only account); the
	// orchestrator surfaces the same invalid-credentials prompt as a
	// hash-mismatch so the response is enumeration-safe.
	ReadPasswordHash(ctx context.Context, subject string) ([]byte, error)
}

// UserPasswordHashUpdater is the optional write side of
// [UserPasswordStore]. When the store behind PrimaryPassword implements
// it, a successful login against a legacy hash (see
// op.PasswordHashScheme) re-encodes the password as argon2id and stores
// it through UpdatePasswordHash.
//
// UpdatePasswordHash replaces the PHC-encoded hash for subject and MUST
// return [ErrNotFound] for an unknown subject. A failure never fails the
// login: the legacy hash stays and the next login retries. Return
// [ErrPasswordHashUpdateUnsupported] when the store cannot update.
//
// After a rewrite the column holds argon2id, so any other login path of
// the application that verifies the column with bcrypt directly must first
// switch to a verifier that accepts both encodings (op.VerifyPassword for
// argon2id, the legacy scheme's Verify for the rest); until it does, leave
// this interface unimplemented.
//
// Stable since v1.5.
type UserPasswordHashUpdater interface {
	UpdatePasswordHash(ctx context.Context, subject string, encoded []byte) error
}

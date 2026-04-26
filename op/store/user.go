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
// UserStore is intentionally outside the transactional cluster: the
// OP never writes to it during a grant exchange, so coupling it to the
// authorization-code transaction would pessimise hot paths without
// improving safety.
type UserStore interface {
	// FindBySubject returns the user record identified by sub. It MUST
	// return [ErrNotFound] when no such user exists; any other non-nil
	// error indicates a backend fault.
	FindBySubject(ctx context.Context, sub string) (*User, error)
}

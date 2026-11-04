package authn

import "context"

// PasswordHashScheme verifies password hashes that are not argon2id PHC
// strings. Recognizes selects the scheme by the stored encoding; Verify
// reports a match, returning an error only for a backend fault (a
// mismatch is (false, nil)).
type PasswordHashScheme interface {
	// Recognizes reports whether encoded is in this scheme's encoding.
	Recognizes(encoded []byte) bool

	// Verify reports whether password matches encoded. A mismatch is
	// (false, nil).
	Verify(ctx context.Context, encoded []byte, password string) (bool, error)
}

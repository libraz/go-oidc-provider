package op

import (
	"bytes"
	"context"

	"golang.org/x/crypto/bcrypt"

	"github.com/libraz/go-oidc-provider/internal/authn/password"
)

// bcryptMaxPasswordBytes is bcrypt's input limit; longer input is silently
// truncated by some implementations.
const bcryptMaxPasswordBytes = 72

// bcryptMaxCost is the highest stored work factor [BcryptHashScheme] will
// run. A hash above it is treated as a mismatch, so a corrupted or hostile
// imported row cannot make one login attempt cost seconds to hours of CPU.
const bcryptMaxCost = 15

// PasswordHashScheme verifies password hashes that are not argon2id, so an
// existing user table can log in without a forced reset. Recognizes
// selects the scheme from the stored encoding; Verify reports a match and
// returns an error only for a backend fault, never for a mismatch.
//
// Stable since v1.5.
type PasswordHashScheme = password.LegacyScheme

// BcryptHashScheme returns the [PasswordHashScheme] for bcrypt hashes
// ($2a$, $2b$ and $2y$ prefixes).
//
// bcrypt only uses the first 72 bytes of a password. This scheme reports
// a mismatch for any password longer than 72 bytes rather than comparing
// a truncated prefix, so a longer string never matches by accident. A
// user whose migration source truncated a longer password before storing
// the hash can therefore no longer log in or be rehashed and needs a
// password reset.
//
// A stored hash whose cost factor is above 15 is refused as a mismatch
// without running bcrypt; such a user needs a password reset.
//
// Verifying a legacy hash takes a different time than an argon2id one.
// The difference disappears for a user once the hash is rewritten, which
// happens on the first successful login when the store implements
// [store.UserPasswordHashUpdater].
//
// Stable since v1.5.
func BcryptHashScheme() PasswordHashScheme { return bcryptScheme{} } //nolint:ireturn // the scheme is consumed through the interface.

type bcryptScheme struct{}

func (bcryptScheme) Recognizes(encoded []byte) bool {
	return bytes.HasPrefix(encoded, []byte("$2a$")) ||
		bytes.HasPrefix(encoded, []byte("$2b$")) ||
		bytes.HasPrefix(encoded, []byte("$2y$"))
}

func (bcryptScheme) Verify(_ context.Context, encoded []byte, pw string) (bool, error) {
	if len(pw) > bcryptMaxPasswordBytes {
		return false, nil
	}
	if cost, err := bcrypt.Cost(encoded); err != nil || cost > bcryptMaxCost {
		return false, nil //nolint:nilerr // a malformed or over-cost stored hash is a mismatch, not a backend fault.
	}
	// Any bcrypt failure, including a malformed stored hash, is a mismatch:
	// the caller treats the account like any other failed login.
	return bcrypt.CompareHashAndPassword(encoded, []byte(pw)) == nil, nil
}

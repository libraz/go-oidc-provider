package inmem

import (
	"time"

	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// hashKey is the in-memory analogue of the SHA-256-with-pepper
// fingerprint a production backend SHOULD use to persist
// authorization-code / refresh-token / PAR-uri rows. The reference
// implementation has no pepper: storing the raw SHA-256 hash exists to
// pin the hash-on-store contract documented in [op/store/doc.go]
// (a snapshot of the in-memory map MUST NOT contain the bearer
// secret) and to keep the read paths constant-time relative to a
// non-existent key.
//
// The body delegates to [patterns.Digest] so every adapter in the
// repository (inmem, SQL, Redis, ...) shares one digest call site:
// the hash-on-store invariant cannot drift between backends, and a
// future swap to HMAC-with-pepper happens in one file.
func hashKey(s string) string {
	return patterns.Digest(s)
}

// constantTimeKeyMatch reports whether stored and presented hash to the
// same digest, comparing in constant time relative to the digest
// length. The check is structurally redundant given map lookup is
// keyed on the digest, but a constant-time compare keeps the helper
// safe to copy into a backend that walks a slice or otherwise diverges
// from the map-lookup model.
//
// The body delegates to [patterns.ConstantTimeKeyMatch] so the
// adapter corpus shares a single comparison primitive.
func constantTimeKeyMatch(stored, presented string) bool {
	return patterns.ConstantTimeKeyMatch(stored, presented)
}

// isExpired reports whether t is strictly before clock.Now(). The zero
// time is treated as "no expiry" so records may opt out of expiry by
// leaving the field unset.
//
// The body delegates to [patterns.IsExpiredStrict] so the strict-less-
// than boundary semantic is shared verbatim with the SQL adapter; the
// thin wrapper keeps the existing (t, clock) call surface inside the
// inmem package so every Find / Consume path keeps reading naturally.
func isExpired(t time.Time, clock Clock) bool {
	return patterns.IsExpiredStrict(t, clock.Now())
}

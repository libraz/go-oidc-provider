package inmem

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
// non-existent key. Production backends MAY reuse this helper but
// SHOULD apply HMAC with a server-side pepper before storage.
func hashKey(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// constantTimeKeyMatch reports whether stored and presented hash to the
// same digest, comparing in constant time relative to the digest
// length. The check is structurally redundant given map lookup is
// keyed on the digest, but a constant-time compare keeps the helper
// safe to copy into a backend that walks a slice or otherwise diverges
// from the map-lookup model.
func constantTimeKeyMatch(stored, presented string) bool {
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
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

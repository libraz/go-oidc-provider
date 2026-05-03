package patterns

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// Digest returns the SHA-256 digest of raw, hex-encoded as 64 ASCII
// bytes. It is the shared one-way fingerprint helper that adapters
// (inmem, SQL, Redis, ...) use to honour the hash-on-store contract
// declared in the [github.com/libraz/go-oidc-provider/op/store] package
// godoc: opaque bearer secrets — authorization codes, refresh-token
// IDs, PAR URIs, and any other credential whose possession alone is
// authoritative — MUST be persisted as the digest of the wire value so
// that a database snapshot, replica, or backup leak does not yield
// redeemable artefacts.
//
// The returned value is hex-encoded so it can be stored in a TEXT /
// VARCHAR column without portability surprises across SQLite, MySQL,
// and PostgreSQL, and so it indexes uniformly. The encoding is fixed
// at 64 ASCII characters (lowercase hex of a 32-byte hash) so a column
// sized for it can be tightened at schema-design time.
//
// Production deployments SHOULD wrap Digest behind a key-derivation
// step (HMAC with a server-side pepper, or a KMS-backed MAC) so a
// stolen database also requires a stolen key to mount an offline
// dictionary attack against the digest. The wrapping is a future
// extension; for v0.x the helper exposes plain SHA-256 to keep the
// invariant — "no raw secret in storage" — visible in every adapter.
func Digest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// DigestBytes returns the SHA-256 digest of raw as a fixed-size byte
// array. It is the byte-form companion to [Digest] for adapters that
// prefer to store the digest as BYTEA / BLOB rather than hex text.
// Callers that store the digest as text MUST use [Digest] so the
// stored representation is uniform across the adapter corpus.
func DigestBytes(raw string) [32]byte {
	return sha256.Sum256([]byte(raw))
}

// ConstantTimeKeyMatch reports whether stored and presented are
// byte-for-byte equal, comparing in constant time relative to the
// shorter operand. The check is structurally redundant when the
// caller has already located the record via map lookup keyed on the
// digest, but it is the right primitive to reach for when an adapter
// walks a slice or otherwise diverges from an exact-key model: a
// stolen database compounded by a timing oracle should still fail
// closed.
//
// Both inputs are expected to be the hex output of [Digest] (i.e. of
// equal length); the helper does not enforce that constraint so callers
// remain free to pass shorter prefixes during tests, but production
// adapters MUST pass full-width digests.
func ConstantTimeKeyMatch(stored, presented string) bool {
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

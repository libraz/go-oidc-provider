package op

import (
	"crypto"
	"time"
)

// SigningKey is one entry in a [Keyset]. It bundles a [crypto.Signer]
// (typically an ECDSA P-256 private key) with the key identifier the OP
// publishes alongside it in JWKS.
//
// SigningKey carries the private signer; callers MUST treat instances as
// secret and never log them.
type SigningKey struct {
	// KeyID is the "kid" header value advertised in JWKS and stamped on
	// every JWS the OP signs with this key. It MUST be unique within
	// the Keyset and stable across the key's lifetime so RP caches stay
	// warm during rotations.
	KeyID string

	// Signer is the private key implementing [crypto.Signer]. The
	// library only signs with ES256 in v1.0; supplying a non-P-256 key
	// causes [op.New] to fail at construction time.
	Signer crypto.Signer

	// NotAfter is the optional retirement deadline for the entry.
	// The zero value (the default) means "never retires"; the entry
	// continues to verify presented JWS / JWE values until the
	// embedder rebuilds the [Keyset] without it.
	//
	// A non-zero value pins the rotation window: once the OP's clock
	// advances on or past NotAfter, verification paths reject any
	// presented kid that names this entry even though the public key
	// is still advertised in JWKS for cache warmth. The asymmetry is
	// deliberate (RFC 7517 §4.5): retiring RPs see the key for as
	// long as the cache holds it, but the OP itself stops trusting
	// the kid at the deadline so a forged token that reuses the old
	// kid after a leak cannot ride past the rotation.
	//
	// The retirement gate runs only on verification ([keys.Set.Find]).
	// The active signer is selected by position in the slice and never
	// consulted against NotAfter at signing time, because the embedder
	// is expected to swap the active entry by rebuilding the [Keyset]
	// rather than letting the runtime mutate selection mid-flight.
	//
	// Stable since v0.x. Tracks H-F1.
	NotAfter time.Time
}

// Keyset is the ordered list of [SigningKey] values the OP advertises and
// signs with. The first entry is the active signer; subsequent entries are
// retiring keys kept in JWKS so RPs can still verify recent tokens.
//
// Keyset is a value type; callers MAY share it across Providers as long as
// every contained Signer is itself safe for concurrent use. Rotation is
// performed by constructing a new Keyset and calling [op.New] again from
// supervisor code; the library does not mutate the slice in place.
type Keyset []SigningKey

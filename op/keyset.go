package op

import "crypto"

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

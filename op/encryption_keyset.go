package op

import (
	"crypto"
	"time"
)

// EncryptionKey is one entry in an [EncryptionKeyset]. It bundles a
// private key (used to decrypt inbound JWE — typically request_object
// payloads on /authorize and /par) with the kid the OP publishes
// alongside the public half on the JWKs endpoint.
//
// EncryptionKey carries a private key; callers MUST treat instances
// as secret and never log them.
//
// Stable since v0.9.1 (added with Wave T1).
type EncryptionKey struct {
	// KeyID is the "kid" header advertised in JWKS and inspected on
	// inbound JWE protected headers to route to the right private
	// key. It MUST be unique within the [EncryptionKeyset] and stable
	// across the key's lifetime so RP caches stay warm during
	// rotations.
	KeyID string

	// PrivateKey is the asymmetric private key used to decrypt
	// inbound JWE addressed to this kid. The library accepts:
	//
	//   - *rsa.PrivateKey with N.BitLen >= 2048 (used for the
	//     RSA-OAEP-* family)
	//   - *ecdsa.PrivateKey on P-256 / P-384 / P-521 (used for the
	//     ECDH-ES family)
	//
	// Other key shapes are rejected at [op.New] construction time.
	// RFC 7517 §4.2 forbids reusing a signing key (use=sig) as an
	// encryption key (use=enc), so the [Keyset] supplied via
	// [WithKeyset] and the [EncryptionKeyset] supplied here MUST be
	// disjoint sets of key material.
	PrivateKey crypto.PrivateKey

	// Algorithm pins the JWE alg ("RSA-OAEP-256", "ECDH-ES",
	// "ECDH-ES+A128KW", "ECDH-ES+A256KW") this key advertises in
	// JWKS when the embedder needs a specific "alg" claim on the
	// published JWK.
	//
	// Empty (the default) infers from the key shape:
	//   - RSA → "RSA-OAEP-256"
	//   - ECDSA → "ECDH-ES"
	//
	// Embedders who need to pin an ECDH-ES key-wrap variant
	// (A128KW / A256KW) supply the explicit value here. Algorithms
	// outside the v0.9.1 closed allow-list ([op.SupportedEncryptionAlgs])
	// are rejected at construction time.
	Algorithm string

	// NotAfter is the optional retirement deadline for the entry.
	// Zero (the default) means "never retires"; a non-zero value
	// is the hard retirement deadline: on or after it the OP refuses
	// to decrypt JWE addressed to this kid and stops advertising the
	// public half in JWKS. Set the deadline only after the JWKS cache
	// overlap and the longest accepted request lifetime have elapsed;
	// publishing a key after it can no longer decrypt requests would
	// cause RPs to select an unusable recipient.
	NotAfter time.Time
}

// EncryptionKeyset is the ordered list of [EncryptionKey] values the
// OP uses to decrypt inbound JWE and publishes on the JWKs endpoint
// with use=enc. The first entry is the active key for outbound JWE
// (id_token / userinfo / JARM / introspection encryption); subsequent
// entries are published only until their respective NotAfter deadline.
// During a rotation overlap, retain the retiring entry and use
// [WithJWKSRotationActive] to shorten JWKS caching; remove it only after
// that overlap and the longest accepted request lifetime have elapsed.
//
// EncryptionKeyset is a value type; callers MAY share it across
// Providers as long as every contained key is itself safe for
// concurrent use. Rotation is performed by constructing a new
// keyset and calling [op.New] again from supervisor code; the
// library does not mutate the slice in place.
//
// Stable since v0.9.1.
type EncryptionKeyset []EncryptionKey

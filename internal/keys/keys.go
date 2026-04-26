package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"
)

// ErrInvalidKey is returned by [NewSet] when an entry fails alg policy.
// It wraps a more specific cause so callers can present operator-friendly
// diagnostics; the wrapped error never reaches the wire.
var ErrInvalidKey = errors.New("keys: invalid signing key")

// Entry is the internal representation of one signing key. It mirrors
// op.SigningKey without depending on the public package; conversion happens
// inside op when the user-supplied Keyset is fed into [NewSet].
type Entry struct {
	// KeyID is the public "kid" header advertised in JWKS and stamped on
	// every JWS the OP signs with this key.
	KeyID string

	// Signer is the private key. The library only signs with ES256 in
	// v1.0; non-P-256 keys are rejected at construction time.
	Signer crypto.Signer
}

// Set is the validated, immutable collection of signing keys the OP uses.
// The first entry is the active signer; subsequent entries are retiring
// keys still advertised in JWKS so RPs can verify recently-issued tokens.
type Set struct {
	entries []Entry
	jwks    josev4.JSONWebKeySet
}

// NewSet validates entries and builds the runtime [Set]. It returns an
// error wrapping [ErrInvalidKey] when any entry is missing fields, has a
// duplicate KeyID, or carries a non-ES256 key shape. The caller (op.New)
// has already performed the same checks; we re-validate here so that
// internal callers cannot bypass the policy by constructing a Set
// directly.
func NewSet(entries []Entry) (*Set, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: empty keyset", ErrInvalidKey)
	}
	seen := make(map[string]struct{}, len(entries))
	jwks := josev4.JSONWebKeySet{Keys: make([]josev4.JSONWebKey, 0, len(entries))}
	out := make([]Entry, len(entries))
	for i, e := range entries {
		if e.KeyID == "" {
			return nil, fmt.Errorf("%w: entry %d has empty KeyID", ErrInvalidKey, i)
		}
		if _, dup := seen[e.KeyID]; dup {
			return nil, fmt.Errorf("%w: duplicate KeyID %q", ErrInvalidKey, e.KeyID)
		}
		seen[e.KeyID] = struct{}{}
		if e.Signer == nil {
			return nil, fmt.Errorf("%w: entry %q has nil Signer", ErrInvalidKey, e.KeyID)
		}
		pub, ok := e.Signer.Public().(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: entry %q is not ECDSA P-256", ErrInvalidKey, e.KeyID)
		}
		jwks.Keys = append(jwks.Keys, josev4.JSONWebKey{
			Key:       pub,
			KeyID:     e.KeyID,
			Algorithm: string(josev4.ES256),
			Use:       "sig",
		})
		out[i] = e
	}
	return &Set{entries: out, jwks: jwks}, nil
}

// Active returns the signing key the OP uses for newly-issued tokens.
// Callers MUST treat the returned [Entry] as read-only.
func (s *Set) Active() Entry { return s.entries[0] }

// JWKS returns the public JWKS view of the [Set]. The returned value is a
// shallow copy: the slice header is fresh, but the entries are shared.
// Callers MUST NOT mutate the returned [josev4.JSONWebKey] values.
func (s *Set) JWKS() josev4.JSONWebKeySet {
	out := josev4.JSONWebKeySet{Keys: make([]josev4.JSONWebKey, len(s.jwks.Keys))}
	copy(out.Keys, s.jwks.Keys)
	return out
}

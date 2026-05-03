package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// ErrInvalidEncryptionKey is returned by [NewEncryptionSet] when an
// entry fails the use=enc construction-time policy: empty kid,
// duplicate kid, nil PrivateKey, or a key shape outside the
// asymmetric allow-list (RSA-2048+ / ECDSA P-256/P-384/P-521).
var ErrInvalidEncryptionKey = errors.New("keys: invalid encryption key")

// EncryptionEntry is the internal representation of one encryption
// key. It mirrors op.EncryptionKey without depending on the public
// package; conversion happens inside op when the user-supplied
// EncryptionKeyset is fed into [NewEncryptionSet].
type EncryptionEntry struct {
	// KeyID is the public "kid" header advertised in JWKS and
	// inspected on inbound JWE protected headers to route to the
	// right private key. It MUST be unique within the set.
	KeyID string

	// PrivateKey is the asymmetric private key used for decryption.
	// It MUST be either *rsa.PrivateKey (with N.BitLen >= 2048) or
	// *ecdsa.PrivateKey (with curve P-256 / P-384 / P-521).
	PrivateKey crypto.PrivateKey

	// Algorithm pins the JWE alg this key advertises in JWKS when
	// the embedder needs a specific "alg" claim on the published
	// JWK. Empty (the default) infers from the key shape:
	// RSA-OAEP-256 for *rsa.PublicKey, ECDH-ES for *ecdsa.PublicKey.
	Algorithm string

	// NotAfter is the optional retirement deadline. Zero means
	// "never retires"; a non-zero value pins the rotation gate so
	// [EncryptionSet.Resolve] rejects the kid on or after the
	// deadline (mirroring the signing keyset's H-F1 posture).
	NotAfter time.Time
}

// EncryptionSet is the validated, immutable collection of encryption
// keys the OP uses to decrypt inbound JWE (request_object) and
// publishes (public halves only) on the JWKs endpoint with use=enc.
//
// The set is functionally distinct from the signing [Set]: a single
// JWK MUST NOT carry both use=sig and use=enc (RFC 7517 §4.2). The
// types are separate so a misconfigured embedder cannot accidentally
// reuse a signer for encryption.
type EncryptionSet struct {
	entries  []EncryptionEntry
	jwks     josev4.JSONWebKeySet
	now      func() time.Time
	observer RetiredKidObserver
}

// NewEncryptionSet validates entries and builds the runtime
// [EncryptionSet]. It returns an error wrapping
// [ErrInvalidEncryptionKey] when any entry is missing fields, has a
// duplicate kid, or carries a key shape outside the asymmetric
// allow-list.
//
// The function reuses [SetOption] for the wall-clock seam and the
// retired-kid observer so encryption-side rotation observability
// composes with the signing-side audit pipeline (the same
// op.AuditKeyRetiredKidPresented event covers both).
func NewEncryptionSet(entries []EncryptionEntry, opts ...SetOption) (*EncryptionSet, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: empty keyset", ErrInvalidEncryptionKey)
	}
	cfg := setConfig{now: timex.SystemClock.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	seen := make(map[string]struct{}, len(entries))
	jwks := josev4.JSONWebKeySet{Keys: make([]josev4.JSONWebKey, 0, len(entries))}
	out := make([]EncryptionEntry, len(entries))
	for i, e := range entries {
		if e.KeyID == "" {
			return nil, fmt.Errorf("%w: entry %d has empty KeyID", ErrInvalidEncryptionKey, i)
		}
		if _, dup := seen[e.KeyID]; dup {
			return nil, fmt.Errorf("%w: duplicate KeyID %q", ErrInvalidEncryptionKey, e.KeyID)
		}
		seen[e.KeyID] = struct{}{}
		if e.PrivateKey == nil {
			return nil, fmt.Errorf("%w: entry %q has nil PrivateKey", ErrInvalidEncryptionKey, e.KeyID)
		}
		pub, alg, err := encPublicAndAlg(e.PrivateKey, e.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %q: %w", ErrInvalidEncryptionKey, e.KeyID, err)
		}
		jwks.Keys = append(jwks.Keys, josev4.JSONWebKey{
			Key:       pub,
			KeyID:     e.KeyID,
			Algorithm: alg,
			Use:       "enc",
		})
		out[i] = e
	}
	return &EncryptionSet{
		entries:  out,
		jwks:     jwks,
		now:      cfg.now,
		observer: cfg.observer,
	}, nil
}

// encPublicAndAlg extracts the public half of priv and selects the
// JWK "alg" advertisement. The selection rules:
//
//   - RSA: must be at least [jose.MinRSAKeyBits]; alg defaults to
//     "RSA-OAEP-256" (the v0.9.1 ship list does not include 384/512
//     for dependency reasons; see ADR 0030 §Q1 amendment).
//   - ECDSA: must be on P-256 / P-384 / P-521; alg defaults to
//     "ECDH-ES". Embedders may pin "ECDH-ES+A128KW" / "ECDH-ES+A256KW"
//     explicitly via [EncryptionEntry.Algorithm].
//
// An explicit Algorithm value is validated against [jose.JWEAlg.IsAllowed]
// so an embedder cannot smuggle a non-shipped alg onto the published JWK.
func encPublicAndAlg(priv crypto.PrivateKey, explicitAlg string) (crypto.PublicKey, string, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		if k.N == nil || k.N.BitLen() < jose.MinRSAKeyBits {
			return nil, "", fmt.Errorf("RSA key must be at least %d bits", jose.MinRSAKeyBits)
		}
		return chooseEncAlg(&k.PublicKey, explicitAlg, jose.JWEAlgRSAOAEP256, "RSA")
	case *ecdsa.PrivateKey:
		if k.Curve == nil {
			return nil, "", errors.New("ECDSA key has nil curve")
		}
		if !isAllowedECDHCurve(k.Curve.Params().Name) {
			return nil, "", fmt.Errorf("ECDSA curve %q is not on the OP allow-list", k.Curve.Params().Name)
		}
		return chooseEncAlg(&k.PublicKey, explicitAlg, jose.JWEAlgECDHES, "ECDSA")
	default:
		return nil, "", fmt.Errorf("unsupported PrivateKey type %T", priv)
	}
}

// chooseEncAlg picks the alg label to advertise on the published JWK.
// The empty input falls back to def; a non-empty input is validated
// against the package allow-list and against the key family
// (RSA-OAEP-* requires RSA, ECDH-ES* requires ECDSA).
func chooseEncAlg(pub crypto.PublicKey, explicit string, def jose.JWEAlg, family string) (crypto.PublicKey, string, error) {
	if explicit == "" {
		return pub, def.String(), nil
	}
	parsed, ok := jose.ParseJWEAlg(explicit)
	if !ok {
		return nil, "", fmt.Errorf("alg %q is not in the JWE allow-list", explicit)
	}
	if !algMatchesKeyFamily(parsed, family) {
		return nil, "", fmt.Errorf("alg %q is not compatible with %s key", explicit, family)
	}
	return pub, parsed.String(), nil
}

// algMatchesKeyFamily reports whether a JWE alg is compatible with
// the supplied key family. RSA keys serve only the RSA-OAEP-* family;
// ECDSA keys serve only the ECDH-ES family.
func algMatchesKeyFamily(alg jose.JWEAlg, family string) bool {
	switch family {
	case "RSA":
		return alg == jose.JWEAlgRSAOAEP256
	case "ECDSA":
		return alg == jose.JWEAlgECDHES ||
			alg == jose.JWEAlgECDHESA128KW ||
			alg == jose.JWEAlgECDHESA256KW
	default:
		return false
	}
}

// isAllowedECDHCurve reports whether the curve name (Curve.Params().Name)
// is on the v0.9.1 ECDH-ES allow-list. P-256 / P-384 / P-521 are
// permitted; P-224 and any custom curve are rejected.
func isAllowedECDHCurve(name string) bool {
	switch name {
	case "P-256", "P-384", "P-521":
		return true
	default:
		return false
	}
}

// Resolve returns the private key whose kid matches keyID. The
// boolean is false when no entry matches OR when the matching entry
// has retired per its [EncryptionEntry.NotAfter] (the same
// observer-fed retirement gate the signing [Set.Find] uses).
//
// Decrypt callers MUST treat ok=false as a hard kid-unknown signal
// and MUST NOT fall back to trial decryption when kid is present —
// see [internal/jose.Decrypt] for the rationale.
func (s *EncryptionSet) Resolve(keyID string) (any, bool) {
	for _, e := range s.entries {
		if e.KeyID != keyID {
			continue
		}
		if !e.NotAfter.IsZero() {
			now := s.nowOrSystem()
			if !now.Before(e.NotAfter) {
				if s.observer != nil {
					s.observer(keyID)
				}
				return nil, false
			}
		}
		return e.PrivateKey, true
	}
	return nil, false
}

// All returns every live private key in rotation order (as the
// embedder supplied them). Used by [internal/jose.Decrypt] for the
// kid-absent fallback iteration; retired entries are skipped so the
// fallback respects the same rotation gate as [Resolve].
func (s *EncryptionSet) All() []any {
	out := make([]any, 0, len(s.entries))
	now := s.nowOrSystem()
	for _, e := range s.entries {
		if !e.NotAfter.IsZero() && !now.Before(e.NotAfter) {
			continue
		}
		out = append(out, e.PrivateKey)
	}
	return out
}

// JWKS returns the public JWKs view of the [EncryptionSet]. Every
// entry is published with use=enc; retired entries remain visible
// (mirroring the signing-side rotation-grace pattern) so RPs see the
// public key for as long as their cache holds it.
//
// The returned value is a shallow copy: the slice header is fresh
// but the keys are shared. Callers MUST NOT mutate the returned
// [josev4.JSONWebKey] values.
func (s *EncryptionSet) JWKS() josev4.JSONWebKeySet {
	out := josev4.JSONWebKeySet{Keys: make([]josev4.JSONWebKey, len(s.jwks.Keys))}
	copy(out.Keys, s.jwks.Keys)
	return out
}

// nowOrSystem mirrors [Set.nowOrSystem]. A nil now defensively
// collapses onto [timex.SystemClock] so the retirement gate cannot
// accidentally accept a retired kid because the clock seam was
// missed at construction.
func (s *EncryptionSet) nowOrSystem() time.Time {
	if s.now == nil {
		return timex.SystemClock.Now()
	}
	return s.now()
}

package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"reflect"
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
	// deadline (mirroring the signing keyset's posture).
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
	jwe      jose.JWEPolicy

	// ctx is the request context [Resolve] hands to the
	// [RetiredKidObserver]. It is nil on the set built at startup and
	// non-nil only on the per-request shallow copies [WithContext]
	// returns. Carrying a context on a struct is normally a smell; it
	// is the only route available here because
	// [jose.EncryptionKeyResolver] is the interface
	// [jose.Decrypt] consults and its methods take no context.
	// The field is read for observability alone — no decryption path
	// branches on it, and no path observes cancellation through it.
	ctx context.Context
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
// op.AuditKeyRetiredKidPresented event covers both). [WithJWEPolicy]
// additionally pins the deployment's alg / enc narrowing onto the set,
// which is what carries the restriction into
// [jose.Decrypt].
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
		if isNilPrivateKey(e.PrivateKey) {
			return nil, fmt.Errorf("%w: entry %q has nil PrivateKey", ErrInvalidEncryptionKey, e.KeyID)
		}
		pub, alg, err := encPublicAndAlg(e.PrivateKey, e.Algorithm, cfg.jwe)
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
		jwe:      cfg.jwe,
	}, nil
}

// JWEPolicy implements [jose.EncryptionPolicyResolver] so
// [jose.Decrypt] enforces the deployment's narrowing on every
// inbound ciphertext this set is asked to decrypt. The value comes from
// [WithJWEPolicy]; omitting the option leaves the package allow-list in
// force.
func (s *EncryptionSet) JWEPolicy() jose.JWEPolicy {
	return s.jwe
}

// isNilPrivateKey detects both a nil interface and a crypto.PrivateKey
// interface carrying a typed-nil value. The latter otherwise enters the RSA or
// ECDSA type-switch arm and panics when public-key fields are inspected.
func isNilPrivateKey(key crypto.PrivateKey) bool {
	if key == nil {
		return true
	}
	value := reflect.ValueOf(key)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return value.IsNil()
	default:
		return false
	}
}

// encPublicAndAlg extracts the public half of priv and selects the
// JWK "alg" advertisement. The selection rules:
//
//   - RSA: must be at least [jose.MinRSAKeyBits]; alg defaults to
//     "RSA-OAEP-256" (the v0.9.1 ship list does not include 384/512
//     for dependency reasons).
//   - ECDSA: must be on P-256 / P-384 / P-521; alg defaults to
//     "ECDH-ES". Embedders may pin "ECDH-ES+A128KW" / "ECDH-ES+A256KW"
//     explicitly via [EncryptionEntry.Algorithm].
//
// An explicit Algorithm value is validated against [jose.JWEAlg.IsAllowed]
// so an embedder cannot smuggle a non-shipped alg onto the published JWK,
// and against policy so the published metadata cannot name an alg the
// deployment's own narrowing has switched off.
func encPublicAndAlg(priv crypto.PrivateKey, explicitAlg string, policy jose.JWEPolicy) (crypto.PublicKey, string, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		if k.N == nil || k.N.BitLen() < jose.MinRSAKeyBits {
			return nil, "", fmt.Errorf("RSA key must be at least %d bits", jose.MinRSAKeyBits)
		}
		return chooseEncAlg(&k.PublicKey, explicitAlg, jose.JWEAlgRSAOAEP256, "RSA", policy)
	case *ecdsa.PrivateKey:
		if k.Curve == nil {
			return nil, "", errors.New("ECDSA key has nil curve")
		}
		if !isAllowedECDHCurve(k.Curve.Params().Name) {
			return nil, "", fmt.Errorf("ECDSA curve %q is not on the OP allow-list", k.Curve.Params().Name)
		}
		return chooseEncAlg(&k.PublicKey, explicitAlg, jose.JWEAlgECDHES, "ECDSA", policy)
	default:
		return nil, "", fmt.Errorf("unsupported PrivateKey type %T", priv)
	}
}

// chooseEncAlg picks the alg label to advertise on the published JWK.
// A non-empty explicit input is validated against the package
// allow-list, against the key family (RSA-OAEP-* requires RSA, ECDH-ES*
// requires ECDSA), and against policy. The empty input infers a label
// from the family: def when the deployment still permits it, otherwise
// the first family alg that survives the narrowing.
//
// The published `alg` is metadata a relying party encrypts by, so it
// MUST name something [jose.Decrypt] would actually accept for this key
// — otherwise an RP that trusts the JWK over the discovery document is
// locked out permanently with no diagnosable cause. Two outcomes follow
// when nothing survives:
//
//   - The narrowing is non-empty but excludes this key's whole family.
//     Two settings the operator chose contradict each other and the key
//     can never decrypt anything, so construction fails.
//   - The narrowing is empty, i.e. the operator switched JWE
//     negotiation off wholesale while still publishing the keyset. That
//     posture is deliberate, so the key is published with no `alg`
//     member (RFC 7517 §4.4 makes it OPTIONAL) rather than with a label
//     that would be false.
func chooseEncAlg(
	pub crypto.PublicKey,
	explicit string,
	def jose.JWEAlg,
	family string,
	policy jose.JWEPolicy,
) (crypto.PublicKey, string, error) {
	if explicit != "" {
		parsed, ok := jose.ParseJWEAlg(explicit)
		if !ok {
			return nil, "", fmt.Errorf("alg %q is not in the JWE allow-list", explicit)
		}
		if !algMatchesKeyFamily(parsed, family) {
			return nil, "", fmt.Errorf("alg %q is not compatible with %s key", explicit, family)
		}
		if !policy.AllowsAlg(parsed) {
			return nil, "", fmt.Errorf("alg %q is excluded by the deployment's JWE alg narrowing", explicit)
		}
		return pub, parsed.String(), nil
	}
	if policy.AllowsAlg(def) {
		return pub, def.String(), nil
	}
	for _, alg := range jose.AllowedJWEAlgs() {
		if algMatchesKeyFamily(alg, family) && policy.AllowsAlg(alg) {
			return pub, alg.String(), nil
		}
	}
	if len(policy.Algs) == 0 {
		return pub, "", nil
	}
	return nil, "", fmt.Errorf(
		"no JWE alg for a %s key survives the deployment's JWE alg narrowing, so the OP would "+
			"publish an encryption key it always refuses to decrypt with", family,
	)
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

// WithContext returns a shallow copy of the set whose retired-kid
// notifications carry ctx. It implements
// [jose.ContextualEncryptionKeyResolver] so a decryption caller
// holding a request context can pin it onto the resolver before handing
// the resolver to [jose.Decrypt] / [jose.DecryptChain],
// whose signatures have no context to thread.
//
// Without the pin the retired-kid audit event reaches the embedder's
// sink with no request correlation, which is the difference between
// "a retired kid was presented" and "a retired kid was presented by
// this caller on this request". Every other aspect of the returned set
// — entries, clock, JWKS view, JWE policy — is shared with the
// receiver, so the copy is as immutable and as concurrency-safe as the
// original.
func (s *EncryptionSet) WithContext(ctx context.Context) jose.EncryptionKeyResolver {
	scoped := *s
	scoped.ctx = ctx
	return &scoped
}

// observerContext returns the context retired-kid notifications ride
// on. A set that was never passed through [WithContext] has none, so
// the notification still fires — silencing the audit event because a
// caller forgot to pin a context would trade an observability gap for
// a security-signal gap.
func (s *EncryptionSet) observerContext() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

// Resolve returns the private key whose kid matches keyID. The
// boolean is false when no entry matches OR when the matching entry
// has retired per its [EncryptionEntry.NotAfter] (the same
// observer-fed retirement gate the signing [Set.Find] uses).
//
// The retired-kid notification carries the context [WithContext]
// pinned onto the set, because [jose.EncryptionKeyResolver]
// gives Resolve no context parameter of its own.
//
// Decrypt callers MUST treat ok=false as a hard kid-unknown signal
// and MUST NOT fall back to trial decryption when kid is present —
// see [jose.Decrypt] for the rationale.
func (s *EncryptionSet) Resolve(keyID string) (any, bool) {
	for _, e := range s.entries {
		if e.KeyID != keyID {
			continue
		}
		if !e.NotAfter.IsZero() {
			now := s.nowOrSystem()
			if !now.Before(e.NotAfter) {
				if s.observer != nil {
					s.observer(s.observerContext(), keyID)
				}
				return nil, false
			}
		}
		return e.PrivateKey, true
	}
	return nil, false
}

// All returns every live private key in rotation order (as the
// embedder supplied them). Used by [jose.Decrypt] for the
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

// JWKS returns the public JWKs view of the [EncryptionSet]. Every live
// entry is published with use=enc. Entries at or past NotAfter are omitted,
// matching [Resolve] and [All]: advertising an encryption key after the OP
// has stopped decrypting for it would direct RPs to an unusable recipient.
//
// The returned value is a shallow copy: the slice header is fresh
// but the keys are shared. Callers MUST NOT mutate the returned
// [josev4.JSONWebKey] values.
func (s *EncryptionSet) JWKS() josev4.JSONWebKeySet {
	now := s.nowOrSystem()
	out := josev4.JSONWebKeySet{Keys: make([]josev4.JSONWebKey, 0, len(s.jwks.Keys))}
	for i, entry := range s.entries {
		if !entry.NotAfter.IsZero() && !now.Before(entry.NotAfter) {
			continue
		}
		out.Keys = append(out.Keys, s.jwks.Keys[i])
	}
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

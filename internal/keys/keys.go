package keys

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/timex"
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

	// Signer is the private key. The library signs with ES256 and only
	// ES256; non-P-256 keys are rejected at construction time.
	Signer crypto.Signer

	// NotAfter is the wall-clock instant after which this entry MUST NOT
	// verify a presented JWS. The zero value (the default) means the
	// entry never retires and continues to verify until removed from the
	// keyset. A non-zero value is the rotation deadline: once the OP's
	// configured clock advances past it, [Set.Find] rejects lookups for
	// the kid even though the entry is still present in JWKS for grace.
	//
	// The field exists so an embedder can stage a key rotation that
	// retains a retiring kid in JWKS for RP cache warmth while the OP
	// itself stops trusting the kid for verification — the rotation
	// graceful-window is asymmetric on purpose so a forged token that
	// reuses an old kid after the deadline cannot ride past [Set.Find].
	NotAfter time.Time
}

// RetiredKidObserver is the seam [Set.Find] and [EncryptionSet.Resolve]
// notify when they reject a presented kid because the matching
// retirement deadline has elapsed. The observer is invoked with the
// requested kid value; a nil observer silences the notification (the
// rejection still fires). The hook is configured at construction time
// through [WithRetiredKidObserver] so every verifier path that consults
// the keyset surfaces the audit event without threading the emitter
// through individual call sites.
//
// ctx is the context of the request whose JWS presented the retired
// kid. It carries the correlation an operator needs to answer "who
// presented it, on which request" — the notification is otherwise a
// bare kid with no way back to the caller. Verification paths that
// hold a request context MUST pass it; see [Set.Find] and
// [EncryptionSet.WithContext].
//
// The observer MUST NOT block on I/O (e.g. a synchronous network audit
// sink) — it runs on the request hot path and a slow handler would
// amplify a hostile-traffic burst into a verifier latency spike.
type RetiredKidObserver func(ctx context.Context, keyID string)

// SetOption customises a [Set] at construction. Apply via [NewSet] or
// the variadic options on the underlying constructor; later values
// override earlier ones for the same field.
type SetOption func(*setConfig)

// setConfig is the internal mutable shape options write into. Kept
// unexported so the option surface stays the only knob.
type setConfig struct {
	now      func() time.Time
	observer RetiredKidObserver
	jwe      jose.JWEPolicy
}

// WithClock pins the wall-clock seam [Set.Find] consults when comparing
// an [Entry.NotAfter] against "now". A nil function (or omitting the
// option) falls back to [timex.SystemClock]; tests SHOULD inject a
// deterministic clock so retirement boundaries can be exercised
// without sleeping.
func WithClock(now func() time.Time) SetOption {
	return func(c *setConfig) {
		if now != nil {
			c.now = now
		}
	}
}

// WithRetiredKidObserver registers the [RetiredKidObserver] notified
// when [Set.Find] or [EncryptionSet.Resolve] rejects a retired kid. A
// nil observer (or omitting the option) leaves the notification path
// silent — the rejection still happens, but no audit event fires.
func WithRetiredKidObserver(obs RetiredKidObserver) SetOption {
	return func(c *setConfig) {
		c.observer = obs
	}
}

// WithJWEPolicy pins the deployment's JWE narrowing onto an
// [EncryptionSet] so inbound decryption enforces the same alg / enc
// subset the discovery document advertises. The zero policy leaves the
// [internal/jose] allow-list in force.
//
// Only [NewEncryptionSet] reads the value: a signing [Set] has no JWE
// surface, so [NewSet] accepts the option and ignores it rather than
// growing a second option type for one field.
func WithJWEPolicy(p jose.JWEPolicy) SetOption {
	return func(c *setConfig) {
		c.jwe = p
	}
}

// Set is the validated, immutable collection of signing keys the OP uses.
// The first entry is the active signer; subsequent entries are retiring
// keys still advertised in JWKS so RPs can verify recently-issued tokens.
type Set struct {
	entries  []Entry
	jwks     josev4.JSONWebKeySet
	now      func() time.Time
	observer RetiredKidObserver
}

// NewSet validates entries and builds the runtime [Set]. It returns an
// error wrapping [ErrInvalidKey] when any entry is missing fields, has a
// duplicate KeyID, or carries a non-ES256 key shape. The caller (op.New)
// has already performed the same checks; we re-validate here so that
// internal callers cannot bypass the policy by constructing a Set
// directly.
//
// Variadic [SetOption] values customise the wall-clock seam and the
// retired-kid observer; defaults are [timex.SystemClock] and a no-op
// observer respectively, so a Set built without options behaves
// identically to a pre-rotation-aware Set apart from honouring
// [Entry.NotAfter] when present.
func NewSet(entries []Entry, opts ...SetOption) (*Set, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: empty keyset", ErrInvalidKey)
	}
	cfg := setConfig{now: timex.SystemClock.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
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
		// Delegate the alg/kty/crv triple to the canonical
		// [jose.KeyShape] matrix, then enforce the ES256-only
		// constraint on top. The narrower constraint is intentional:
		// every downstream package (jarm / dpop / tokens) hard-codes
		// ES256 today, so admitting another shape here would cause a
		// silent mismatch when those packages run against the new key.
		pub := e.Signer.Public()
		alg, _, _, shapeOK := jose.KeyShape(pub)
		if !shapeOK || alg != "ES256" {
			return nil, fmt.Errorf("%w: entry %q is not ECDSA P-256", ErrInvalidKey, e.KeyID)
		}
		jwks.Keys = append(jwks.Keys, josev4.JSONWebKey{
			Key:       pub,
			KeyID:     e.KeyID,
			Algorithm: alg,
			Use:       "sig",
		})
		out[i] = e
	}
	return &Set{entries: out, jwks: jwks, now: cfg.now, observer: cfg.observer}, nil
}

// Active returns the signing key the OP uses for newly-issued tokens.
// Callers MUST treat the returned [Entry] as read-only.
//
// The active signer's [Entry.NotAfter] is intentionally not consulted
// here. Active selection is rotation-supervisor-driven: the operator
// rebuilds the [Set] with a fresh first entry rather than relying on a
// runtime check at signing time, because a signer that "expired"
// mid-flight would surface as an issuance crash with no fallback. The
// retirement gate applies on verification ([Set.Find]) only, where the
// failure mode is a clean rejection.
func (s *Set) Active() Entry { return s.entries[0] }

// Find returns the [Entry] whose KeyID matches keyID. The boolean is
// false when no entry matches OR when the matching entry has retired
// per its [Entry.NotAfter]. Verification paths use this to look up the
// public key for a JWS "kid" header; callers MUST treat a false return
// as an unknown-kid signal and MUST NOT fall back to the active key —
// doing so would defeat key rotation auditing.
//
// ctx is the context of the request that presented the kid. It is used
// only to correlate the retired-kid notification described below; the
// lookup itself does no I/O and does not observe cancellation. Callers
// MUST pass the request context rather than a detached one so the audit
// event reaches the sink with the request's correlation attached.
//
// Retirement gate: an entry whose [Entry.NotAfter] is non-zero
// and lies on or before the [Set]'s configured clock reading is
// rejected as if the kid were unknown. The configured
// [RetiredKidObserver] is notified with ctx so the audit pipeline can
// fire [op.AuditKeyRetiredKidPresented] with the rejected kid; the
// notification fires once per call.
//
// The retirement comparison uses `!After(now)` (i.e., now >= NotAfter)
// so a deadline of exactly "now" rejects, matching the intuitive
// semantics: a kid scheduled to retire at T MUST NOT verify a JWS
// presented at T.
func (s *Set) Find(ctx context.Context, keyID string) (Entry, bool) {
	for _, e := range s.entries {
		if e.KeyID != keyID {
			continue
		}
		if !e.NotAfter.IsZero() {
			now := s.nowOrSystem()
			if !now.Before(e.NotAfter) {
				if s.observer != nil {
					s.observer(ctx, keyID)
				}
				return Entry{}, false
			}
		}
		return e, true
	}
	return Entry{}, false
}

// nowOrSystem returns the wall-clock reading the retirement gate uses.
// A nil [Set.now] (defensively possible if a caller built the struct
// outside [NewSet]) collapses onto [timex.SystemClock], so the gate
// cannot accidentally accept a retired kid because the clock seam was
// missed.
func (s *Set) nowOrSystem() time.Time {
	if s.now == nil {
		return timex.SystemClock.Now()
	}
	return s.now()
}

// JWKS returns the public JWKS view of the [Set]. The returned value is a
// shallow copy: the slice header is fresh, but the entries are shared.
// Callers MUST NOT mutate the returned [josev4.JSONWebKey] values.
//
// Retired entries (those whose [Entry.NotAfter] has elapsed) remain in
// the JWKS view: the JWKS endpoint is the public RP-facing rotation
// surface and pulling a kid out before the cache TTL expires would
// strand RPs that have not yet observed the rotation. The asymmetry
// between [Set.Find] (rejects retired kids on verification) and
// [Set.JWKS] (still advertises them) is the rotation-grace pattern
// described in RFC 7517 §4.5: keep the public key visible long enough
// for caches to refresh, while the OP itself stops trusting it.
func (s *Set) JWKS() josev4.JSONWebKeySet {
	out := josev4.JSONWebKeySet{Keys: make([]josev4.JSONWebKey, len(s.jwks.Keys))}
	copy(out.Keys, s.jwks.Keys)
	return out
}

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

	// Signer is the private key: ECDSA P-256 or RSA of at least 2048 bits.
	// [NewSet] requires the active entry to match the OP's signing alg.
	Signer crypto.Signer

	// Alg is the one JWS alg this key is used with ("ES256" or "RS256").
	// [NewSet] overwrites it from the key shape, so a caller-supplied
	// value never survives into a [Set].
	Alg string

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

// AcceptsAlg reports whether a JWS whose "alg" header is alg may be
// verified with this entry. A key is bound to exactly one alg
// (RFC 8725 §3.1), so the comparison is exact.
func (e Entry) AcceptsAlg(alg string) bool { return alg == e.Alg }

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
	now        func() time.Time
	observer   RetiredKidObserver
	jwe        jose.JWEPolicy
	signingAlg jose.Algorithm
}

// newSetConfig applies opts over the defaults (system clock, no observer,
// ES256 signing).
func newSetConfig(opts []SetOption) setConfig {
	cfg := setConfig{now: timex.SystemClock.Now, signingAlg: jose.AlgES256}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
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
// internal/jose allow-list in force.
//
// Only [NewEncryptionSet] reads the value: a signing [Set] has no JWE
// surface, so [NewSet] accepts the option and ignores it rather than
// growing a second option type for one field.
func WithJWEPolicy(p jose.JWEPolicy) SetOption {
	return func(c *setConfig) {
		c.jwe = p
	}
}

// WithSigningAlg pins the JWS alg the OP issues with; [NewSet] requires
// the active entry's key shape to match it. The default is ES256.
//
// Only [NewSet] reads the value; [NewEncryptionSet] accepts the option
// and ignores it, the mirror of [WithJWEPolicy].
func WithSigningAlg(alg jose.Algorithm) SetOption {
	return func(c *setConfig) {
		c.signingAlg = alg
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
// error wrapping [ErrInvalidKey] when any entry is missing fields or has
// a duplicate KeyID, when the active entry (entries[0]) does not match
// the signing alg set by [WithSigningAlg], or when any other entry is
// neither an ES256 nor an RS256 key. Each entry's [Entry.Alg] is set
// from its key shape. The caller (op.New) has already performed the
// same checks, including the NotAfter requirement on entries of the
// other key type; we re-validate the shapes here so that internal
// callers cannot bypass the policy by constructing a Set directly.
//
// The remaining [SetOption] values customise the wall-clock seam and the
// retired-kid observer; defaults are [timex.SystemClock] and a no-op
// observer.
func NewSet(entries []Entry, opts ...SetOption) (*Set, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: empty keyset", ErrInvalidKey)
	}
	cfg := newSetConfig(opts)
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
		alg, err := entryAlg(e, i == 0, cfg.signingAlg)
		if err != nil {
			return nil, err
		}
		pub := e.Signer.Public()
		jwks.Keys = append(jwks.Keys, josev4.JSONWebKey{
			Key:       pub,
			KeyID:     e.KeyID,
			Algorithm: alg,
			Use:       "sig",
		})
		e.Alg = alg
		out[i] = e
	}
	return &Set{entries: out, jwks: jwks, now: cfg.now, observer: cfg.observer}, nil
}

// entryAlg returns the algorithm e's key shape signs with. The active
// entry must match signingAlg; any other entry must be ES256 or RS256.
func entryAlg(e Entry, active bool, signingAlg jose.Algorithm) (string, error) {
	if e.Signer == nil {
		return "", fmt.Errorf("%w: entry %q has nil Signer", ErrInvalidKey, e.KeyID)
	}
	alg, _, _, shapeOK := jose.KeyShape(e.Signer.Public())
	if active && (!shapeOK || alg != string(signingAlg)) {
		return "", fmt.Errorf("%w: entry %q is not a %s key", ErrInvalidKey, e.KeyID, signingAlg)
	}
	if !shapeOK || (alg != string(jose.AlgES256) && alg != string(jose.AlgRS256)) {
		return "", fmt.Errorf("%w: entry %q has an unsupported key shape", ErrInvalidKey, e.KeyID)
	}
	return alg, nil
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
// fire op/audit.KeyRetiredKidPresented with the rejected kid; the
// notification fires once per call.
//
// The retirement comparison uses `!After(now)` (i.e., now >= NotAfter)
// so a deadline of exactly "now" rejects, matching the intuitive
// semantics: a kid scheduled to retire at T MUST NOT verify a JWS
// presented at T.
func (s *Set) Find(ctx context.Context, keyID string) (Entry, bool) {
	return findLive(s.entries, keyID, func(e Entry) (string, time.Time) { return e.KeyID, e.NotAfter },
		s.now, s.observer, ctx)
}

// findLive returns the entry whose id matches keyID, unless it has
// retired per its NotAfter; a retired match notifies the observer with ctx
// and is reported as absent.
func findLive[E any](
	entries []E,
	keyID string,
	idAndNotAfter func(E) (string, time.Time),
	now func() time.Time,
	observer RetiredKidObserver,
	ctx context.Context,
) (E, bool) {
	var zero E
	for _, e := range entries {
		id, notAfter := idAndNotAfter(e)
		if id != keyID {
			continue
		}
		if retiredBy(now(), notAfter) {
			if observer != nil {
				observer(ctx, keyID)
			}
			return zero, false
		}
		return e, true
	}
	return zero, false
}

// retiredBy reports whether an entry whose NotAfter is notAfter has
// retired at now. A zero notAfter never retires; otherwise the entry is
// retired once now >= notAfter, so a kid scheduled to retire at T does
// not verify anything presented at T.
func retiredBy(now, notAfter time.Time) bool {
	return !notAfter.IsZero() && !now.Before(notAfter)
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

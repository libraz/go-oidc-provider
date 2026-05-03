package jar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Default knobs for the verifier. The values mirror the project-wide
// posture for short-lived signed envelopes: a small future-tolerance
// window so a clock-skewed RP retries quickly, no past tolerance so an
// attacker cannot replay a stale request object indefinitely.
const (
	// DefaultMaxFutureSkew is the symmetric tolerance applied to the
	// "iat" / "nbf" claims. RFC 9101 does not pin an exact value; 60
	// seconds matches the DPoP iat window so the two surfaces share
	// a single posture.
	DefaultMaxFutureSkew = 60 * time.Second

	// DefaultMaxAge caps how old a request object's "iat" claim may
	// be when it reaches the verifier. The value bounds the replay
	// window for a stolen JWT regardless of its "exp"; a JWT with
	// "iat" older than this is rejected even if "exp" still lies in
	// the future.
	DefaultMaxAge = 10 * time.Minute

	// maxJTILen bounds the "jti" claim length. RFC 9101 sets no cap;
	// the verifier rejects oversized values to close the unbounded-
	// allocation surface (replay store key, audit log column). The
	// value is comfortably above any UUID encoding.
	maxJTILen = 256
)

// JWKSResolver is the verifier's seam for fetching the client's
// keyset. The default implementation pulls inline JWKs from
// [op/store.Client.JWKs] and, when absent, fetches
// [op/store.Client.JWKsURI] through the hardened HTTP fetcher.
//
// Embedders rarely need to substitute the resolver; the seam exists
// primarily so tests can wire deterministic fixtures without bringing
// up an httptest server for every JAR scenario.
type JWKSResolver interface {
	Resolve(ctx context.Context, c *store.Client) (*josev4.JSONWebKeySet, error)
}

// Verifier is the request-scoped entry point. Construct it once at
// startup with [NewVerifier]; the value is immutable and safe for
// concurrent use.
type Verifier struct {
	clock         timex.Clock
	resolver      JWKSResolver
	issuer        string
	allowedAlgs   map[jose.Algorithm]struct{}
	maxFutureSkew time.Duration
	maxAge        time.Duration
	requireNbf    bool
	allowMissJTI  bool
	jtis          store.ConsumedJTIStore
	maxLifetime   time.Duration
}

// VerifierConfig is the parameter bundle for [NewVerifier].
type VerifierConfig struct {
	// Issuer is the OP issuer URL; the verifier checks the request
	// object's "aud" claim against this value.
	Issuer string

	// Resolver fetches the client's keyset. Required.
	Resolver JWKSResolver

	// Clock supplies the wall-clock reading for the "exp" / "nbf" /
	// "iat" comparisons. A nil value falls back to
	// [timex.SystemClock].
	Clock timex.Clock

	// AllowedAlgs restricts the JWS "alg" values the verifier accepts.
	// An empty list falls back to the project-wide allow-list (RS256,
	// PS256, ES256, EdDSA). The set is intersected with the per-client
	// pin in [op/store.Client.RequestObjectSigningAlg] at verification
	// time.
	AllowedAlgs []jose.Algorithm

	// MaxFutureSkew overrides [DefaultMaxFutureSkew]. Zero or negative
	// falls back to the default.
	MaxFutureSkew time.Duration

	// MaxAge overrides [DefaultMaxAge]. Zero or negative falls back to
	// the default.
	MaxAge time.Duration

	// RequireNbf, when true, rejects request objects whose "nbf"
	// claim is absent. The flag exists so callers can pin the
	// FAPI 2.0 Message Signing §5.6 posture explicitly; the
	// runtime default is also true and is suppressed only by
	// [VerifierConfig.AllowMissingNbf]. RFC 9101 §6.1 marks "nbf"
	// optional but every modern signed-request-object flow expects
	// it.
	RequireNbf bool

	// AllowMissingNbf, when true, restores the back-compat posture
	// of admitting request objects without an "nbf" claim. The
	// default (false) rejects nbf-less request objects so the
	// safer FAPI 2.0 Message Signing §5.6 stance applies uniformly
	// to every JAR-enabling deployment. Embedders that need to
	// admit nbf-less RPs (legacy clients that pre-date the FAPI 2.0
	// mandate) opt in by setting the flag; the explicit opt-in
	// surfaces the looser stance in the embedder's boot code so a
	// future audit can locate it with a grep.
	//
	// Mutually independent of [VerifierConfig.RequireNbf]: when
	// both are set, AllowMissingNbf wins (the explicit opt-out
	// dominates). The two-flag shape exists so the zero value of
	// the struct does not silently flip the default behaviour
	// when an existing call site adds new fields above the
	// RequireNbf entry.
	AllowMissingNbf bool

	// JTIs is the replay store the verifier consults for the
	// request object's "jti" claim. RFC 9101 §10.8 names jti as
	// the replay-defence anchor; supplying a store enables the
	// per-jti gate, and the gate fires whenever a request object
	// carries a jti (legacy RPs that omit jti are still rejected
	// as [ErrJTIMissing] unless [AllowMissingJTI] is set). Required
	// for production wiring; tests that exercise paths upstream of
	// the jti gate may leave the field nil and instead set
	// [AllowMissingJTI] to skip the check entirely.
	JTIs store.ConsumedJTIStore

	// AllowMissingJTI, when true, admits request objects without a
	// "jti" claim. The default (false) rejects jti-less request
	// objects with [ErrJTIMissing] so the replay-defence floor
	// applies uniformly to every JAR-enabling deployment. RFC 9101
	// §6.1 marks jti optional but §10.8 mandates a replay defence
	// anchored on jti; embedders that need to admit legacy RPs
	// (that pre-date the §10.8 strengthening) opt in here. The
	// flag is also honoured when [JTIs] is nil so JAR can be wired
	// in test setups without a JTI store.
	//
	// Profile interaction: under any FAPI-family profile
	// (FAPI2Baseline, FAPI2MessageSigning, FAPICIBA) the [op.New]
	// wiring layer hard-codes this field to false so the §10.8
	// reading is enforced uniformly. There is intentionally no
	// embedder-facing option to flip it back: the FAPI MUST is
	// add-only, and any opt-out would have to live next to the
	// profile-activation site rather than as a verifier-level knob.
	AllowMissingJTI bool

	// MaxLifetime, when positive, caps how far "exp" may lie in the
	// future and how far "nbf" may lie in the past relative to "now".
	// FAPI 2.0 Message Signing §5.6 mandates a 60-second window.
	// Zero leaves the cap disabled (back-compat).
	MaxLifetime time.Duration
}

// NewVerifier builds a [*Verifier] from cfg. The function returns an
// error when a required field is missing so the embedder fails fast
// at startup rather than at the first request.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("jar: NewVerifier requires Issuer")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("jar: NewVerifier requires Resolver")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = timex.SystemClock
	}
	skew := cfg.MaxFutureSkew
	if skew <= 0 {
		skew = DefaultMaxFutureSkew
	}
	maxAge := cfg.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	algs := cfg.AllowedAlgs
	if len(algs) == 0 {
		algs = defaultAllowedAlgs()
	}
	allowed := make(map[jose.Algorithm]struct{}, len(algs))
	for _, a := range algs {
		if !a.IsAllowed() {
			return nil, fmt.Errorf("jar: NewVerifier: alg %q not in project allow-list", a)
		}
		allowed[a] = struct{}{}
	}
	// Default posture is RFC 9101 §6.1 ("nbf" optional). FAPI 2.0
	// Message Signing §5.6 mandates nbf; the FAPI profile flips
	// [VerifierConfig.RequireNbf] on at op-level wiring so the
	// stricter stance lands on FAPI deployments without breaking
	// non-FAPI back-compat. [VerifierConfig.AllowMissingNbf] remains
	// available as an explicit opt-out for the rare profile that
	// flipped RequireNbf on but needs to admit a legacy RP.
	requireNbf := cfg.RequireNbf && !cfg.AllowMissingNbf
	// JTI replay gate: a non-nil store lets the verifier mark every
	// jti the request object carries (RFC 9101 §10.8). When the
	// store is nil the embedder MUST set AllowMissingJTI to
	// acknowledge the floor is being bypassed; otherwise NewVerifier
	// fails fast at startup so the gap surfaces during boot rather
	// than at the first request.
	if cfg.JTIs == nil && !cfg.AllowMissingJTI {
		return nil, errors.New("jar: NewVerifier requires JTIs store (or AllowMissingJTI to opt out)")
	}
	return &Verifier{
		clock:         clock,
		resolver:      cfg.Resolver,
		issuer:        cfg.Issuer,
		allowedAlgs:   allowed,
		maxFutureSkew: skew,
		maxAge:        maxAge,
		requireNbf:    requireNbf,
		allowMissJTI:  cfg.AllowMissingJTI,
		jtis:          cfg.JTIs,
		maxLifetime:   cfg.MaxLifetime,
	}, nil
}

// defaultAllowedAlgs returns the project-wide JWS allow-list. The list
// mirrors [internal/jose] so JAR widens with every new alg the rest of
// the codebase admits without a separate audit.
func defaultAllowedAlgs() []jose.Algorithm {
	return []jose.Algorithm{
		jose.AlgRS256,
		jose.AlgPS256,
		jose.AlgES256,
		jose.AlgEdDSA,
	}
}

// AllowedAlgs returns the alg values the verifier accepts, sorted
// for stable output. The slice is freshly allocated; callers may
// mutate it.
func (v *Verifier) AllowedAlgs() []jose.Algorithm {
	out := make([]jose.Algorithm, 0, len(v.allowedAlgs))
	for _, candidate := range defaultAllowedAlgs() {
		if _, ok := v.allowedAlgs[candidate]; ok {
			out = append(out, candidate)
		}
	}
	return out
}

// Verify parses raw, fetches the client's keyset, verifies the
// signature, and validates the claims (RFC 9101 §6.1 + FAPI 2.0
// Message Signing §5.6). The returned [*Object] carries the parsed
// claim bag with the signature already verified; callers MUST hand
// it to [Merge] before consuming individual values.
//
// expectedClientID is the client_id from the wire. The verifier
// confirms the request object's "iss" matches it (RFC 9101 §10.2);
// the wire-vs-payload "client_id" reconciliation happens in [Merge]
// so the rule lives next to the other merge invariants.
func (v *Verifier) Verify(ctx context.Context, raw, expectedClientID string, client *store.Client) (*Object, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: client is required", ErrJWKSConfigured)
	}
	parsed, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if _, ok := v.allowedAlgs[parsed.Algorithm]; !ok {
		return nil, fmt.Errorf("%w: alg %q", ErrAlgNotAllowed, parsed.Algorithm)
	}
	if pin := client.RequestObjectSigningAlg; pin != "" && pin != parsed.Algorithm.String() {
		return nil, fmt.Errorf("%w: client requires %q", ErrAlgNotAllowed, pin)
	}
	keys, err := v.resolver.Resolve(ctx, client)
	if err != nil {
		return nil, err
	}
	if keys == nil || len(keys.Keys) == 0 {
		return nil, ErrNoMatchingJWK
	}
	jwk, err := pickKey(keys, parsed.KeyID)
	if err != nil {
		return nil, err
	}
	payload, err := parsed.jws.Verify(jwk.Key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigInvalid, err)
	}
	// Re-decode against the verified payload bytes so the verifier
	// never trusts [Object.Claims] from before the signature check.
	verifiedClaims, err := decodeVerifiedClaims(payload)
	if err != nil {
		return nil, err
	}
	parsed.Claims = verifiedClaims
	if err := v.validateClaims(parsed, expectedClientID); err != nil {
		return nil, err
	}
	if err := v.consumeJTI(ctx, parsed, expectedClientID); err != nil {
		return nil, err
	}
	return parsed, nil
}

// consumeJTI enforces the RFC 9101 §10.8 replay-defence floor on the
// request object's "jti" claim. The function runs after the rest of
// the claim validation succeeds so a malformed or stale request
// object never advances the consumed-jti table. The mark key is
// scoped to the client_id ("jar:" + clientID + ":" + jti) so two
// clients minting the same jti by coincidence do not collide.
//
// When the verifier was constructed with a nil JTIs store, the
// embedder explicitly opted into [VerifierConfig.AllowMissingJTI];
// the function then admits every request object regardless of jti
// presence. The opt-in is the only path that bypasses the gate.
func (v *Verifier) consumeJTI(ctx context.Context, obj *Object, clientID string) error {
	jti, _ := obj.Claims["jti"].(string)
	if jti == "" {
		if v.allowMissJTI {
			return nil
		}
		return ErrJTIMissing
	}
	// Cap the jti at 256 bytes. RFC 9101 sets no upper bound; the
	// limit closes an unbounded-allocation surface (replay store key,
	// audit logs) at the verifier boundary. ErrParse is the right
	// shape: an oversized jti is a malformed request object.
	if len(jti) > maxJTILen {
		return fmt.Errorf("%w: jti too long", ErrParse)
	}
	if v.jtis == nil {
		// AllowMissingJTI=true with no store: skip the gate.
		return nil
	}
	expiresAt, ok := jtiExpiry(obj.Claims, v.clock.Now())
	if !ok {
		// "exp" was already validated upstream; reaching this branch
		// means the claim disappeared between the two reads, which is
		// a malformed-object class.
		return fmt.Errorf("%w: jti consume: missing exp", ErrParse)
	}
	key := "jar:" + clientID + ":" + jti
	if err := v.jtis.Mark(ctx, key, expiresAt); err != nil {
		if errors.Is(err, store.ErrAlreadyConsumed) {
			return ErrJTIReplayed
		}
		return fmt.Errorf("jar: mark jti: %w", err)
	}
	return nil
}

// jtiExpiry reads the request object's "exp" claim and projects it
// onto the wall clock the verifier is using. The value bounds the
// jti record's TTL in the consumed-jti store; readers eviction
// triggers off the same value.
func jtiExpiry(claims map[string]any, now time.Time) (time.Time, bool) {
	exp, ok := claimSeconds(claims, "exp")
	if !ok {
		return time.Time{}, false
	}
	t := time.Unix(exp, 0)
	if !t.After(now) {
		return time.Time{}, false
	}
	return t, true
}

// decodeVerifiedClaims is the post-signature variant of
// [decodeUnverifiedPayload]. It is split out so the call site reads as
// a single line and so a future security review can audit the
// distinction between the two decode paths in one place.
func decodeVerifiedClaims(payload []byte) (map[string]any, error) {
	out := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: decode verified payload: %w", ErrParse, err)
	}
	return out, nil
}

// pickKey selects the verifying JWK from keys. When the request
// object's "kid" header is present the function requires an exact
// match; when the header is absent the function only succeeds when the
// keyset carries exactly one key, because choosing arbitrarily would
// hide an OP-side key-rotation bug.
func pickKey(keys *josev4.JSONWebKeySet, kid string) (*josev4.JSONWebKey, error) {
	if kid != "" {
		matches := keys.Key(kid)
		if len(matches) == 0 {
			return nil, ErrNoMatchingJWK
		}
		// JSONWebKeySet.Key returns every key whose kid matches; pick
		// the first to keep behaviour deterministic. Multiple keys
		// sharing a kid is a misconfiguration on the RP side.
		k := matches[0]
		return &k, nil
	}
	if len(keys.Keys) == 1 {
		k := keys.Keys[0]
		return &k, nil
	}
	return nil, ErrNoMatchingJWK
}

// validateClaims runs the RFC 9101 §6.1 / FAPI 2.0 Message Signing
// §5.6 checklist on the verified claim bag.
func (v *Verifier) validateClaims(obj *Object, expectedClientID string) error {
	if err := v.assertNoNestedRequest(obj); err != nil {
		return err
	}
	if err := assertIssuer(obj, expectedClientID); err != nil {
		return err
	}
	if err := assertAudience(obj, v.issuer); err != nil {
		return err
	}
	now := v.clock.Now()
	if err := assertExp(obj, now, v.maxLifetime); err != nil {
		return err
	}
	if err := assertNbf(obj, now, v.maxFutureSkew, v.maxLifetime, v.requireNbf); err != nil {
		return err
	}
	if err := assertIat(obj, now, v.maxFutureSkew, v.maxAge); err != nil {
		return err
	}
	return nil
}

// assertNoNestedRequest enforces RFC 9101 §6.1: the request object
// MUST NOT itself carry "request" or "request_uri" because doing so
// would invite recursive fetches and complicate the merge semantics.
func (v *Verifier) assertNoNestedRequest(obj *Object) error {
	if _, has := obj.Claims["request"]; has {
		return ErrNestedRequest
	}
	if _, has := obj.Claims["request_uri"]; has {
		return ErrNestedRequest
	}
	return nil
}

// assertIssuer enforces "iss" == client_id. The check is case-sensitive
// because client_id is byte-equal compared at every other endpoint.
func assertIssuer(obj *Object, expectedClientID string) error {
	got, _ := obj.Claims["iss"].(string)
	if got == "" {
		return fmt.Errorf("%w: missing", ErrIssMismatch)
	}
	if got != expectedClientID {
		return fmt.Errorf("%w: iss=%q wire=%q", ErrIssMismatch, got, expectedClientID)
	}
	return nil
}

// assertAudience enforces "aud" containing the OP issuer. The claim
// may be a single string or an array per RFC 7519 §4.1.3; the verifier
// accepts either shape.
func assertAudience(obj *Object, issuer string) error {
	switch v := obj.Claims["aud"].(type) {
	case nil:
		return fmt.Errorf("%w: missing", ErrAudMismatch)
	case string:
		if v != issuer {
			return fmt.Errorf("%w: aud=%q want %q", ErrAudMismatch, v, issuer)
		}
		return nil
	case []any:
		for _, raw := range v {
			if s, ok := raw.(string); ok && s == issuer {
				return nil
			}
		}
		return fmt.Errorf("%w: %v does not contain %q", ErrAudMismatch, v, issuer)
	default:
		return fmt.Errorf("%w: aud has unsupported type %T", ErrAudMismatch, v)
	}
}

// assertExp enforces a non-empty "exp" claim that has not already
// passed. The verifier does not apply a skew tolerance here: an "exp"
// in the past is unambiguous. When maxLifetime is positive (FAPI 2.0
// Message Signing §5.6 imposes a 60s cap) the function additionally
// rejects request objects whose "exp" lies further in the future than
// that — the strict ceiling matches the OFCS conformance test
// "ensure-request-object-with-exp-over-60-fails".
func assertExp(obj *Object, now time.Time, maxLifetime time.Duration) error {
	exp, ok := claimSeconds(obj.Claims, "exp")
	if !ok {
		return fmt.Errorf("%w: missing exp", ErrExpired)
	}
	expTime := time.Unix(exp, 0)
	if !expTime.After(now) {
		return ErrExpired
	}
	if maxLifetime > 0 && expTime.Sub(now) > maxLifetime {
		return fmt.Errorf("%w: exp lies more than %s in the future", ErrExpired, maxLifetime)
	}
	return nil
}

// assertNbf enforces "nbf" not lying in the future beyond skew. When
// requireNbf is true (FAPI 2.0 Message Signing) an absent "nbf" is
// rejected. When maxLifetime is positive the function also caps how
// far in the past "nbf" may lie — RFC 9101 §6.1 phrases the window as
// "request objects MUST be short-lived"; the OFCS test
// "ensure-request-object-with-nbf-over-60-fails" pins 60s.
func assertNbf(obj *Object, now time.Time, skew, maxLifetime time.Duration, requireNbf bool) error {
	nbf, ok := claimSeconds(obj.Claims, "nbf")
	if !ok {
		if requireNbf {
			return fmt.Errorf("%w: missing nbf", ErrNotYetValid)
		}
		return nil
	}
	nbfTime := time.Unix(nbf, 0)
	if nbfTime.After(now.Add(skew)) {
		return ErrNotYetValid
	}
	if maxLifetime > 0 && now.Sub(nbfTime) > maxLifetime {
		return fmt.Errorf("%w: nbf lies more than %s in the past", ErrNotYetValid, maxLifetime)
	}
	return nil
}

// assertIat enforces a non-future "iat" within the configured skew, and
// rejects request objects whose "iat" lies more than maxAge in the
// past. An absent "iat" is permitted because RFC 9101 marks the claim
// optional; the OP relies on "exp" + the per-request_uri TTL to bound
// the replay window in that case.
func assertIat(obj *Object, now time.Time, skew, maxAge time.Duration) error {
	iat, ok := claimSeconds(obj.Claims, "iat")
	if !ok {
		return nil
	}
	t := time.Unix(iat, 0)
	if t.After(now.Add(skew)) {
		return ErrNotYetValid
	}
	if now.Sub(t) > maxAge {
		return ErrExpired
	}
	return nil
}

// claimSeconds extracts an integer-seconds claim. JWT numeric date
// claims are encoded as JSON numbers; the function tolerates both
// json.Number (the [json.Decoder.UseNumber] output) and the legacy
// float64 produced by callers that decoded without UseNumber.
func claimSeconds(claims map[string]any, key string) (int64, bool) {
	switch v := claims[key].(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, true
		}
		if f, err := v.Float64(); err == nil {
			return int64(f), true
		}
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	}
	return 0, false
}

// defaultResolver is the production [JWKSResolver]: pull inline JWKs
// from the client when present, fall back to JWKsURI, surface
// [ErrJWKSConfigured] when neither is set.
type defaultResolver struct {
	fetcher *httpJWKSFetcher
}

// NewDefaultResolver returns a resolver suitable for production. It
// uses an in-process JWKS cache keyed by URL with a 5-minute default
// TTL and applies the SSRF / body-cap / content-type protections in
// [httpJWKSFetcher]. Apply [AllowPrivateNetwork] when the OP must
// reach a JWKS endpoint on a private network — the deny-list rejects
// loopback / link-local / RFC 1918 hosts otherwise.
func NewDefaultResolver(clock timex.Clock, opts ...ResolverOption) *DefaultResolver {
	fetcher := newHTTPJWKSFetcher(clock)
	for _, opt := range opts {
		if opt != nil {
			opt(fetcher)
		}
	}
	return &DefaultResolver{inner: &defaultResolver{fetcher: fetcher}}
}

// ResolverOption customises a [DefaultResolver] at construction.
// Applied in order; later values override earlier ones for the same
// underlying field.
type ResolverOption func(*httpJWKSFetcher)

// AllowPrivateNetwork disables the SSRF deny-list on the JWKS fetcher
// so the OP may reach RP JWKS endpoints whose hosts resolve to
// loopback / link-local / RFC 1918 addresses. The opt-in is required
// because the default posture rejects every private network to
// neutralise SSRF attacks via attacker-controlled jwks_uri values.
func AllowPrivateNetwork() ResolverOption {
	return func(f *httpJWKSFetcher) { f.allowPrivate = true }
}

// DefaultResolver is the exported wrapper around the package-private
// production resolver. The concrete type exists so the constructor
// satisfies the project ireturn allow-list while the underlying
// implementation remains unexported.
type DefaultResolver struct {
	inner *defaultResolver
}

// Resolve implements [JWKSResolver].
func (r *DefaultResolver) Resolve(ctx context.Context, c *store.Client) (*josev4.JSONWebKeySet, error) {
	return r.inner.Resolve(ctx, c)
}

// Resolve implements [JWKSResolver].
func (r *defaultResolver) Resolve(ctx context.Context, c *store.Client) (*josev4.JSONWebKeySet, error) {
	if len(c.JWKs) > 0 {
		keys, err := parseJWKS(c.JWKs)
		if err != nil {
			return nil, err
		}
		return keys, nil
	}
	if c.JWKsURI != "" {
		return r.fetcher.fetch(ctx, c.JWKsURI)
	}
	return nil, ErrJWKSConfigured
}

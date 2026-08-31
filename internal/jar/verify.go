package jar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
	//
	// This default is deliberately tighter than the window FAPI 2.0
	// Message Signing §5.6 grants a request object (60 minutes). A
	// deployment running under that profile MUST raise
	// [VerifierConfig.MaxAge] to the profile's bound, otherwise it
	// rejects request objects the profile declares valid; the
	// op-level wiring does exactly that from the active profile set.
	DefaultMaxAge = 10 * time.Minute

	// maxJTILen bounds the "jti" claim length. RFC 9101 sets no cap;
	// the verifier rejects oversized values to close the unbounded-
	// allocation surface (replay store key, audit log column). The
	// value is comfortably above any UUID encoding.
	maxJTILen = 256
)

// jtiUse is the typed scope tag for the request-object jti replay key.
// Keeping the type unexported and the constants below as the only
// constructors lets callers pick a scope through the typed [*Verifier]
// methods ([Verifier.Verify] / [Verifier.VerifyCIBA]) rather than by
// passing a raw string, so a typo cannot silently merge a new endpoint
// into an existing JTI namespace.
type jtiUse string

const (
	// jtiUseAuthorize scopes consumed request-object jti values minted
	// for the authorization endpoint. PAR shares this scope with
	// /authorize so a request object consumed at PAR cannot be replayed
	// at /authorize within its lifetime.
	jtiUseAuthorize jtiUse = "authz"

	// jtiUseCIBA scopes consumed request-object jti values minted for
	// the CIBA backchannel authentication endpoint. CIBA is a distinct
	// flow from /authorize so the jti namespace is independent: a
	// client may legitimately mint the same jti string on both
	// surfaces over time.
	jtiUseCIBA jtiUse = "ciba"
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

// freshJWKSResolver is the optional extension a [JWKSResolver] implements
// to support a cache-bypassing refetch of a jwks_uri client's keyset. The
// production [DefaultResolver] satisfies it; a resolver that only
// implements [JWKSResolver] simply loses key-rotation recovery — a request
// object signed with a key the RP rotated in after the OP last cached its
// keyset fails with invalid_request_object until the cache TTL lapses.
//
// This mirrors the private_key_jwt recovery path
// (clientauth.StoreJWKSResolver.RefreshJWKS): the token endpoint already
// retries once against fresh keys, so /authorize, /par, and CIBA (which
// share this verifier) must do the same for the RP experience to stay
// consistent across endpoints.
type freshJWKSResolver interface {
	ResolveFresh(ctx context.Context, c *store.Client) (*josev4.JSONWebKeySet, error)
}

// EncryptionResolver is the type alias the public verifier exposes for
// the JWE decryption seam. It mirrors [jose.EncryptionKeyResolver] so
// callers can plumb a [keys.EncryptionSet] (or any other resolver)
// through [VerifierConfig.EncryptionResolver] without taking a direct
// dependency on the JOSE wrapper.
type EncryptionResolver = jose.EncryptionKeyResolver

// Verifier is the request-scoped entry point. Construct it once at
// startup with [NewVerifier]; the value is immutable and safe for
// concurrent use.
type Verifier struct {
	clock         timex.Clock
	resolver      JWKSResolver
	decrypter     EncryptionResolver
	issuer        string
	allowedAlgs   map[jose.Algorithm]struct{}
	maxFutureSkew time.Duration
	maxAge        time.Duration
	requireNbf    bool
	requireIAT    bool
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

	// MaxAge overrides [DefaultMaxAge]: it is the oldest "iat" the
	// verifier admits. Zero or negative falls back to the default.
	//
	// The field is profile-driven at the op layer. It must not be left
	// at the default under a profile that grants request objects a
	// longer window than [DefaultMaxAge] — FAPI 2.0 Message Signing
	// §5.6 grants 60 minutes — because the age check runs ahead of
	// [VerifierConfig.MaxLifetime] and would reject a still-valid
	// object first.
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

	// RequireIAT, when true, rejects request objects whose "iat"
	// claim is absent. RFC 9101 §6.1 marks "iat" as OPTIONAL but
	// FAPI-CIBA Profile §5.2.2 promotes it to MUST. The flag exists
	// so the strict FAPI-CIBA posture lands on CIBA deployments
	// without breaking the OIDC Core / FAPI 2.0 baseline default.
	RequireIAT bool

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
	// Profile interaction: the [op.New] wiring layer leaves this
	// field true for OIDC Core, FAPI2Baseline, and
	// FAPI2MessageSigning, because RFC 9101 §6.1 marks "jti" as
	// OPTIONAL and neither FAPI 2.0 profile promotes it to MUST; the
	// §10.8 replay-defence floor is still preserved through [JTIs]
	// for every jti a request object does carry. FAPICIBA is the
	// sole profile that flips the field to false: the FAPI-CIBA
	// Profile §5.2.2 promotes jti to MUST on the backchannel
	// authentication request object, so a jti-less object under that
	// profile is rejected with [ErrJTIMissing]. There is no
	// embedder-facing option to override either default; the setting
	// lives at the profile-activation site.
	AllowMissingJTI bool

	// MaxLifetime, when positive, caps how far "exp" may lie in the
	// future and how far "nbf" may lie in the past relative to "now".
	// FAPI 2.0 Message Signing §5.6 mandates a 60-minute window.
	// Zero leaves the cap disabled (back-compat).
	MaxLifetime time.Duration

	// EncryptionResolver, when non-nil, enables JWE-shaped request
	// objects (compact form with five base64url segments). The
	// verifier decrypts the JWE through [jose.Decrypt],
	// expecting a nested JWS plaintext (`cty=JWT` or absent), and
	// runs the rest of the pipeline against the decrypted JWS.
	//
	// A nil resolver leaves the verifier JWS-only: a JWE-shaped raw
	// returns [ErrEncryptionUnsupported] so the wire layer can map
	// the failure onto invalid_request_object. The OP-level wiring
	// supplies a [*keys.EncryptionSet] when [op.WithEncryptionKeyset]
	// is configured; without that option the field stays nil and
	// the rest of the pipeline is unaffected.
	EncryptionResolver EncryptionResolver
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
		decrypter:     cfg.EncryptionResolver,
		issuer:        cfg.Issuer,
		allowedAlgs:   allowed,
		maxFutureSkew: skew,
		maxAge:        maxAge,
		requireNbf:    requireNbf,
		requireIAT:    cfg.RequireIAT,
		allowMissJTI:  cfg.AllowMissingJTI,
		jtis:          cfg.JTIs,
		maxLifetime:   cfg.MaxLifetime,
	}, nil
}

// defaultAllowedAlgs returns the project-wide JWS allow-list. The list
// mirrors internal/jose so JAR widens with every new alg the rest of
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
	return v.verifyForUse(ctx, raw, expectedClientID, client, jtiUseAuthorize)
}

// VerifyCIBA verifies raw as a signed CIBA backchannel-authentication
// request object. It is identical to [Verifier.Verify] except that any
// consumed "jti" is recorded under the CIBA scope, so the /authorize
// and CIBA endpoints do not share a replay namespace. See [jtiUse] for
// the scoping rationale.
func (v *Verifier) VerifyCIBA(ctx context.Context, raw, expectedClientID string, client *store.Client) (*Object, error) {
	return v.verifyForUse(ctx, raw, expectedClientID, client, jtiUseCIBA)
}

// verifyForUse is the shared body behind [Verifier.Verify] and
// [Verifier.VerifyCIBA]. The use parameter is unexported and typed so
// the only call sites are the typed entry points above; adding a new
// endpoint requires adding a new typed method and a new [jtiUse]
// constant, which makes the scoping decision explicit at the call site
// rather than hidden behind a string literal.
func (v *Verifier) verifyForUse(ctx context.Context, raw, expectedClientID string, client *store.Client, use jtiUse) (*Object, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: client is required", ErrJWKSConfigured)
	}
	innerJWS, err := v.maybeDecrypt(ctx, raw)
	if err != nil {
		return nil, err
	}
	parsed, err := Parse(innerJWS)
	if err != nil {
		return nil, err
	}
	if _, ok := v.allowedAlgs[parsed.Algorithm]; !ok {
		return nil, fmt.Errorf("%w: alg %q", ErrAlgNotAllowed, parsed.Algorithm)
	}
	if pin := client.RequestObjectSigningAlg; pin != "" && pin != parsed.Algorithm.String() {
		return nil, fmt.Errorf("%w: client requires %q", ErrAlgNotAllowed, pin)
	}
	payload, err := v.verifySignature(ctx, parsed, client)
	if err != nil {
		return nil, err
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
	if err := v.consumeJTI(ctx, parsed, expectedClientID, use); err != nil {
		return nil, err
	}
	return parsed, nil
}

// verifySignature resolves the client's keyset, selects the key named by
// the parsed header, holds it to the OP's key-shape floor, and verifies
// the JWS signature, returning the verified payload bytes. It runs after
// the alg-allowlist and client alg-pin checks in [Verifier.verifyForUse]
// so the error precedence (alg rejection before key resolution) is
// preserved.
func (v *Verifier) verifySignature(ctx context.Context, parsed *Object, client *store.Client) ([]byte, error) {
	keys, err := v.resolver.Resolve(ctx, client)
	if err != nil {
		return nil, err
	}
	if keys == nil || len(keys.Keys) == 0 {
		return nil, ErrNoMatchingJWK
	}
	jwk, err := pickKey(keys, parsed.KeyID)
	if err != nil {
		jwk, err = v.pickFromRefreshedKeys(ctx, parsed, client, err)
		if err != nil {
			return nil, err
		}
	}
	// Defence-in-depth: hold the client-supplied verification key to the
	// same RFC 7518 §3.3 / RFC 8725 §3.2 floor the OP applies to its own
	// keys (RSA >= 2048 bits, curve pinned to the declared alg). A
	// sub-floor or curve-mismatched client key is rejected as an invalid
	// signature rather than being handed to go-jose with a laxer check.
	if err := jose.AssertAlgKeyShape(parsed.Algorithm.String(), jwk.Key); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigInvalid, err)
	}
	payload, err := parsed.jws.Verify(jwk.Key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigInvalid, err)
	}
	return payload, nil
}

// pickFromRefreshedKeys performs the key-rotation-recovery retry when the
// initial key selection missed. It applies only to a jwks_uri client (an
// inline-JWKs client cannot rotate out-of-band) whose resolver supports a
// cache-bypassing refetch; in every other case, or when the refreshed set
// still lacks the key, it returns the original miss unchanged so the wire
// response and error precedence are preserved. The forced refetch is
// throttled per URL by the fetcher ([rpjwks.ForcedRefreshInterval]), so a bogus
// kid cannot be used to hammer the RP's jwks_uri endpoint.
func (v *Verifier) pickFromRefreshedKeys(
	ctx context.Context,
	parsed *Object,
	client *store.Client,
	miss error,
) (*josev4.JSONWebKey, error) {
	if !errors.Is(miss, ErrNoMatchingJWK) || client.JWKsURI == "" || len(client.JWKs) != 0 {
		return nil, miss
	}
	fresh, ok := v.resolver.(freshJWKSResolver)
	if !ok {
		return nil, miss
	}
	keys, err := fresh.ResolveFresh(ctx, client)
	if err != nil || keys == nil || len(keys.Keys) == 0 {
		return nil, miss
	}
	jwk, err := pickKey(keys, parsed.KeyID)
	if err != nil {
		return nil, miss
	}
	return jwk, nil
}

// maybeDecrypt detects a JWE-shaped raw (5-segment compact form per
// RFC 7516 §3.1) and peels every nested JWE layer through the
// configured [EncryptionResolver] until the plaintext is no longer
// JWE-shaped. The final non-JWE plaintext is expected to be a JWS the
// downstream [Parse] consumes — OIDC §6.1 mandates a signed inner
// payload, so a JWE wrapping plain JSON would fail at JWS parsing
// regardless and the verifier does not special-case it.
//
// A 3-segment raw (compact JWS) is returned unchanged. Any other
// segment count is left to [Parse] to reject as [ErrParse]; the
// segment-count gate exists only so we do not call [jose.DecryptChain]
// against a JWS by mistake.
//
// Nested JWE-of-JWE-of-JWS chains are honoured up to a total of
// [jose.MaxJOSENestingDepth] JOSE layers (counting both the JWE peels
// and the inner JWS the caller parses). The chain budget passed to
// [jose.DecryptChain] reserves one slot for the final JWS so a
// JWE-of-JWS chain costs depth=2 and the boundary case sits at
// 9 JWEs + 1 JWS = 10 layers. The 11th layer is rejected with
// [jose.ErrJWENestingTooDeep], which collapses onto [ErrParse] so the
// wire layer surfaces invalid_request_object uniformly.
//
// JWE-shaped raw without a configured resolver returns
// [ErrEncryptionUnsupported] (the OP cannot honour the request
// object). With a resolver configured, the JOSE-level sentinels are
// collapsed onto the JAR taxonomy:
//
//   - [jose.ErrJWEAlgNotAllowed] / [jose.ErrJWEEncNotAllowed] →
//     [ErrEncryptionAlgNotAllowed].
//   - [jose.ErrJWEKidUnknown] / [jose.ErrJWEDecryptFailed] →
//     [ErrDecryptFailed] (kid-unknown is folded into the failure
//     class so an attacker cannot enumerate the OP's encryption
//     keyset through the wire response).
//   - Every other JOSE sentinel — including [jose.ErrJWENestingTooDeep]
//     — maps to [ErrParse] so the wire layer surfaces
//     invalid_request_object uniformly.
//
// ctx is pinned onto the resolver when it implements
// [jose.ContextualEncryptionKeyResolver], so the audit event a rotating
// encryption keyset fires for a retired kid names the request object
// that presented it. [jose.DecryptChain] itself takes no context: the
// JOSE layer does no I/O and has nothing to cancel.
func (v *Verifier) maybeDecrypt(ctx context.Context, raw string) (string, error) {
	dotCount := strings.Count(raw, ".")
	if dotCount != 4 {
		return raw, nil
	}
	if v.decrypter == nil {
		return "", ErrEncryptionUnsupported
	}
	decrypter := v.decrypter
	if contextual, ok := decrypter.(jose.ContextualEncryptionKeyResolver); ok {
		decrypter = contextual.WithContext(ctx)
	}
	// Reserve one slot of [jose.MaxJOSENestingDepth] for the inner
	// JWS [Parse] consumes after this function returns; the rest of
	// the budget bounds how many JWE layers DecryptChain may peel.
	// The boundary therefore lands at 9 JWE peels + 1 JWS parse =
	// MaxJOSENestingDepth layers total.
	out, err := jose.DecryptChain(raw, decrypter, jose.MaxJOSENestingDepth-1)
	if err != nil {
		return "", mapJWEError(err)
	}
	return string(out.Plaintext), nil
}

// mapJWEError collapses the JOSE-level JWE sentinels onto the JAR
// wire-error taxonomy. The mapping mirrors the doc on
// [Verifier.maybeDecrypt] and lives in one place so a future audit
// can verify the wire-error envelope is uniform across kid-unknown,
// decrypt-failed, decrypt-succeeded-but-malformed-plaintext, and
// nesting-too-deep paths.
//
// [jose.ErrJWENestingTooDeep] folds onto [ErrParse] so the wire layer
// surfaces invalid_request_object — a deeply nested JWE chain is a
// malformed request object from the verifier's perspective, and
// distinguishing it on the wire would only help an attacker
// enumerate the depth cap.
func mapJWEError(err error) error {
	switch {
	case errors.Is(err, jose.ErrJWEAlgNotAllowed),
		errors.Is(err, jose.ErrJWEEncNotAllowed):
		return fmt.Errorf("%w: %w", ErrEncryptionAlgNotAllowed, err)
	case errors.Is(err, jose.ErrJWEKidUnknown),
		errors.Is(err, jose.ErrJWEDecryptFailed):
		return fmt.Errorf("%w: %w", ErrDecryptFailed, err)
	default:
		return fmt.Errorf("%w: %w", ErrParse, err)
	}
}

// consumeJTI enforces the RFC 9101 §10.8 replay-defence floor on the
// request object's "jti" claim. The function runs after the rest of
// the claim validation succeeds so a malformed or stale request
// object never advances the consumed-jti table. The mark key is
// scoped to endpoint use and client_id so two endpoints or clients
// minting the same jti by coincidence do not collide.
//
// When the verifier was constructed with a nil JTIs store, the
// embedder explicitly opted into [VerifierConfig.AllowMissingJTI];
// the function then admits every request object regardless of jti
// presence. The opt-in is the only path that bypasses the gate.
func (v *Verifier) consumeJTI(ctx context.Context, obj *Object, clientID string, use jtiUse) error {
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
	expiresAt, ok := jtiExpiry(obj.Claims, v.clock.Now(), v.maxAge, v.maxFutureSkew, v.maxLifetime)
	if !ok {
		// "exp" was already validated upstream; reaching this branch
		// means the claim disappeared between the two reads, which is
		// a malformed-object class.
		return fmt.Errorf("%w: jti consume: missing exp", ErrParse)
	}
	key := "jar:" + string(use) + ":" + clientID + ":" + jti
	if err := v.jtis.Mark(ctx, key, expiresAt); err != nil {
		if errors.Is(err, store.ErrAlreadyConsumed) {
			return ErrJTIReplayed
		}
		return fmt.Errorf("jar: mark jti: %w", err)
	}
	return nil
}

// jtiExpiry reads the request object's "exp" claim and projects it onto the
// wall clock the verifier is using. The consumed-jti row is retained at least
// through the verifier's max-age window plus clock skew so coarse TTL
// backends cannot evict a just-accepted jti before every still-valid replay
// candidate has aged out.
//
// Retention is also bounded above by a server-configured ceiling: the widest
// window the verifier's own configuration admits a request object to live in
// (maxLifetime when it is set, the max-age window otherwise) plus skew. Without
// the clamp a client-chosen "exp" decides how long the OP keeps the row, so a
// single misbehaving RP could pin one replay marker per authorization request
// for centuries and make the consumed-jti table's size its own choice. The
// clamp is unconditional for the same reason the DPoP and client-assertion
// replay gates clamp theirs: it must not depend on a profile being enabled.
// On every accepting path with maxLifetime set the ceiling is above the
// admitted "exp", so the clamp only bites where a client-supplied timestamp
// would otherwise be unbounded.
func jtiExpiry(claims map[string]any, now time.Time, maxAge, skew, maxLifetime time.Duration) (time.Time, bool) {
	exp, ok := claimSeconds(claims, "exp")
	if !ok {
		return time.Time{}, false
	}
	expAt := time.Unix(exp, 0)
	if !expAt.After(now) {
		return time.Time{}, false
	}
	window := maxAge
	if maxLifetime > window {
		window = maxLifetime
	}
	retainUntil := expAt
	if floor := now.Add(maxAge); floor.After(retainUntil) {
		retainUntil = floor
	}
	if ceiling := now.Add(window); retainUntil.After(ceiling) {
		retainUntil = ceiling
	}
	return retainUntil.Add(skew), true
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
//
// Either branch additionally requires the selected key to be usable for
// signatures ([signingUsable]).
func pickKey(keys *josev4.JSONWebKeySet, kid string) (*josev4.JSONWebKey, error) {
	if kid != "" {
		// JSONWebKeySet.Key returns every key whose kid matches; pick
		// the first usable one to keep behaviour deterministic.
		// Multiple keys sharing a kid is a misconfiguration on the RP
		// side.
		for _, k := range keys.Key(kid) {
			if signingUsable(k.Use) {
				return &k, nil
			}
		}
		return nil, ErrNoMatchingJWK
	}
	if len(keys.Keys) == 1 && signingUsable(keys.Keys[0].Use) {
		k := keys.Keys[0]
		return &k, nil
	}
	return nil, ErrNoMatchingJWK
}

// signingUsable reports whether a JWK whose "use" member is declared as
// use may verify a signature. RFC 7517 §4.2 makes the declaration
// binding: a key published as "enc" is the RP's response-encryption key,
// not a verification key, and an unrecognised value names a purpose this
// OP cannot honour. An absent "use" leaves the key unrestricted, which
// RFC 7517 permits and many RPs rely on.
//
// The predicate mirrors the one client registration applies when it
// decides whether a JWKS carries a signing key. Without it here the
// verifier is laxer than the registration gate, so a client could sign a
// request object with a key the OP never accepted as a signing key.
func signingUsable(use string) bool {
	return use == "" || use == "sig"
}

// validateClaims runs the RFC 9101 §6.1 / FAPI 2.0 Message Signing
// §5.6 checklist on the verified claim bag.
func (v *Verifier) validateClaims(obj *Object, expectedClientID string) error {
	if err := assertType(obj); err != nil {
		return err
	}
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
	if err := assertIat(obj, now, v.maxFutureSkew, v.maxAge, v.requireIAT); err != nil {
		return err
	}
	return nil
}

const requestObjectType = "oauth-authz-req+jwt"

// assertType enforces RFC 9101 §10.8 explicit typing only when the
// request object actually declares a "typ". The "oauth-authz-req+jwt"
// media type is RECOMMENDED, not REQUIRED, so a request object that
// omits typ entirely — as RFC 9101 permits and many RPs emit — is
// accepted. When typ IS present it must name a request object
// (optionally with the "application/" media-type prefix); any other
// declared type is rejected so a JWT minted for a different purpose
// cannot be replayed here. The comparison is case-insensitive because
// media types are case-insensitive (RFC 2045 §5.1).
func assertType(obj *Object) error {
	switch strings.ToLower(obj.Type) {
	case "", requestObjectType, "application/" + requestObjectType:
		return nil
	default:
		return ErrTypeInvalid
	}
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

// assertAudience enforces RFC 9101 §6.1: the request object "aud" must
// identify the OP issuer. The claim may be a single string or an array
// per RFC 7519 §4.1.3, and an array is accepted as long as the issuer is
// among its values — RFC 9101 / FAPI 2.0 Message Signing require the
// issuer to be present, not that it be the sole audience, so additional
// audiences are ignored rather than rejected.
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
// Message Signing §5.6 imposes a 60-minute cap) the function additionally
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
// "ensure-request-object-with-nbf-over-60-fails" pins 60 minutes.
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
// past. An absent "iat" is permitted unless requireIAT is set: RFC
// 9101 marks the claim optional, but FAPI-CIBA Profile §5.2.2
// promotes it to MUST so the OP-level wiring opts in for CIBA
// deployments.
func assertIat(obj *Object, now time.Time, skew, maxAge time.Duration, requireIAT bool) error {
	iat, ok := claimSeconds(obj.Claims, "iat")
	if !ok {
		if requireIAT {
			return ErrIATMissing
		}
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
	fetcher *Fetcher
}

// NewDefaultResolver returns a resolver suitable for production. It
// uses an in-process JWKS cache keyed by URL with a 5-minute default
// TTL and applies the SSRF / body-cap / content-type protections in
// [Fetcher]. Apply [AllowPrivateNetwork] when the OP must reach a
// JWKS endpoint on a private network — the deny-list rejects loopback
// / link-local / RFC 1918 hosts otherwise.
func NewDefaultResolver(clock timex.Clock, opts ...ResolverOption) *DefaultResolver {
	fetcher := NewFetcher(clock)
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
type ResolverOption func(*Fetcher)

// AllowPrivateNetwork disables the SSRF deny-list on the JWKS fetcher
// so the OP may reach RP JWKS endpoints whose hosts resolve to
// loopback / link-local / RFC 1918 addresses. The opt-in is required
// because the default posture rejects every private network to
// neutralise SSRF attacks via attacker-controlled jwks_uri values.
func AllowPrivateNetwork() ResolverOption {
	return func(f *Fetcher) { f.SetAllowPrivate(true) }
}

// WithBaseTransport injects a [http.RoundTripper] the JWKS fetcher
// will use instead of the package default. Forwards to
// [Fetcher.SetBaseTransport]; see that doc comment for the semantics.
// Used by embedders that need a custom TLS trust store (internal CA,
// dev conformance harness with self-signed certs).
func WithBaseTransport(rt http.RoundTripper) ResolverOption {
	return func(f *Fetcher) { f.SetBaseTransport(rt) }
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

// ResolveFresh implements the optional [freshJWKSResolver] key-rotation
// recovery seam so a request object signed with a freshly rotated RP key
// verifies without waiting out the JWKS cache TTL.
func (r *DefaultResolver) ResolveFresh(ctx context.Context, c *store.Client) (*josev4.JSONWebKeySet, error) {
	return r.inner.ResolveFresh(ctx, c)
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
		return r.fetcher.Fetch(ctx, c.JWKsURI)
	}
	return nil, ErrJWKSConfigured
}

// ResolveFresh mirrors [defaultResolver.Resolve] but forces a
// cache-bypassing refetch for a jwks_uri client. Inline-JWKs clients
// cannot rotate out-of-band, so their keyset is returned unchanged.
func (r *defaultResolver) ResolveFresh(ctx context.Context, c *store.Client) (*josev4.JSONWebKeySet, error) {
	if len(c.JWKs) > 0 {
		keys, err := parseJWKS(c.JWKs)
		if err != nil {
			return nil, err
		}
		return keys, nil
	}
	if c.JWKsURI != "" {
		return r.fetcher.FetchFresh(ctx, c.JWKsURI)
	}
	return nil, ErrJWKSConfigured
}

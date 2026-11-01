package clientauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/op/store"
)

// AssertionVerifier verifies a private_key_jwt assertion. The interface
// abstracts the source of client public keys (static registry, JWKS URI,
// JWKS-by-value) so the rest of the package can stay agnostic.
type AssertionVerifier interface {
	// Verify returns nil when the compact-serialised assertion verifies
	// against a key registered for clientID, the standard claims pass
	// (iss == sub == clientID, aud contains expectedAudience, exp not in
	// the past, iat not in the future, nbf if present), AND the
	// assertion's "jti" was not previously consumed within its lifetime.
	//
	// On success Verify SHOULD record the jti so a subsequent call with
	// the same assertion fails with [ErrAssertionReplayed].
	Verify(ctx context.Context, clientID, assertion string) error
}

// AssertionClaims is the subset of standard JWT claims the verifier
// inspects. The shape is exposed so embedders implementing their own
// AssertionVerifier can reuse the parser.
type AssertionClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"-"`
	JTI       string   `json:"jti"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
}

// JWKSResolver returns the JWKS registered for a client. Embedders wire
// this to their client store; the package keeps it abstract so it can
// drive both static registries and JWKS-URI fetchers.
type JWKSResolver interface {
	// JWKS returns the keys registered for clientID. The returned set
	// MAY be empty when the caller hasn't registered any; the verifier
	// treats an empty set as a hard reject.
	JWKS(ctx context.Context, clientID string) (*josev4.JSONWebKeySet, error)
}

type assertionSigningAlgResolver interface {
	AssertionSigningAlg(ctx context.Context, clientID string) (string, error)
}

// MaxAssertionLifetime bounds how far in the future a client assertion's
// exp may sit. The jwt-bearer grant verifier shares it.
const MaxAssertionLifetime = 5 * time.Minute

// DefaultAssertionLeeway is the skew tolerance applied to the time
// claims of a client assertion when [PrivateKeyJWTVerifier.Leeway] is
// zero.
//
// It is deliberately wider than the tolerance applied to access tokens
// (see tokens.DefaultLeeway): an assertion is minted by a peer whose
// clock this OP does not control and cannot correct, whereas an access
// token was minted by this OP against its own clock. The two budgets
// answer different questions and are not required to agree, but each
// must have exactly one source so that neither drifts by having a
// number restated at a second verification point.
const DefaultAssertionLeeway = 60 * time.Second

// PrivateKeyJWTVerifier is the library's reference [AssertionVerifier].
// Embedders typically use this verifier wrapped around their own
// JWKSResolver and the OP's [store.ConsumedJTIStore].
type PrivateKeyJWTVerifier struct {
	// Resolver returns the candidate JWKS for the client. Required.
	Resolver JWKSResolver

	// JTIStore records assertion identifiers for replay defence.
	// Required: an OP without a JTI store cannot honour RFC 7523 §3.
	JTIStore store.ConsumedJTIStore

	// Audience is the expected "aud" value of the assertion: per
	// OIDC Core §9 it MUST be the OP's token endpoint URL.
	Audience string

	// AuxAudiences is the set of additional "aud" values the verifier
	// accepts when [Audience] does not match. It exists because
	// FAPI 2.0 §5.2.2 mandates aud == issuer (not aud == token
	// endpoint), and RFC 7523 §3 itself says "a value identifying
	// the authorization server" without pinning which identifier.
	// A wider verifier accepts both shapes so an OP that runs OIDC
	// Core and FAPI 2.0 simultaneously authenticates clients in
	// either dialect. Empty disables the extra acceptance.
	AuxAudiences []string

	// Clock returns the current wall-clock time. Required so tests can
	// pin the verification window.
	Clock func() time.Time

	// Leeway tolerates small clock skew on iat / nbf / exp comparisons.
	// Defaults to [DefaultAssertionLeeway] when zero.
	Leeway time.Duration

	// AllowedAlgs narrows the JWS "alg" values an assertion may carry
	// below the project allow-list, independently of any per-client pin.
	// The op layer populates it from the active profile. Empty leaves the
	// project allow-list in force.
	AllowedAlgs []jose.Algorithm
}

// Verify implements [AssertionVerifier].
func (v *PrivateKeyJWTVerifier) Verify(ctx context.Context, clientID, assertion string) error {
	if v.Resolver == nil || v.JTIStore == nil || v.Clock == nil || v.Audience == "" {
		return errors.New("authn: PrivateKeyJWTVerifier missing required fields")
	}
	// Install a per-request client memo so the resolver's alg-pin, JWKS,
	// and rotation-refetch seams share one GetClient round-trip.
	ctx = withClientMemo(ctx)
	leeway := v.Leeway
	if leeway <= 0 {
		leeway = DefaultAssertionLeeway
	}

	jws, _, err := jose.ParseSigned(assertion)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAssertionMalformed, err)
	}
	if !v.policyAllowsAlg(jws) {
		return ErrCredentialsInvalid
	}
	if err := checkAssertionAlgPin(ctx, v.Resolver, clientID, jws); err != nil {
		return err
	}
	payload, err := resolveAndVerify(ctx, v.Resolver, clientID, jws)
	if err != nil {
		return err
	}
	claims, err := decodeAssertionClaims(payload)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAssertionMalformed, err)
	}
	accepted := append([]string{v.Audience}, v.AuxAudiences...)
	now := v.Clock()
	if err := validateAssertionClaims(claims, clientID, accepted, now, leeway); err != nil {
		return err
	}
	replayKey, err := assertionReplayKey(clientID, claims.JTI)
	if err != nil {
		return err
	}
	expiresAt := assertionJTIExpiry(claims, now, leeway)
	if err := v.JTIStore.Mark(ctx, replayKey, expiresAt); err != nil {
		if errors.Is(err, store.ErrAlreadyConsumed) {
			return ErrAssertionReplayed
		}
		return fmt.Errorf("authn: jti store: %w", err)
	}
	return nil
}

// resolveAndVerify resolves the client's keyset and verifies the
// assertion signature against it. On a verification miss that a key
// rotation could explain (see [refreshedKeysOnKIDMiss]) it refetches the
// keyset once and retries. Every client-side failure collapses to
// [ErrCredentialsInvalid] so the wire response never distinguishes
// "unknown client" / "no keys" / "bad signature"; a server-side
// key-source failure passes through [classifyKeyResolution] instead.
func resolveAndVerify(ctx context.Context, resolver JWKSResolver, clientID string, jws *josev4.JSONWebSignature) ([]byte, error) {
	keys, err := resolver.JWKS(ctx, clientID)
	if err != nil && keySourceUnavailable(err) {
		return nil, classifyKeyResolution(err)
	}
	if err != nil || keys == nil || len(keys.Keys) == 0 {
		// Timing uniformity (L-14): a known client with no usable JWKS
		// (unconfigured keys, a resolver/fetch error, or an empty set)
		// would otherwise return without any signature work and complete
		// measurably faster than the wrong-signature path, letting an
		// attacker distinguish "client has no keys" from "client has keys,
		// bad signature". Burn one fixed-cost verify so the two branches
		// share a floor. Perfect leveling is impossible (the verify branch
		// trials 1..MaxKidlessTrialKeys keys), but the gross zero-vs-some
		// gap is what an attacker measures.
		burnJWTVerify()
		return nil, ErrCredentialsInvalid
	}
	if payload, vErr := rpjwks.VerifySignature(jws, keys); vErr == nil {
		return payload, nil
	}
	// RP key rotation: the assertion may be signed with a key the client
	// rotated in after the OP last cached its jwks_uri keyset. When the
	// signing kid is absent from the cached set and the resolver supports
	// a (throttled) refetch, pull the current keyset once and retry.
	refreshed, ok, err := refreshedKeysOnKIDMiss(ctx, resolver, clientID, jws, keys)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrCredentialsInvalid
	}
	payload, err := rpjwks.VerifySignature(jws, refreshed)
	if err != nil {
		return nil, ErrCredentialsInvalid
	}
	return payload, nil
}

// jwksRefresher is the optional extension a [JWKSResolver] implements to
// expose a cache-bypassing keyset refetch for RP key rotation. The
// production [StoreJWKSResolver] satisfies it; a resolver that does not
// simply forgoes rotation recovery.
type jwksRefresher interface {
	RefreshJWKS(ctx context.Context, clientID string) (*josev4.JSONWebKeySet, error)
}

// refreshedKeysOnKIDMiss returns a freshly-fetched keyset, and true, when
// a verification miss is plausibly a rotated-out key: the resolver
// supports a refetch AND [rpjwks.RefreshOnKIDMiss] accepts the miss. It
// returns ok=false when rotation cannot explain the miss (resolver has no
// refetch, kid is present so the signature is simply wrong, the refetch
// failed, or it returned the keyset just tried), so the caller rejects
// without a wasted retry. A server-side refetch failure is returned as an
// error.
func refreshedKeysOnKIDMiss(
	ctx context.Context,
	resolver JWKSResolver,
	clientID string,
	jws *josev4.JSONWebSignature,
	tried *josev4.JSONWebKeySet,
) (*josev4.JSONWebKeySet, bool, error) {
	refresher, ok := resolver.(jwksRefresher)
	if !ok {
		return nil, false, nil
	}
	fresh, ok, err := rpjwks.RefreshOnKIDMiss(ctx, jws, tried, func(ctx context.Context) (*josev4.JSONWebKeySet, error) {
		return refresher.RefreshJWKS(ctx, clientID)
	})
	if err != nil {
		if keySourceUnavailable(err) {
			return nil, false, classifyKeyResolution(err)
		}
		// A client-side refetch failure cannot explain the miss.
		return nil, false, nil
	}
	return fresh, ok, nil
}

// keySourceUnavailable reports whether a key-resolution failure is a
// server-side fault (client-store outage, or URL-load capacity pressure on
// the jwks_uri fetch) rather than evidence about the client's credentials.
func keySourceUnavailable(err error) bool {
	return errors.Is(err, errClientLookup) || rpjwks.IsKeySourceUnavailable(err)
}

// classifyKeyResolution maps a key-resolution failure onto the verifier's
// error contract: a server-side fault keeps its cause so the endpoint
// answers server_error and the client retries; anything else collapses to
// [ErrCredentialsInvalid].
func classifyKeyResolution(err error) error {
	if keySourceUnavailable(err) {
		return fmt.Errorf("authn: client key resolution: %w", err)
	}
	return ErrCredentialsInvalid
}

// policyAllowsAlg reports whether the assertion's alg is inside
// [PrivateKeyJWTVerifier.AllowedAlgs]; an empty list admits every alg
// [jose.ParseSigned] already accepted.
func (v *PrivateKeyJWTVerifier) policyAllowsAlg(jws *josev4.JSONWebSignature) bool {
	if len(v.AllowedAlgs) == 0 {
		return true
	}
	if len(jws.Signatures) == 0 {
		return false
	}
	return slices.Contains(v.AllowedAlgs, jose.Algorithm(jws.Signatures[0].Header.Algorithm))
}

// checkAssertionAlgPin rejects an assertion whose alg differs from the
// client's registered token_endpoint_auth_signing_alg, when one is pinned.
func checkAssertionAlgPin(ctx context.Context, resolver JWKSResolver, clientID string, jws *josev4.JSONWebSignature) error {
	algResolver, ok := resolver.(assertionSigningAlgResolver)
	if !ok {
		return nil
	}
	pin, err := algResolver.AssertionSigningAlg(ctx, clientID)
	if err != nil {
		return classifyKeyResolution(err)
	}
	if pin == "" {
		return nil
	}
	if len(jws.Signatures) == 0 || jws.Signatures[0].Header.Algorithm != pin {
		return ErrCredentialsInvalid
	}
	return nil
}

// decodeAssertionClaims unmarshals the JWS payload onto AssertionClaims,
// reconciling the "aud" claim's polymorphic shape.
func decodeAssertionClaims(payload []byte) (AssertionClaims, error) {
	var raw struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
		Jti string          `json:"jti"`
		Iat int64           `json:"iat"`
		Nbf int64           `json:"nbf"`
		Exp int64           `json:"exp"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return AssertionClaims{}, err
	}
	aud, err := jose.DecodeAudience(raw.Aud)
	if err != nil {
		return AssertionClaims{}, err
	}
	return AssertionClaims{
		Issuer:    raw.Iss,
		Subject:   raw.Sub,
		Audience:  aud,
		JTI:       raw.Jti,
		IssuedAt:  raw.Iat,
		NotBefore: raw.Nbf,
		ExpiresAt: raw.Exp,
	}, nil
}

// validateAssertionClaims enforces the standard claim invariants
// required by OIDC Core §9: iss == sub == clientID, aud contains one
// of the accepted audience values, exp is in the future, iat is not in
// the future (within leeway), nbf if present is past. The jti is
// checked by [assertionReplayKey].
func validateAssertionClaims(claims AssertionClaims, clientID string, acceptedAud []string, now time.Time, leeway time.Duration) error {
	if claims.Issuer != clientID || claims.Subject != clientID {
		return ErrAssertionMalformed
	}
	if !audienceMatchesAny(claims.Audience, acceptedAud) {
		return ErrAssertionMalformed
	}
	if claims.ExpiresAt == 0 {
		return ErrAssertionMalformed
	}
	exp := time.Unix(claims.ExpiresAt, 0).UTC()
	if !now.Add(-leeway).Before(exp) {
		return ErrAssertionMalformed
	}
	if exp.After(now.Add(MaxAssertionLifetime)) {
		return ErrAssertionMalformed
	}
	if claims.IssuedAt != 0 {
		iat := time.Unix(claims.IssuedAt, 0).UTC()
		if iat.After(now.Add(leeway)) {
			return ErrAssertionMalformed
		}
	}
	if claims.NotBefore != 0 {
		nbf := time.Unix(claims.NotBefore, 0).UTC()
		if nbf.After(now.Add(leeway)) {
			return ErrAssertionMalformed
		}
	}
	return nil
}

// replayKeyEscaper percent-encodes the key separator in the identifier so
// each (identifier, jti) pair maps to exactly one replay key.
//
//nolint:gochecknoglobals // immutable, concurrency-safe replacer.
var replayKeyEscaper = strings.NewReplacer("%", "%25", ":", "%3A")

// ReplayKey builds the consumed-JTI store key for a (id, jti) pair under a
// namespace prefix (which carries its own trailing separator). The id is
// escaped so distinct pairs never collide on the separator.
func ReplayKey(prefix, id, jti string) string {
	return prefix + replayKeyEscaper.Replace(id) + ":" + jti
}

// assertionReplayKey builds the consumed-JTI key for an assertion,
// rejecting a jti that is empty or longer than [jose.MaxJTILen].
func assertionReplayKey(clientID, jti string) (string, error) {
	if jti == "" || len(jti) > jose.MaxJTILen {
		return "", ErrAssertionMalformed
	}
	return ReplayKey("clientassertion:", clientID, jti), nil
}

func assertionJTIExpiry(claims AssertionClaims, now time.Time, leeway time.Duration) time.Time {
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC().Add(leeway)
	maxRetain := now.Add(MaxAssertionLifetime + leeway)
	if expiresAt.After(maxRetain) {
		return maxRetain
	}
	return expiresAt
}

// audienceMatchesAny reports whether any of expected appears in aud.
// Empty entries in expected are skipped so a partially populated
// accept-list does not silently accept everything.
func audienceMatchesAny(aud, expected []string) bool {
	for _, e := range expected {
		if e == "" {
			continue
		}
		if slices.Contains(aud, e) {
			return true
		}
	}
	return false
}

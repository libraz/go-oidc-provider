package clientauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
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

// audienceClaim helps decode the "aud" claim, which RFC 7519 §4.1.3
// allows to be either a string or an array of strings.
type audienceClaim []string

// UnmarshalJSON accepts either form of the "aud" claim.
func (a *audienceClaim) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := jsonUnmarshal(data, &s); err != nil {
			return err
		}
		*a = audienceClaim{s}
		return nil
	}
	var arr []string
	if err := jsonUnmarshal(data, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
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

const maxAssertionLifetime = 5 * time.Minute

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
	// Defaults to 60 seconds when zero.
	Leeway time.Duration
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
		leeway = 60 * time.Second
	}

	jws, _, err := jose.ParseSigned(assertion)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAssertionMalformed, err)
	}
	if !assertionAlgAllowed(ctx, v.Resolver, clientID, jws) {
		return ErrCredentialsInvalid
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
	expiresAt := assertionJTIExpiry(claims, now, leeway)
	if err := v.JTIStore.Mark(ctx, assertionJTIKey(clientID, claims.JTI), expiresAt); err != nil {
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
// keyset once and retries. Any failure collapses to
// [ErrCredentialsInvalid] so the wire response never distinguishes
// "unknown client" / "no keys" / "bad signature".
func resolveAndVerify(ctx context.Context, resolver JWKSResolver, clientID string, jws *josev4.JSONWebSignature) ([]byte, error) {
	keys, err := resolver.JWKS(ctx, clientID)
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
		dummyJWTVerify()
		return nil, ErrCredentialsInvalid
	}
	if payload, vErr := verifySignature(jws, keys); vErr == nil {
		return payload, nil
	}
	// RP key rotation: the assertion may be signed with a key the client
	// rotated in after the OP last cached its jwks_uri keyset. When the
	// signing kid is absent from the cached set and the resolver supports
	// a (throttled) refetch, pull the current keyset once and retry.
	refreshed, ok := refreshedKeysOnKIDMiss(ctx, resolver, clientID, jws, keys)
	if !ok {
		return nil, ErrCredentialsInvalid
	}
	payload, err := verifySignature(jws, refreshed)
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
// supports a refetch AND the assertion's signing kid is absent from the
// keyset just tried. It returns ok=false when rotation cannot explain the
// miss (resolver has no refetch, kid is present so the signature is
// simply wrong, or the refetch failed), so the caller rejects without a
// wasted retry.
func refreshedKeysOnKIDMiss(
	ctx context.Context,
	resolver JWKSResolver,
	clientID string,
	jws *josev4.JSONWebSignature,
	tried *josev4.JSONWebKeySet,
) (*josev4.JSONWebKeySet, bool) {
	refresher, ok := resolver.(jwksRefresher)
	if !ok || !assertionKIDAbsent(jws, tried) {
		return nil, false
	}
	fresh, err := refresher.RefreshJWKS(ctx, clientID)
	if err != nil || fresh == nil || len(fresh.Keys) == 0 {
		return nil, false
	}
	return fresh, true
}

// assertionKIDAbsent reports whether the assertion's signing key id is
// missing from keys. A signature with no kid is treated as absent (a
// single-key rotation still warrants one refetch); an empty keyset is
// absent by definition.
func assertionKIDAbsent(jws *josev4.JSONWebSignature, keys *josev4.JSONWebKeySet) bool {
	if len(jws.Signatures) == 0 {
		return false
	}
	kid := jws.Signatures[0].Header.KeyID
	if keys == nil || len(keys.Keys) == 0 {
		return true
	}
	if kid == "" {
		return true
	}
	for i := range keys.Keys {
		if keys.Keys[i].KeyID == kid {
			return false
		}
	}
	return true
}

func assertionAlgAllowed(ctx context.Context, resolver JWKSResolver, clientID string, jws *josev4.JSONWebSignature) bool {
	algResolver, ok := resolver.(assertionSigningAlgResolver)
	if !ok {
		return true
	}
	pin, err := algResolver.AssertionSigningAlg(ctx, clientID)
	if err != nil || pin == "" {
		return err == nil
	}
	if len(jws.Signatures) == 0 {
		return false
	}
	return jws.Signatures[0].Header.Algorithm == pin
}

// verifySignature returns the verified payload on the first candidate key
// that validates the assertion, or an error if none do.
//
// Candidate selection bounds the CPU an attacker can force per request
// (the assertion endpoints run before client authentication, so a garbage
// signature against a maximally large JWKS would otherwise trigger one
// RSA verify per registered key):
//   - When the assertion header names a `kid` (RFC 7515 §4.1.4), only
//     keys bearing that kid are trialled — an O(1) lookup instead of a
//     full-keyset sweep. A named-but-unknown kid matches nothing; the
//     miss is surfaced so the caller's rotation-refetch path can retry.
//   - A kid-less assertion trials the alg/shape-matching keys but caps
//     the number of actual verifications at [jose.MaxKidlessTrialKeys],
//     mirroring the kid-less bound the JWE decrypt path already applies.
//
// Each candidate is first gated through [jose.AssertAlgKeyShape]: the
// OP's own signing keys are held to the RFC 7518 §3.3 / RFC 8725 §3.2
// floor (RSA >= 2048 bits, curve pinned to the declared alg), and a
// client registering a weaker or mismatched key MUST NOT receive a laxer
// check than the OP applies to itself. A key whose shape does not match
// the declared alg is skipped rather than handed to go-jose (and does not
// count against the kid-less trial cap), so a sub-floor key can never
// satisfy the assertion. Compliant keys are unaffected: the gate is a
// superset of what go-jose already enforces.
func verifySignature(jws *josev4.JSONWebSignature, keys *josev4.JSONWebKeySet) ([]byte, error) {
	if len(jws.Signatures) == 0 {
		return nil, errors.New("authn: assertion has no signatures")
	}
	header := jws.Signatures[0].Header
	alg := header.Algorithm

	candidates := keys.Keys
	if header.KeyID != "" {
		candidates = keys.Key(header.KeyID)
		if len(candidates) == 0 {
			// The named kid is absent from this keyset. Do NOT fall back
			// to trialling every key: that would restore the amplification
			// the kid gate removes. The caller consults the rotation
			// refetch path (assertionKIDAbsent) on this miss.
			return nil, errors.New("authn: assertion signature does not verify")
		}
	}

	trials := 0
	for i := range candidates {
		if jose.AssertAlgKeyShape(alg, candidates[i].Key) != nil {
			continue
		}
		payload, err := jws.Verify(candidates[i])
		if err == nil {
			return payload, nil
		}
		trials++
		// Bound the trial verifications regardless of whether a kid was
		// named. The kid-less branch trials every alg/shape-matching key,
		// but a kid-present branch is only bounded to a single key when the
		// keyset carries at most one key per kid — nothing enforces kid
		// uniqueness, so a client serving many same-kid, same-alg keys would
		// otherwise reopen the per-key amplification the cap exists to close.
		// A legitimate client has at most a handful of keys sharing an exact
		// kid (rotation overlap), well under the cap.
		if trials >= jose.MaxKidlessTrialKeys {
			break
		}
	}
	return nil, errors.New("authn: assertion signature does not verify")
}

// decodeAssertionClaims unmarshals the JWS payload onto AssertionClaims,
// reconciling the "aud" claim's polymorphic shape.
func decodeAssertionClaims(payload []byte) (AssertionClaims, error) {
	var raw struct {
		Iss string        `json:"iss"`
		Sub string        `json:"sub"`
		Aud audienceClaim `json:"aud"`
		Jti string        `json:"jti"`
		Iat int64         `json:"iat"`
		Nbf int64         `json:"nbf"`
		Exp int64         `json:"exp"`
	}
	if err := jsonUnmarshal(payload, &raw); err != nil {
		return AssertionClaims{}, err
	}
	return AssertionClaims{
		Issuer:    raw.Iss,
		Subject:   raw.Sub,
		Audience:  []string(raw.Aud),
		JTI:       raw.Jti,
		IssuedAt:  raw.Iat,
		NotBefore: raw.Nbf,
		ExpiresAt: raw.Exp,
	}, nil
}

// validateAssertionClaims enforces the standard claim invariants
// required by OIDC Core §9: iss == sub == clientID, aud contains one
// of the accepted audience values, jti is non-empty, exp is in the
// future, iat is not in the future (within leeway), nbf if present
// is past.
func validateAssertionClaims(claims AssertionClaims, clientID string, acceptedAud []string, now time.Time, leeway time.Duration) error {
	if claims.Issuer != clientID || claims.Subject != clientID {
		return ErrAssertionMalformed
	}
	if !audienceMatchesAny(claims.Audience, acceptedAud) {
		return ErrAssertionMalformed
	}
	if claims.JTI == "" {
		return ErrAssertionMalformed
	}
	if claims.ExpiresAt == 0 {
		return ErrAssertionMalformed
	}
	exp := time.Unix(claims.ExpiresAt, 0).UTC()
	if !now.Add(-leeway).Before(exp) {
		return ErrAssertionMalformed
	}
	if exp.After(now.Add(maxAssertionLifetime)) {
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

func assertionJTIKey(clientID, jti string) string {
	return "clientassertion:" + clientID + ":" + jti
}

func assertionJTIExpiry(claims AssertionClaims, now time.Time, leeway time.Duration) time.Time {
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC().Add(leeway)
	maxRetain := now.Add(maxAssertionLifetime + leeway)
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
		if audienceMatches(aud, e) {
			return true
		}
	}
	return false
}

// audienceMatches reports whether expected appears in aud.
func audienceMatches(aud []string, expected string) bool {
	for _, a := range aud {
		if a == expected {
			return true
		}
	}
	return false
}

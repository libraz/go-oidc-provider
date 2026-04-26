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
	leeway := v.Leeway
	if leeway <= 0 {
		leeway = 60 * time.Second
	}

	jws, _, err := jose.ParseSigned(assertion)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAssertionMalformed, err)
	}
	keys, err := v.Resolver.JWKS(ctx, clientID)
	if err != nil || keys == nil || len(keys.Keys) == 0 {
		return ErrCredentialsInvalid
	}
	payload, err := verifySignature(jws, keys)
	if err != nil {
		return ErrCredentialsInvalid
	}
	claims, err := decodeAssertionClaims(payload)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAssertionMalformed, err)
	}
	if err := validateAssertionClaims(claims, clientID, v.Audience, v.Clock(), leeway); err != nil {
		return err
	}
	if err := v.JTIStore.Mark(ctx, claims.JTI, time.Unix(claims.ExpiresAt, 0).UTC()); err != nil {
		if errors.Is(err, store.ErrAlreadyConsumed) {
			return ErrAssertionReplayed
		}
		return fmt.Errorf("authn: jti store: %w", err)
	}
	return nil
}

// verifySignature tries every key in keys and returns the verified
// payload on the first success. It returns an error if no key validates.
func verifySignature(jws *josev4.JSONWebSignature, keys *josev4.JSONWebKeySet) ([]byte, error) {
	for i := range keys.Keys {
		payload, err := jws.Verify(keys.Keys[i])
		if err == nil {
			return payload, nil
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
// required by OIDC Core §9: iss == sub == clientID, aud contains the
// expected token endpoint, jti is non-empty, exp is in the future, iat
// is not in the future (within leeway), nbf if present is past.
func validateAssertionClaims(claims AssertionClaims, clientID, expectedAud string, now time.Time, leeway time.Duration) error {
	if claims.Issuer != clientID || claims.Subject != clientID {
		return ErrAssertionMalformed
	}
	if !audienceMatches(claims.Audience, expectedAud) {
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

// audienceMatches reports whether expected appears in aud.
func audienceMatches(aud []string, expected string) bool {
	for _, a := range aud {
		if a == expected {
			return true
		}
	}
	return false
}

package tokens

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// Sentinel errors returned by [AccessTokenVerifier.Verify]. Callers MUST
// branch on these via [errors.Is] rather than string-matching the wrapped
// cause; the wrapped cause is for logging only and MUST NOT reach the
// HTTP layer untouched (RFC 6750 §3.1 limits the error codes the
// resource server may echo to the client).
var (
	// ErrAccessTokenMalformed signals that the input is not a
	// syntactically valid compact-serialised JWS, that its alg is not
	// in the allow-list (HS*, "none"), or that its "iat" claim is in
	// the future beyond the configured leeway. Verification is
	// short-circuited before any signature material is touched.
	ErrAccessTokenMalformed = errors.New("tokens: access token malformed")

	// ErrAccessTokenSignature signals that signature verification
	// failed. The cause may be a tampered signature, an unknown "kid",
	// or a header that points at a key shape this verifier cannot use.
	// The error class deliberately conflates these so the response to
	// an attacker does not leak which sub-cause produced the failure.
	ErrAccessTokenSignature = errors.New("tokens: access token signature invalid")

	// ErrAccessTokenExpired signals that the token's "exp" claim plus
	// the configured leeway is before the current clock reading.
	ErrAccessTokenExpired = errors.New("tokens: access token expired")

	// ErrAccessTokenIssuerMismatch signals that the token's "iss"
	// claim does not equal the verifier's configured issuer. The
	// resource server uses this to reject tokens that traversed the
	// wrong OP — defence-in-depth against confused-deputy bugs in
	// multi-tenant deployments.
	ErrAccessTokenIssuerMismatch = errors.New("tokens: access token issuer mismatch")

	// ErrAccessTokenAudienceMismatch is exported for callers that
	// validate audience after Verify returns. [AccessTokenVerifier]
	// itself does not raise this error — see the godoc on Verify.
	ErrAccessTokenAudienceMismatch = errors.New("tokens: access token audience mismatch")
)

// Clock is the package-local view of [internal/timex.Clock]. It is
// duplicated here (rather than imported transitively through op/) so
// this package keeps the same SigningKey/Entry split it already uses
// for keys: the public op/ namespace converts its [op.Clock] to this
// type at the boundary. Implementations MUST be safe for concurrent
// use. A nil [AccessTokenVerifier.Clock] falls back to
// [internal/timex.SystemClock] — see [AccessTokenVerifier.now].
type Clock interface {
	Now() time.Time
}

// AccessTokenVerifier introspects a JWT-shaped access token (RFC 9068)
// against a [keys.Set]. The verifier is stateless apart from its
// configuration and is safe for concurrent use; the upcoming /userinfo
// handler builds one at startup and shares it across requests.
type AccessTokenVerifier struct {
	// Keys is the set of public keys used to verify the JWS. The
	// active key plus all retiring keys MUST be present so that
	// tokens minted before a rotation continue to verify.
	Keys *keys.Set

	// Issuer is the value the "iss" claim is compared against. An
	// empty Issuer disables the check; callers MUST set it for any
	// production deployment.
	Issuer string

	// Clock supplies the current wall-clock reading. A nil Clock
	// falls back to [internal/timex.SystemClock].
	Clock Clock

	// Leeway is the symmetric tolerance applied to the "exp" and
	// "iat" comparisons. Two minutes is the upper bound recommended
	// by RFC 7519 §4.1.4; the verifier does not enforce a maximum
	// because resource-server policy varies.
	Leeway time.Duration
}

// Verify parses raw, validates its signature, issuer, and time-bound
// claims, and returns the decoded claims plus the kid of the key that
// verified the signature. The returned claims share the same wire-form
// rules as [SignAccessToken]: "scope" is split back into a slice and
// "aud" accepts both the bare-string and array shapes that RFC 7519
// §4.1.3 allows.
//
// Verify intentionally does NOT validate the audience claim against an
// expected value. Audience policy varies by caller — the /userinfo
// handler validates that aud contains the issuer URL, while a resource
// server validates that aud contains its own resource identifier — so
// the check belongs to the layer that knows the answer. Callers that
// want the assertion can compare claims.Audience after Verify returns
// and surface [ErrAccessTokenAudienceMismatch] on failure.
func (v *AccessTokenVerifier) Verify(raw string) (*AccessTokenClaims, string, error) {
	jws, _, err := jose.ParseSigned(raw)
	if err != nil {
		// jose.ParseSigned wraps both alg-not-allowed and parse
		// failures before any signature material is touched, so both
		// shapes map onto ErrAccessTokenMalformed (NOT
		// ErrAccessTokenSignature). HS* / "none" therefore surface as
		// malformed, which is the taxonomy RFC 8725 §2.1 prescribes
		// for downgrade rejections.
		return nil, "", fmt.Errorf("%w: %w", ErrAccessTokenMalformed, err)
	}

	kid := jws.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, "", ErrAccessTokenSignature
	}
	entry, ok := v.Keys.Find(kid)
	if !ok {
		return nil, "", ErrAccessTokenSignature
	}

	payload, err := jws.Verify(entry.Signer.Public())
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrAccessTokenSignature, err)
	}

	claims, err := decodeAccessTokenClaims(payload)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrAccessTokenMalformed, err)
	}

	if v.Issuer != "" && claims.Issuer != v.Issuer {
		return nil, "", ErrAccessTokenIssuerMismatch
	}

	now := v.now()
	leeway := v.Leeway

	if claims.ExpiresAt > 0 {
		exp := time.Unix(claims.ExpiresAt, 0).Add(leeway)
		if now.After(exp) {
			return nil, "", ErrAccessTokenExpired
		}
	}
	if claims.IssuedAt > 0 {
		iat := time.Unix(claims.IssuedAt, 0)
		if iat.After(now.Add(leeway)) {
			return nil, "", fmt.Errorf("%w: iat in the future", ErrAccessTokenMalformed)
		}
	}

	return claims, kid, nil
}

// now reads the verifier's clock, falling back to the system clock when
// the field is unset. Centralised so the nil check happens in one
// place; returning [time.Time] (not [Clock]) keeps the [ireturn] lint
// satisfied without enumerating this package in its allow-list.
func (v *AccessTokenVerifier) now() time.Time {
	if v.Clock == nil {
		return timex.SystemClock.Now()
	}
	return v.Clock.Now()
}

// accessTokenWire mirrors [AccessTokenClaims] for decoding. The "aud"
// field accepts either a string or a []string per RFC 7519 §4.1.3 and
// is therefore decoded as raw JSON; the "scope" claim is the canonical
// space-delimited string form (RFC 6749 §3.3) which we split back into
// the public slice shape.
type accessTokenWire struct {
	Issuer       string            `json:"iss"`
	Subject      string            `json:"sub"`
	Audience     json.RawMessage   `json:"aud"`
	ClientID     string            `json:"client_id"`
	IssuedAt     int64             `json:"iat"`
	ExpiresAt    int64             `json:"exp"`
	JTI          string            `json:"jti"`
	Scope        string            `json:"scope"`
	AuthTime     int64             `json:"auth_time"`
	ACR          string            `json:"acr"`
	AMR          []string          `json:"amr"`
	Confirmation map[string]string `json:"cnf"`
	Gid          string            `json:"gid,omitempty"`
}

// decodeAccessTokenClaims parses payload into an [AccessTokenClaims].
// It rejects payloads that are not valid JSON and audience claims that
// are neither a JSON string nor a JSON array of strings. Unknown
// fields are tolerated because RFC 9068 §2 explicitly allows extension
// claims; verification only enforces shapes for the claims this
// package projects onto [AccessTokenClaims].
func decodeAccessTokenClaims(payload []byte) (*AccessTokenClaims, error) {
	var w accessTokenWire
	if err := json.NewDecoder(bytes.NewReader(payload)).Decode(&w); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	aud, err := decodeAudience(w.Audience)
	if err != nil {
		return nil, err
	}

	out := &AccessTokenClaims{
		Issuer:       w.Issuer,
		Subject:      w.Subject,
		Audience:     aud,
		ClientID:     w.ClientID,
		IssuedAt:     w.IssuedAt,
		ExpiresAt:    w.ExpiresAt,
		JTI:          w.JTI,
		Scope:        splitScope(w.Scope),
		AuthTime:     w.AuthTime,
		ACR:          w.ACR,
		AMR:          w.AMR,
		Confirmation: w.Confirmation,
		GrantID:      w.Gid,
	}
	return out, nil
}

// decodeAudience handles the dual shape RFC 7519 §4.1.3 mandates: the
// "aud" claim is either a JSON string or a JSON array of strings. A
// nil/empty raw message decodes to a nil slice so callers can treat
// "audience absent" identically to "audience empty".
func decodeAudience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil, nil
		}
		return []string{single}, nil
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err != nil {
		return nil, fmt.Errorf("decode aud: %w", err)
	}
	return multi, nil
}

// splitScope inverts [joinScope]. RFC 6749 §3.3 separates scopes with a
// single ASCII space; consecutive spaces (which the spec disallows) are
// tolerated here by dropping empty fields so a misbehaving issuer does
// not propagate empty scope strings into the public slice.
func splitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	parts := strings.Split(scope, " ")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

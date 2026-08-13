package tokens

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
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

	// ErrAccessTokenTypeMismatch signals that the JOSE "typ" header is
	// not exactly "at+jwt" (RFC 9068 §2.1 / §4). The check defends
	// against an ID token (typ=JWT) being presented at a resource-server
	// endpoint that consumes access tokens: even though both are signed
	// by the same OP key, the "typ" pin keeps cross-format substitution
	// out of the protocol surface. The resource server collapses this
	// onto invalid_token at the wire layer (RFC 6750 §3.1).
	ErrAccessTokenTypeMismatch = errors.New("tokens: access token typ header is not at+jwt")
)

// DefaultLeeway is the symmetric tolerance every in-library
// [AccessTokenVerifier] applies to the "exp" and "iat" comparisons when
// its own [AccessTokenVerifier.Leeway] is left at zero.
//
// It lives here, next to the field it feeds, because it has to be one
// value rather than one value per endpoint: /userinfo, /introspect,
// /revoke and the token-exchange subject-token lookup all answer "is
// this access token still valid?" about the same token, and a
// deployment with clock skew gets contradictory answers the moment
// those numbers drift apart. Thirty seconds sits well below the RFC
// 7519 §4.1.4 recommended ceiling, so a skewed peer retries quickly
// without widening the replay window on a stolen token.
const DefaultLeeway = 30 * time.Second

// Clock is the package-local view of [timex.Clock]. It is
// duplicated here (rather than imported transitively through op/) so
// this package keeps the same SigningKey/Entry split it already uses
// for keys: the public op/ namespace converts its [op.Clock] to this
// type at the boundary. Implementations MUST be safe for concurrent
// use. A nil [AccessTokenVerifier.Clock] falls back to
// [timex.SystemClock] — see [AccessTokenVerifier.now].
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
	// falls back to [timex.SystemClock].
	Clock Clock

	// Leeway is the symmetric tolerance applied to the "exp" and
	// "iat" comparisons. Two minutes is the upper bound recommended
	// by RFC 7519 §4.1.4; the verifier does not enforce a maximum
	// because resource-server policy varies.
	//
	// Every construction site inside this library resolves a zero value
	// to [DefaultLeeway]. That is not a convenience: an access token's
	// validity is a property of the token, not of the endpoint that
	// happens to inspect it, so the surfaces that verify one have to
	// agree on the tolerance or the same token becomes live at one and
	// dead at another under the very clock skew the tolerance exists
	// for.
	Leeway time.Duration

	// RequireJTI, when true, makes [AccessTokenVerifier.Verify]
	// reject a token whose "jti" claim is missing or empty. The
	// option is wired by callers whose revocation strategy keys on
	// jti (registry / denylist) — without a jti those callers
	// cannot tell a revoked token from a fresh one, so accepting
	// the token would silently bypass revocation.
	//
	// Every access-token-consuming endpoint sets it from the
	// configured [store.AccessTokenRevocationStrategy]: on for
	// anything other than [store.RevocationStrategyNone]. Both
	// non-None strategies have a path that can only be answered
	// through the jti —
	//
	//   - [store.RevocationStrategyJTIRegistry] looks the token up by
	//     jti alone, so an empty one reads as "no row, not revoked".
	//   - [store.RevocationStrategyGrantTombstone] covers a
	//     grant-bound token through its "gid" claim, but a grantless
	//     one (client_credentials mints no gid) is reachable only
	//     through the jti denylist row that /revocation wrote.
	//
	// [store.RevocationStrategyNone] consults no per-token state at
	// all, so requiring a jti there would reject tokens for no gain.
	//
	// The flag stays opt-in at this layer rather than defaulting to
	// true because the verifier is also constructed by callers that
	// have no revocation strategy to consult, and the spec
	// (RFC 9068 §2.2) lists jti as RECOMMENDED rather than REQUIRED.
	RequireJTI bool
}

// Verify parses raw, validates its signature, issuer, and time-bound
// claims, and returns the decoded claims plus the kid of the key that
// verified the signature. The returned claims share the same wire-form
// rules as [SignAccessToken]: "scope" is split back into a slice and
// "aud" accepts both the bare-string and array shapes that RFC 7519
// §4.1.3 allows.
//
// Verify intentionally does NOT validate the audience claim against an
// expected value. Audience policy varies by caller and is enforced one
// layer up: the /userinfo handler calls its own enforceAudience to
// require aud-contains-issuer, while a downstream resource server
// validates that aud contains its own resource identifier. Callers
// that want the assertion compare claims.Audience after Verify
// returns and surface [ErrAccessTokenAudienceMismatch] on failure.
//
// ctx is the context of the request that presented raw. Verification
// does no I/O and does not observe cancellation; the context exists so
// the keyset's retired-kid audit event — fired when the token names a
// kid the OP has stopped trusting — reaches the embedder's sink with
// the presenting request's correlation attached.
func (v *AccessTokenVerifier) Verify(ctx context.Context, raw string) (*AccessTokenClaims, string, error) {
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

	// RFC 9068 §2.1 mandates typ="at+jwt" so a resource server can
	// distinguish a JWT-shaped access token from an ID token. The pin
	// MUST land before signature verification so a token with the
	// wrong typ does not contribute timing data about key state.
	if !accessTokenTypHeaderMatches(jws.Signatures[0]) {
		return nil, "", ErrAccessTokenTypeMismatch
	}

	kid := jws.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, "", ErrAccessTokenSignature
	}
	entry, ok := v.Keys.Find(ctx, kid)
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

	if err := v.requireClaims(claims); err != nil {
		return nil, "", err
	}

	if v.Issuer != "" && claims.Issuer != v.Issuer {
		return nil, "", ErrAccessTokenIssuerMismatch
	}

	now := v.now()
	leeway := v.Leeway

	exp := time.Unix(claims.ExpiresAt, 0).Add(leeway)
	if now.After(exp) {
		return nil, "", ErrAccessTokenExpired
	}
	iat := time.Unix(claims.IssuedAt, 0)
	if iat.After(now.Add(leeway)) {
		return nil, "", fmt.Errorf("%w: iat in the future", ErrAccessTokenMalformed)
	}

	return claims, kid, nil
}

// requireClaims enforces that a JWT-shaped access token carries iss,
// sub, aud, client_id, iat, and exp. A production-issued token under
// the OP's signing key always populates these (RFC 9068 §2.2 marks
// them REQUIRED), so a missing claim indicates either a malformed
// token or an internal bug in a custom grant — both of which the
// verifier MUST refuse rather than silently degrade. The check
// fires before the issuer / time-bound comparisons so a verifier
// wired against a custom-grant bug surfaces the missing field
// instead of the downstream "issuer mismatch" / "expired" red
// herring.
//
// jti is governed by [AccessTokenVerifier.RequireJTI] because RFC 9068
// §2.2 marks it RECOMMENDED rather than REQUIRED; callers whose
// revocation strategy keys on jti opt in explicitly so a verifier
// constructed without revocation wiring continues to accept the
// tokens it used to accept.
//
// Every failure surface collapses onto [ErrAccessTokenMalformed]
// (NOT [ErrAccessTokenSignature]) so the resource-server response
// stays at the RFC 6750 §3.1 invalid_token taxonomy without leaking
// which specific claim was missing. The wrapped cause names the
// claim for log diagnosis only.
func (v *AccessTokenVerifier) requireClaims(c *AccessTokenClaims) error {
	switch {
	case c.Issuer == "":
		return fmt.Errorf("%w: iss claim missing", ErrAccessTokenMalformed)
	case c.Subject == "":
		return fmt.Errorf("%w: sub claim missing", ErrAccessTokenMalformed)
	case len(c.Audience) == 0:
		return fmt.Errorf("%w: aud claim missing", ErrAccessTokenMalformed)
	case c.ClientID == "":
		return fmt.Errorf("%w: client_id claim missing", ErrAccessTokenMalformed)
	case c.IssuedAt <= 0:
		return fmt.Errorf("%w: iat claim missing", ErrAccessTokenMalformed)
	case c.ExpiresAt <= 0:
		return fmt.Errorf("%w: exp claim missing", ErrAccessTokenMalformed)
	}
	if v.RequireJTI && c.JTI == "" {
		return fmt.Errorf("%w: jti claim missing", ErrAccessTokenMalformed)
	}
	return nil
}

// accessTokenTypHeaderMatches reports whether sig carries the canonical
// "at+jwt" JOSE typ header (RFC 9068 §2.1). The value lives in the
// protected (or unprotected) ExtraHeaders map because go-jose only
// promotes "kid", "alg", "jwk", and "nonce" into the typed [Header]
// struct. The check is case-sensitive: RFC 9068 fixes the literal
// media type "at+jwt".
func accessTokenTypHeaderMatches(sig josev4.Signature) bool {
	for _, hdr := range []map[josev4.HeaderKey]any{sig.Protected.ExtraHeaders, sig.Header.ExtraHeaders} {
		if v, ok := hdr[josev4.HeaderType]; ok {
			if s, ok := v.(string); ok {
				return s == accessTokenTypeHeader
			}
			return false
		}
	}
	return false
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
	Issuer               string            `json:"iss"`
	Subject              string            `json:"sub"`
	Audience             json.RawMessage   `json:"aud"`
	ClientID             string            `json:"client_id"`
	IssuedAt             int64             `json:"iat"`
	ExpiresAt            int64             `json:"exp"`
	JTI                  string            `json:"jti"`
	Scope                string            `json:"scope"`
	AuthTime             int64             `json:"auth_time"`
	ACR                  string            `json:"acr"`
	AMR                  []string          `json:"amr"`
	Confirmation         map[string]string `json:"cnf"`
	Gid                  string            `json:"gid,omitempty"`
	AuthorizationDetails []map[string]any  `json:"authorization_details,omitempty"`
}

// decodeAccessTokenClaims parses payload into an [AccessTokenClaims].
// It rejects payloads that are not valid JSON and audience claims that
// are neither a JSON string nor a JSON array of strings. Unknown
// fields are tolerated because RFC 9068 §2 explicitly allows extension
// claims; verification only enforces shapes for the claims this
// package projects onto [AccessTokenClaims].
func decodeAccessTokenClaims(payload []byte) (*AccessTokenClaims, error) {
	var w accessTokenWire
	dec := json.NewDecoder(bytes.NewReader(payload))
	// UseNumber preserves integer fidelity for the authorization_details
	// claim (the only any-typed target); the other claims are typed.
	dec.UseNumber()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	aud, err := decodeAudience(w.Audience)
	if err != nil {
		return nil, err
	}

	out := &AccessTokenClaims{
		Issuer:               w.Issuer,
		Subject:              w.Subject,
		Audience:             aud,
		ClientID:             w.ClientID,
		IssuedAt:             w.IssuedAt,
		ExpiresAt:            w.ExpiresAt,
		JTI:                  w.JTI,
		Scope:                oidcscope.Parse(w.Scope),
		AuthTime:             w.AuthTime,
		ACR:                  w.ACR,
		AMR:                  w.AMR,
		Confirmation:         w.Confirmation,
		GrantID:              w.Gid,
		AuthorizationDetails: w.AuthorizationDetails,
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

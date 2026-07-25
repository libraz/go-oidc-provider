// Package tokens builds and signs the JWTs the OP issues at the token
// endpoint: id_token (OIDC Core 1.0 §2) and JWT-formatted access_token
// (RFC 9068). The package is a pure transformation: it consumes a fully-
// resolved claims bundle and a key from [internal/keys] and emits a
// compact-serialised JWS string. It never reads the wall clock, never
// touches storage, and never mutates its inputs.
//
// The HTTP layer composes this package with its grant exchanger, the
// session store, and the userinfo claim resolver to produce the final
// response body. Splitting the signing surface from the orchestration
// keeps the JWS / claims correctness testable without spinning up an
// httptest server.
//
// # Algorithm policy
//
// The OP signs with ES256 and only ES256 (RFC 7518 §3.4). The package routes through
// [internal/jose] / [internal/keys] so the algorithm allow-list and key
// shape are enforced in one place; supplying a non-ECDSA key fails fast.
//
// # Hash claims
//
// id_token MAY carry "at_hash" and "c_hash" (OIDC Core 1.0 §3.1.3.6 and
// §3.3.2.10). The package exposes [Hash] so callers can compute these
// the way the spec expects (left-most half of the alg's digest, base64url
// without padding).
package tokens

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

// SigningKey is the package-private view of a signing key. The package
// never imports op/, so callers convert their public Keyset to a
// SigningKey at the boundary.
type SigningKey struct {
	// KeyID becomes the "kid" header on every emitted JWS.
	KeyID string

	// Signer is the private key. v1.0 requires ECDSA P-256.
	Signer crypto.Signer

	// Alg is the JWS signing algorithm advertised on every emitted JWS and
	// used to select the matching SHA digest for [HashForAlg]. Empty
	// defaults to "ES256" (the single-alg policy), so callers
	// that build a SigningKey directly stay correct.
	Alg string
}

// fromInternalEntry converts an [internal/keys.Entry] to the package-
// local [SigningKey]. The conversion is trivial; the helper exists so
// the HTTP layer can keep the conversion in one place.
func fromInternalEntry(e keys.Entry) SigningKey {
	return SigningKey{KeyID: e.KeyID, Signer: e.Signer, Alg: string(josev4.ES256)}
}

// IDTokenClaims is the OIDC Core 1.0 §2 claim set. Fields with omitempty
// JSON tags are dropped from the wire form when zero so the encoded
// JWT matches the spec's expectations.
type IDTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	AuthTime  int64    `json:"auth_time,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	ACR       string   `json:"acr,omitempty"`
	AMR       []string `json:"amr,omitempty"`
	AZP       string   `json:"azp,omitempty"`
	AtHash    string   `json:"at_hash,omitempty"`
	CHash     string   `json:"c_hash,omitempty"`
	SID       string   `json:"sid,omitempty"`

	// Extra carries non-standard claims (custom scope claims, profile
	// fields if the OP embeds them in the id_token). The encoder
	// flattens this map alongside the standard fields; collisions with
	// standard claim names are rejected by [SignIDToken].
	Extra map[string]any `json:"-"`
}

// AccessTokenClaims is the JWT-shaped access token (RFC 9068). The
// "scope" claim is encoded as the space-delimited string the spec
// mandates; callers pass the slice and the encoder handles the join.
type AccessTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	JTI       string   `json:"jti"`
	Scope     []string `json:"-"`
	AuthTime  int64    `json:"auth_time,omitempty"`
	ACR       string   `json:"acr,omitempty"`
	AMR       []string `json:"amr,omitempty"`

	// Confirmation is the RFC 7800 "cnf" claim. The OP populates it
	// when a token is sender-constrained: "jkt" for DPoP-bound tokens
	// (RFC 9449 §6) and, in a future task, "x5t#S256" for mTLS-bound
	// tokens (RFC 8705 §3). Empty / nil means "bearer", which is the
	// v1.0 default. The map shape keeps the wire format forward-
	// compatible with both binding methods landing in the same claim.
	Confirmation map[string]string `json:"-"`

	// GrantID is the "gid" private claim (RFC 7519 §4.3 Private Claim
	// Names) that ADR 0025 introduces to wire grant-tombstone
	// revocation through the JWT itself. The claim is meaningful only
	// to the issuing OP — resource servers MUST ignore it per
	// RFC 7519 §4.3 — so the wire form uses the short, unallocated
	// name "gid" rather than a URI-form private claim. The field is
	// indirected through [mergeAccessTokenClaims] (the same pattern
	// as Scope and Confirmation) and the merge applies omitempty
	// semantics so legacy strategies that never populate GrantID
	// emit unchanged wire bytes.
	GrantID string `json:"-"`

	// AuthorizationDetails is the RFC 9396 authorization_details claim
	// (RFC 9068 §2.2.3): when the grant carries authorization_details, the
	// JWT access token echoes them so a resource server can read the rich
	// authorization directly off the token. Nil / empty omits the claim.
	// Indirected through [mergeAccessTokenClaims] like Scope / GrantID.
	AuthorizationDetails []map[string]any `json:"-"`

	// Extra carries non-standard claims the caller wants stamped on
	// the JWT alongside the standard set. The encoder flattens this
	// map after the typed fields; collisions with standard claim
	// names are rejected by [SignAccessToken] so silent overwrites
	// of "sub" / "exp" / "cnf" cannot ship.
	Extra map[string]any `json:"-"`
}

// ErrSignerInvalid is returned when SignIDToken / SignAccessToken is
// asked to sign with a SigningKey whose Signer is nil.
var ErrSignerInvalid = errors.New("tokens: SigningKey has nil Signer")

// ErrHashAlgUnsupported is returned by [HashForAlg] when no OIDC hash-claim
// digest is defined for the supplied JWS signing algorithm.
var ErrHashAlgUnsupported = errors.New("tokens: unsupported hash-claim alg")

// idTokenTypeHeader is the value of the "typ" JOSE header for ID Tokens
// (OIDC Core 1.0 §2). RP libraries that strict-check the type expect
// the legacy "JWT" value here.
const idTokenTypeHeader = "JWT"

// accessTokenTypeHeader is the value of the "typ" JOSE header for
// JWT-shaped access tokens. RFC 9068 §2.1 requires the explicit
// "at+jwt" media type so a resource server can distinguish access
// tokens from ID tokens or other JWTs at parse time, frustrating
// cross-token confusion attacks (RFC 9068 §5).
const accessTokenTypeHeader = "at+jwt"

// SignIDToken serialises claims as an ES256-signed compact JWS. The
// "kid" header is set to key.KeyID; the "typ" header is "JWT" so RP
// libraries that strict-check the type do not reject the token. The
// expiry is encoded as an integer Unix timestamp.
//
// The function returns an error when claims.Extra contains a key that
// would clobber a standard claim — silently overwriting "sub" or "exp"
// in id_tokens has historically been a source of subtle confused-
// deputy bugs, so the package refuses to do it.
func SignIDToken(key SigningKey, claims IDTokenClaims) (string, error) {
	if key.Signer == nil {
		return "", ErrSignerInvalid
	}
	if err := validateNoStandardCollisions(claims.Extra, idTokenStandardKeys); err != nil {
		return "", err
	}
	signer, err := newSigner(key, idTokenTypeHeader)
	if err != nil {
		return "", err
	}
	merged := mergeIDTokenClaims(claims)
	return serializeJWT(signer, merged)
}

// SignAccessToken serialises claims as an ES256-signed compact JWS. It
// follows the same invariants as [SignIDToken]; "scope" is encoded as
// the canonical space-delimited string per RFC 6749 §3.3. The "typ"
// header is fixed to "at+jwt" per RFC 9068 §2.1: a resource server
// MUST reject any access-token JWT whose typ is not exactly "at+jwt"
// (or its case-insensitive equivalent), which structurally prevents
// an attacker from substituting an ID token for an access token.
func SignAccessToken(key SigningKey, claims AccessTokenClaims) (string, error) {
	if key.Signer == nil {
		return "", ErrSignerInvalid
	}
	if err := validateNoStandardCollisions(claims.Extra, accessTokenStandardKeys); err != nil {
		return "", err
	}
	signer, err := newSigner(key, accessTokenTypeHeader)
	if err != nil {
		return "", err
	}
	merged := mergeAccessTokenClaims(claims)
	return serializeJWT(signer, merged)
}

// Hash is a convenience for tests and fixtures pinned to the ES256
// signing policy; production callers MUST go through [HashForAlg] with the
// active SigningKey.Alg so the digest follows the signing algorithm if
// future versions admit anything beyond ES256 (OIDC Core 1.0 §3.1.3.6).
func Hash(input string) string {
	out, _ := HashForAlg(input, "ES256")
	return out
}

// HashForAlg computes the at_hash / c_hash digest OIDC Core 1.0 §3.1.3.6
// asks for: hash the input with the digest implied by the JWS signing
// algorithm, take the left-most half, and base64url-encode without padding.
func HashForAlg(input, alg string) (string, error) {
	var sum []byte
	switch {
	case strings.HasSuffix(alg, "256"):
		raw := sha256.Sum256([]byte(input))
		sum = raw[:]
	case strings.HasSuffix(alg, "384"):
		raw := sha512.Sum384([]byte(input))
		sum = raw[:]
	case strings.HasSuffix(alg, "512"):
		raw := sha512.Sum512([]byte(input))
		sum = raw[:]
	default:
		return "", fmt.Errorf("%w: %q", ErrHashAlgUnsupported, alg)
	}
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}

// idTokenStandardKeys is the set of claim names [SignIDToken] manages
// itself. Callers that pass [IDTokenClaims.Extra] MUST NOT include any
// of these keys.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var idTokenStandardKeys = map[string]struct{}{
	"iss":       {},
	"sub":       {},
	"aud":       {},
	"iat":       {},
	"exp":       {},
	"auth_time": {},
	"nonce":     {},
	"acr":       {},
	"amr":       {},
	"azp":       {},
	"at_hash":   {},
	"c_hash":    {},
	"sid":       {},
}

// accessTokenStandardKeys is the set of claim names [SignAccessToken]
// manages itself. Callers that pass [AccessTokenClaims.Extra] MUST NOT
// include any of these keys; the OP refuses to silently overwrite the
// sender-constraint cnf claim or the spec-mandated iss/sub/aud/exp.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var accessTokenStandardKeys = map[string]struct{}{
	"iss":                   {},
	"sub":                   {},
	"aud":                   {},
	"client_id":             {},
	"iat":                   {},
	"exp":                   {},
	"jti":                   {},
	"scope":                 {},
	"auth_time":             {},
	"acr":                   {},
	"amr":                   {},
	"cnf":                   {},
	"gid":                   {},
	"authorization_details": {},
}

// validateNoStandardCollisions returns an error when extra contains a
// key in standard. The error names the offending key so the caller can
// fix the call site without guessing.
func validateNoStandardCollisions(extra map[string]any, standard map[string]struct{}) error {
	for k := range extra {
		if _, dup := standard[k]; dup {
			return fmt.Errorf("tokens: Extra claim %q collides with a standard claim", k)
		}
	}
	return nil
}

// mergeIDTokenClaims flattens the typed claims and the Extra map onto
// a single map[string]any the JWT serialiser can encode.
func mergeIDTokenClaims(c IDTokenClaims) map[string]any {
	out := map[string]any{
		"iss": c.Issuer,
		"sub": c.Subject,
		"aud": encodeAudience(c.Audience),
		"iat": c.IssuedAt,
		"exp": c.ExpiresAt,
	}
	if c.AuthTime != 0 {
		out["auth_time"] = c.AuthTime
	}
	if c.Nonce != "" {
		out["nonce"] = c.Nonce
	}
	if c.ACR != "" {
		out["acr"] = c.ACR
	}
	if len(c.AMR) > 0 {
		out["amr"] = c.AMR
	}
	if c.AZP != "" {
		out["azp"] = c.AZP
	}
	if c.AtHash != "" {
		out["at_hash"] = c.AtHash
	}
	if c.CHash != "" {
		out["c_hash"] = c.CHash
	}
	if c.SID != "" {
		out["sid"] = c.SID
	}
	for k, v := range c.Extra {
		out[k] = v
	}
	return out
}

// mergeAccessTokenClaims flattens the access-token claims onto a map
// the JWT serialiser can encode, joining the scope slice into the
// canonical space-delimited form.
func mergeAccessTokenClaims(c AccessTokenClaims) map[string]any {
	out := map[string]any{
		"iss":       c.Issuer,
		"sub":       c.Subject,
		"aud":       encodeAudience(c.Audience),
		"client_id": c.ClientID,
		"iat":       c.IssuedAt,
		"exp":       c.ExpiresAt,
	}
	if c.JTI != "" {
		out["jti"] = c.JTI
	}
	if len(c.Scope) > 0 {
		out["scope"] = joinScope(c.Scope)
	}
	if c.AuthTime != 0 {
		out["auth_time"] = c.AuthTime
	}
	if c.ACR != "" {
		out["acr"] = c.ACR
	}
	if len(c.AMR) > 0 {
		out["amr"] = c.AMR
	}
	if cnf := encodeConfirmation(c.Confirmation); cnf != nil {
		out["cnf"] = cnf
	}
	if c.GrantID != "" {
		out["gid"] = c.GrantID
	}
	if len(c.AuthorizationDetails) > 0 {
		out["authorization_details"] = c.AuthorizationDetails
	}
	for k, v := range c.Extra {
		out[k] = v
	}
	return out
}

// encodeConfirmation projects the typed [AccessTokenClaims.Confirmation]
// map onto the wire shape RFC 7800 §3.1 prescribes. An empty / nil
// input returns nil so the caller can guard the "cnf" assignment with
// a simple non-nil check.
func encodeConfirmation(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if v == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// encodeAudience returns the wire form of the "aud" claim. RFC 7519
// §4.1.3 allows either a single string or an array; the OP emits the
// array form whenever there is more than one audience and a bare
// string otherwise so common RP libraries (which often expect a string
// for the single-aud case) round-trip cleanly.
func encodeAudience(aud []string) any {
	switch len(aud) {
	case 0:
		return ""
	case 1:
		return aud[0]
	default:
		return aud
	}
}

// joinScope concatenates the scope slice with single-space separators.
// The function is in this package so the encoding rule is colocated
// with the only place that emits a "scope" JWT claim.
func joinScope(scopes []string) string {
	return strings.Join(scopes, " ")
}

// newSigner builds the [josev4.Signer] used by [SignIDToken] and
// [SignAccessToken]. The signer is created on every call (rather than
// cached) because go-jose's signer holds a reference to the key plus
// alg-specific state; sharing a signer across goroutines is allowed
// but the per-call cost is negligible compared to the Sign step.
//
// typ selects the JOSE "typ" header: "JWT" for ID tokens (OIDC Core
// 1.0 §2) and "at+jwt" for JWT-shaped access tokens (RFC 9068 §2.1).
// Splitting the value at the call site keeps the cross-token
// confusion guard structural rather than relying on a runtime check. The
// returned interface is intentional: josev4.Signer is the third-party
// package's contract for stateful JWS signing.
func newSigner(key SigningKey, typ string) (josev4.Signer, error) {
	alg := josev4.SignatureAlgorithm(key.Alg)
	if alg == "" {
		alg = josev4.ES256
	}
	sk := josev4.SigningKey{
		Algorithm: alg,
		Key: josev4.JSONWebKey{
			Key:       key.Signer,
			KeyID:     key.KeyID,
			Algorithm: string(alg),
			Use:       "sig",
		},
	}
	opts := (&josev4.SignerOptions{}).WithType(josev4.ContentType(typ))
	signer, err := josev4.NewSigner(sk, opts)
	if err != nil {
		return nil, fmt.Errorf("tokens: build signer: %w", err)
	}
	return signer, nil
}

// serializeJWT runs the claims through the [jwt] builder and returns
// the compact-serialised string.
func serializeJWT(signer josev4.Signer, claims map[string]any) (string, error) {
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("tokens: serialise: %w", err)
	}
	return out, nil
}

// FromInternalEntry is the exported converter the HTTP layer uses to
// translate an [internal/keys.Entry] into this package's local
// [SigningKey]. Inlining the function on every call site would create
// noise; centralising it here keeps the boundary single-sourced.
func FromInternalEntry(e keys.Entry) SigningKey { return fromInternalEntry(e) }

// ExpiresIn returns now+ttl as an integer Unix timestamp suitable for
// the "exp" claim. It exists so callers do not have to remember the
// Unix-second granularity (RFC 7519 §2 mandates seconds-since-epoch).
func ExpiresIn(now time.Time, ttl time.Duration) int64 {
	return now.Add(ttl).Unix()
}

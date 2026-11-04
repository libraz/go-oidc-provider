package rs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// Verify authenticates the access token r carries in its Authorization
// header (RFC 6750 §2.1; the DPoP scheme of RFC 9449 §7.1 is accepted
// too). On success it returns the token; on failure the error is always
// an [*Error] whose challenge reflects the scheme the client used.
//
// A JWT is verified locally against the issuer's JWK Set; any other token
// goes to introspection when [Config.Introspection] is set and is rejected
// as invalid_token otherwise. A JWT that fails verification is not retried
// through introspection.
//
// The DPoP proof's htu is compared with the URL r was addressed to, built
// from r.URL, r.Host and r.TLS. Behind a reverse proxy that rewrites the
// host or terminates TLS, restore those fields before calling Verify.
//
// Stable since v1.5.
func (v *Verifier) Verify(r *http.Request) (*Token, error) {
	tok, e := v.verify(r)
	if e != nil {
		return nil, e
	}
	return tok, nil
}

// verify is [Verifier.Verify] with the concrete error type, so the
// middleware can decorate it without a type assertion.
func (v *Verifier) verify(r *http.Request) (*Token, *Error) {
	scheme, raw, e := parseAuthorization(r)
	if e == nil {
		var tok *Token
		tok, e = v.verifyToken(r, scheme, raw)
		if e == nil {
			return tok, nil
		}
	}
	return nil, v.decorate(e, scheme)
}

// decorate stamps the verifier-wide challenge inputs onto e.
func (v *Verifier) decorate(e *Error, scheme authScheme) *Error {
	e.mode = v.dpopMode
	e.realm = v.audience
	e.scheme = scheme
	return e
}

// parseAuthorization extracts the scheme and token from the single
// Authorization header. The scheme name is case-insensitive (RFC 9110
// §11.1) and the credentials must be a token68 (RFC 9110 §11.2).
func parseAuthorization(r *http.Request) (authScheme, string, *Error) {
	values := r.Header.Values("Authorization")
	switch len(values) {
	case 0:
		return schemeNone, "", &Error{Status: http.StatusUnauthorized, Description: "no access token presented"}
	case 1:
	default:
		return schemeOther, "", invalidRequest("more than one Authorization header")
	}
	name, rest, _ := strings.Cut(values[0], " ")
	var scheme authScheme
	switch strings.ToLower(name) {
	case "bearer":
		scheme = schemeBearer
	case "dpop":
		scheme = schemeDPoP
	default:
		// An unsupported scheme counts as no credentials (RFC 6750 §3.1).
		return schemeNone, "", &Error{Status: http.StatusUnauthorized, Description: "no access token presented"}
	}
	raw := strings.TrimLeft(rest, " ")
	if !isToken68(raw) {
		return scheme, "", invalidRequest("access token is missing or malformed")
	}
	return scheme, raw, nil
}

// isToken68 reports whether s is a non-empty RFC 9110 §11.2 token68.
func isToken68(s string) bool {
	body := strings.TrimRight(s, "=")
	if body == "" {
		return false
	}
	for i := range len(body) {
		c := body[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '-', c == '.', c == '_', c == '~', c == '+', c == '/':
		default:
			return false
		}
	}
	return true
}

// verifyToken validates raw and the request's proof of possession.
func (v *Verifier) verifyToken(r *http.Request, scheme authScheme, raw string) (*Token, *Error) {
	ctx := r.Context()
	now := v.clock.Now()
	var (
		claims *tokens.AccessTokenClaims
		all    map[string]any
		e      *Error
	)
	if endpointsupport.LooksLikeJWT(raw) {
		claims, all, e = v.verifyJWT(ctx, raw)
	} else {
		claims, all, e = v.introspect(ctx, raw)
	}
	if e != nil {
		return nil, e
	}
	if e = v.checkClaims(claims, all, now); e != nil {
		return nil, e
	}
	binding := Binding{JKT: claims.Confirmation[tokens.CnfJKT], CertThumbprint: claims.Confirmation[tokens.CnfX5tS256]}
	if e = v.checkBinding(r, scheme, raw, binding); e != nil {
		return nil, e
	}
	return newToken(claims, all, binding, scheme, now), nil
}

// verifyJWT verifies a JWT access token per RFC 9068 §4 up to, but not
// including, the iss / aud / time checks shared with introspection.
func (v *Verifier) verifyJWT(ctx context.Context, raw string) (*tokens.AccessTokenClaims, map[string]any, *Error) {
	payload, e := v.verifySignature(ctx, raw)
	if e != nil {
		return nil, nil, e
	}
	claims, err := tokens.DecodeAccessTokenClaims(payload)
	if err != nil {
		return nil, nil, invalidToken("access token claims are malformed")
	}
	if err := tokens.RequireAccessTokenClaims(claims); err != nil {
		return nil, nil, invalidToken("access token lacks a required claim")
	}
	var all map[string]any
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil, nil, invalidToken("access token claims are malformed")
	}
	return claims, all, nil
}

// jwtKind names the issuer-signed JWT being verified; each has its own
// typ header.
type jwtKind int

const (
	jwtAccessToken jwtKind = iota
	jwtIntrospection
)

// Reasons [Verifier.verifyIssuerJWS] rejects a JWS. An unreachable key set
// is reported as the [*Error] the caller returns instead.
var (
	errJWSMalformed = errors.New("rs: not an acceptable JWS")
	errJWSType      = errors.New("rs: unexpected typ header")
	errJWSSignature = errors.New("rs: signature is not valid")
)

// verifySignature checks the JWS header rules and the signature of an
// access token, and returns the verified payload.
func (v *Verifier) verifySignature(ctx context.Context, raw string) ([]byte, *Error) {
	payload, err := v.verifyIssuerJWS(ctx, raw, jwtAccessToken)
	var e *Error
	switch {
	case err == nil:
		return payload, nil
	case errors.As(err, &e):
		return nil, e
	case errors.Is(err, errJWSType):
		return nil, invalidToken("access token typ header is not at+jwt")
	case errors.Is(err, errJWSSignature):
		return nil, invalidToken("access token signature is not valid")
	default:
		return nil, invalidToken("access token is not an acceptable JWS")
	}
}

// verifyIssuerJWS checks that raw is a JWS of the given kind signed by a
// key in the issuer's JWK Set, and returns the verified payload.
//
// The alg is already inside the allow-list once jose.ParseSigned accepts
// the token. A JWK that declares an alg must declare that same one, and a
// JWK whose use is not "sig" never verifies. A kid the cached set does
// not hold triggers one throttled refetch, which is how a key rotation
// propagates.
func (v *Verifier) verifyIssuerJWS(ctx context.Context, raw string, kind jwtKind) ([]byte, error) {
	jws, alg, err := jose.ParseSigned(raw)
	if err != nil {
		return nil, errors.Join(errJWSMalformed, err)
	}
	sig := jws.Signatures[0]
	var typOK bool
	switch kind {
	case jwtAccessToken:
		typOK = tokens.ResourceServerTypHeaderMatches(sig)
	case jwtIntrospection:
		typOK = isIntrospectionTyp(sig.Protected.ExtraHeaders["typ"])
	}
	if !typOK {
		return nil, errJWSType
	}
	uri, e := v.jwksEndpoint(ctx)
	if e != nil {
		return nil, e
	}
	kid := sig.Header.KeyID
	set, err := v.keys.Fetch(ctx, uri)
	if err == nil && kid != "" && len(set.Key(kid)) == 0 {
		cached := set
		set, err = v.keys.FetchFresh(ctx, uri)
		if err != nil && errors.Is(err, rpjwks.ErrOverloaded) {
			// Capacity pressure must not turn a held key set into a 503; the
			// unknown kid is then rejected as an invalid signature.
			set, err = cached, nil
		}
	}
	if err != nil {
		v.logFault("JWK Set fetch failed", err)
		return nil, unavailable("the issuer's signing keys are unavailable")
	}
	for _, k := range set.Keys {
		if !keyEligible(kid, alg.String(), k.KeyID, k.Use, k.Algorithm) {
			continue
		}
		if payload, err := jws.Verify(k.Key); err == nil {
			return payload, nil
		}
	}
	return nil, errJWSSignature
}

// isIntrospectionTyp reports whether a "typ" header value names an RFC
// 9701 response, in its short or its full media-type form.
func isIntrospectionTyp(typ any) bool {
	s, _ := typ.(string)
	return strings.EqualFold(s, typIntrospectionJWT) || strings.EqualFold(s, mediaTypeIntrospectionJWT)
}

// keyEligible reports whether a JWK may verify a JWS with header kid and
// alg: the kid matches when the header names one, the key is not
// restricted to another use, and a declared alg equals the header's.
func keyEligible(kid, alg, keyID, use, keyAlg string) bool {
	switch {
	case kid != "" && keyID != kid:
		return false
	case !rpjwks.SigningUsable(use):
		return false
	case keyAlg != "" && keyAlg != alg:
		return false
	default:
		return true
	}
}

// checkClaims applies the iss, aud and time rules every accepted token
// obeys, whether it was a JWT or an introspection response. exp is
// exclusive (a token is expired at its exp second) and iat may not lie in
// the future and nbf, when present, may not lie ahead of now; none takes a
// leeway. raw is the full payload or introspection response.
func (v *Verifier) checkClaims(c *tokens.AccessTokenClaims, raw map[string]any, now time.Time) *Error {
	switch {
	case c.Issuer != v.issuer:
		return invalidToken("access token was issued by another issuer")
	case !slices.Contains(c.Audience, v.audience):
		return invalidToken("access token is not addressed to this resource")
	case c.ExpiresAt > 0 && now.Unix() >= c.ExpiresAt:
		return invalidToken("access token has expired")
	case c.IssuedAt > now.Unix():
		return invalidToken("access token is issued in the future")
	}
	if nbf, ok := raw["nbf"].(float64); ok && float64(now.Unix()) < nbf {
		return invalidToken("access token is not yet valid")
	}
	return nil
}

// checkBinding enforces the token's sender constraint against the request.
func (v *Verifier) checkBinding(r *http.Request, scheme authScheme, raw string, b Binding) *Error {
	switch {
	case b.JKT != "":
		if scheme != schemeDPoP {
			return invalidToken("DPoP-bound access token presented without the DPoP scheme")
		}
		if e := v.verifyProof(r, raw, b.JKT); e != nil {
			return e
		}
	case scheme == schemeDPoP, v.dpopMode == DPoPRequired:
		return invalidToken("access token is not DPoP-bound")
	}
	if b.CertThumbprint != "" {
		if err := v.mtls.VerifyBoundRequest(r, b.CertThumbprint); err != nil {
			return invalidToken("certificate-bound access token presented without the bound certificate")
		}
	}
	return nil
}

// verifyProof checks the DPoP proof against the request, the token's ath
// and the bound key, and only then consumes its jti, so a proof made with
// the wrong key does not use up the replay slot.
func (v *Verifier) verifyProof(r *http.Request, raw, jkt string) *Error {
	ctx := r.Context()
	checked, err := v.dpop.CheckHTTPRequest(ctx, r, raw)
	if err != nil {
		return invalidProof("DPoP proof is not valid for this request")
	}
	if checked.JKT != jkt {
		return invalidToken("DPoP proof key does not match the access token binding")
	}
	if err := v.dpop.Commit(ctx, checked); err != nil {
		if errors.Is(err, dpop.ErrProofReplayed) {
			return invalidProof("DPoP proof was already used")
		}
		v.logFault("DPoP replay store write failed", err)
		return unavailable("the DPoP replay store is unavailable")
	}
	return nil
}

// logFault reports a server-side failure the client cannot fix.
func (v *Verifier) logFault(msg string, err error) {
	if v.logger != nil {
		v.logger.Warn("rs: "+msg, "error", err)
	}
}

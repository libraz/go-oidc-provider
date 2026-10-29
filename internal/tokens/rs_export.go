package tokens

import (
	josev4 "github.com/go-jose/go-jose/v4"
)

// ResourceServerTypHeaderMatches reports whether sig carries a typ header a
// resource server accepts on a JWT access token: the canonical "at+jwt" this
// package checks on its own verification path, or the full media type
// "application/at+jwt" that RFC 9068 §4 also admits. Any other value,
// including a missing header, is a mismatch.
func ResourceServerTypHeaderMatches(sig josev4.Signature) bool {
	if accessTokenTypHeaderMatches(sig) {
		return true
	}
	for _, hdr := range []map[josev4.HeaderKey]any{sig.Protected.ExtraHeaders, sig.Header.ExtraHeaders} {
		if v, ok := hdr[josev4.HeaderType]; ok {
			s, ok := v.(string)
			return ok && s == "application/"+accessTokenTypeHeader
		}
	}
	return false
}

// DecodeAccessTokenClaims decodes a verified JWT access-token payload, or an
// RFC 7662 introspection response, into [AccessTokenClaims] under the same
// rules [AccessTokenVerifier] applies: "aud" as a string or an array,
// "scope" split on spaces, unknown members tolerated.
func DecodeAccessTokenClaims(payload []byte) (*AccessTokenClaims, error) {
	return decodeAccessTokenClaims(payload)
}

// RequireAccessTokenClaims enforces the RFC 9068 §2.2 required claims (iss,
// sub, aud, client_id, iat, exp) exactly as [AccessTokenVerifier] does with
// RequireJTI unset. Every failure wraps [ErrAccessTokenMalformed].
func RequireAccessTokenClaims(c *AccessTokenClaims) error {
	return (&AccessTokenVerifier{}).requireClaims(c)
}

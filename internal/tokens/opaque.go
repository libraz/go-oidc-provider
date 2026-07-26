package tokens

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// opaqueAccessTokenByteLength is the entropy of an opaque access
// token. 32 bytes (256 bits) sits comfortably above the birthday
// bound for any single deployment and matches the entropy already
// used for refresh-token IDs, authorization-code IDs, and PAR
// request_uri values.
const opaqueAccessTokenByteLength = 32

// MintOpaqueAccessToken returns a freshly generated 32-byte opaque
// access token. The wire form is base64.RawURLEncoding, 43
// characters, alphabet [A-Za-z0-9_-]. Errors propagate from
// [crypto/rand.Read]; callers treat any error as fatal and fail the
// /token request with server_error.
//
// The wire bytes carry no prefix and no checksum: adding a brand
// prefix would leak OP fingerprinting for log correlation and is not
// load-bearing for the introspection-side dispatch (the JWS-shape
// probe in resolveOpaque is robust against an opaque token because
// base64.RawURLEncoding output never contains the '.' separator a JWS
// Compact Serialisation requires).
func MintOpaqueAccessToken() (string, error) {
	buf := make([]byte, opaqueAccessTokenByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("tokens: read random for opaque access token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

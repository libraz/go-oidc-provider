package endpointsupport

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// LooksLikeJWT reports whether token has the structural shape of a
// compact-serialised JWS: three base64url segments separated by dots,
// with the header decoding to a non-empty JSON object. The check is
// deliberately shallow — full parsing happens inside the token
// verifier — because callers use it only to choose between JWT and
// opaque-token branches.
//
// A token whose header is not valid base64url-encoded JSON is treated
// as opaque so a malformed JWT cannot bypass the opaque lookup; the
// JWT branch would reject it anyway, but the conservative choice keeps
// the dispatcher simple to reason about.
func LooksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}
	return len(header) > 0
}

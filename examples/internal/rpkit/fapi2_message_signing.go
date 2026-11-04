//go:build example

package rpkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

// requestObjectLifetime bounds the "exp" of a signed request object; the
// OP accepts far longer, but a request object is consumed within seconds.
const requestObjectLifetime = 5 * time.Minute

// signRequestObject wraps the authorization request parameters in a JAR
// request object (RFC 9101) signed with the registered client key. Besides
// the parameters it carries the claims the OP's Message Signing profile
// checks: iss, aud, exp, nbf, iat and a single-use jti. response_mode=jwt
// asks for the JARM response.
func (f *FAPI2Flow) signRequestObject(params url.Values) (string, error) {
	jti, err := randURL(16)
	if err != nil {
		return "", err
	}
	now := f.clock.Now()
	claims := map[string]any{
		"iss":           f.clientID,
		"aud":           f.endpoints.Issuer,
		"exp":           now.Add(requestObjectLifetime).Unix(),
		"nbf":           now.Unix(),
		"iat":           now.Unix(),
		"jti":           jti,
		"response_mode": "jwt",
	}
	for name, values := range params {
		if len(values) > 0 {
			claims[name] = values[0]
		}
	}
	return signJWT(f.clientKey, f.clientKID, "oauth-authz-req+jwt", claims, nil)
}

// openJARM verifies a JARM authorization response (OAuth 2.0 JARM) and
// returns its claims in the shape of the query parameters a plain response
// would carry. The signature is checked against the OP's published JWKS;
// "iss" is left in the result so the caller's issuer check still runs.
func (f *FAPI2Flow) openJARM(ctx context.Context, response string) (url.Values, error) {
	if response == "" {
		return nil, errors.New("redirect carries no \"response\" parameter; the OP did not answer with JARM")
	}
	payload, err := f.opKeys.VerifySignature(ctx, response)
	if err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var std jwt.Claims
	if err := json.Unmarshal(payload, &std); err != nil {
		return nil, fmt.Errorf("decode registered claims: %w", err)
	}
	if err := std.ValidateWithLeeway(jwt.Expected{
		AnyAudience: jwt.Audience{f.clientID},
		Time:        f.clock.Now(),
	}, time.Minute); err != nil {
		return nil, fmt.Errorf("validate claims: %w", err)
	}

	out := url.Values{}
	for _, name := range []string{"iss", "code", "state", "error", "error_description"} {
		if v, ok := claims[name].(string); ok {
			out.Set(name, v)
		}
	}
	return out, nil
}

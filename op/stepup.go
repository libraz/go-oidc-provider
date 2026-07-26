package op

import (
	"strconv"
	"strings"
)

// StepUpChallenge builds the value of an RFC 9470 §3 "WWW-Authenticate:
// Bearer" challenge that a resource server returns when an access token
// lacks the authentication strength (acr) or freshness (max_age) the
// resource requires.
//
// The challenge always carries error="insufficient_user_authentication".
// A non-empty realm, a non-empty acrValues list, and a non-nil maxAge are
// appended as additional auth-params; acrValues is encoded as a single
// space-delimited quoted string, mirroring the acr_values request
// parameter. The returned string is the header value only (the
// "WWW-Authenticate" field name and the 401 status are the caller's
// responsibility).
//
// This helper exists for the resource-server side of step-up: the OP
// itself never emits this header. Token validation and the 401 response
// belong to the embedder's resource server, not to the OP handler, so the
// library stops at producing a correctly-formatted challenge string. The
// client is expected to retry authorization with the advertised acr_values
// / max_age, which the OP honours at the authorization endpoint.
//
// Stable since v1.0.
func StepUpChallenge(realm string, acrValues []string, maxAge *int64) string {
	params := make([]string, 0, 4)
	if realm != "" {
		params = append(params, "realm="+quoteAuthParam(realm))
	}
	// RFC 9470 §3: the error code is mandatory.
	params = append(params, `error="insufficient_user_authentication"`)
	if len(acrValues) > 0 {
		params = append(params, "acr_values="+quoteAuthParam(strings.Join(acrValues, " ")))
	}
	if maxAge != nil {
		params = append(params, "max_age="+quoteAuthParam(strconv.FormatInt(*maxAge, 10)))
	}
	return "Bearer " + strings.Join(params, ", ")
}

// quoteAuthParam wraps v in an RFC 7235 quoted-string, escaping the only
// two characters that are illegal inside one.
func quoteAuthParam(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

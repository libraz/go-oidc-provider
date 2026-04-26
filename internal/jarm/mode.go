package jarm

// ResponseMode is the typed enumeration of JARM response_mode values.
// The zero value is invalid; constructors return a typed value with an
// ok flag so callers branch on the bool rather than on string equality.
type ResponseMode string

// JARM response_mode constants. The literal values are the canonical
// strings the spec mandates on the wire.
const (
	// ResponseModeQueryJWT carries the response JWT in the query string
	// of redirect_uri.
	ResponseModeQueryJWT ResponseMode = "query.jwt"

	// ResponseModeFragmentJWT carries the response JWT in the URL
	// fragment of redirect_uri.
	ResponseModeFragmentJWT ResponseMode = "fragment.jwt"

	// ResponseModeFormPostJWT carries the response JWT in a hidden
	// "response" field of an auto-submitted HTML form.
	ResponseModeFormPostJWT ResponseMode = "form_post.jwt"

	// ResponseModeJWT is the bare alias the JARM spec defines as "use
	// the default for the response_type". For "code" it resolves to
	// [ResponseModeQueryJWT]; for "token" / "id_token" responses it
	// would resolve to [ResponseModeFragmentJWT], but v0.x does not
	// implement those flows.
	ResponseModeJWT ResponseMode = "jwt"
)

// Parse reports whether s is one of the four recognised JARM modes and,
// if so, returns the typed value. Non-JARM strings ("query", "form_post",
// "" for "default") return ("", false) so the caller can treat the
// non-JARM path uniformly.
func Parse(s string) (ResponseMode, bool) {
	switch ResponseMode(s) {
	case ResponseModeQueryJWT, ResponseModeFragmentJWT, ResponseModeFormPostJWT, ResponseModeJWT:
		return ResponseMode(s), true
	default:
		return "", false
	}
}

// IsJARM reports whether s names one of the four JARM response_mode
// values. It is a thin convenience over [Parse]; the boolean second
// return of [Parse] is preferred when the caller also wants the typed
// value.
func IsJARM(s string) bool {
	_, ok := Parse(s)
	return ok
}

// Resolve maps the bare [ResponseModeJWT] onto the concrete mode the
// spec implies for the response_type. For every other JARM mode the
// argument is returned unchanged. For non-JARM modes the function
// returns the empty string so misuse fails fast.
//
// The mapping follows the JARM specification §4.3:
//
//   - response_type=code (or anything that does NOT include "token" /
//     "id_token") → query.jwt
//   - response_type containing "token" or "id_token"           → fragment.jwt
//
// v0.x only ships the Code flow, so in practice every resolution lands
// on [ResponseModeQueryJWT]; the fragment branch is wired so future
// hybrid-flow support can opt into JARM without rewriting this helper.
func Resolve(mode ResponseMode, responseType string) ResponseMode {
	if mode != ResponseModeJWT {
		if _, ok := Parse(string(mode)); ok {
			return mode
		}
		return ""
	}
	if responseTypeImpliesFragment(responseType) {
		return ResponseModeFragmentJWT
	}
	return ResponseModeQueryJWT
}

// responseTypeImpliesFragment reports whether the response_type value
// would normally be delivered through the URL fragment. The check is
// intentionally permissive: any response_type that contains "token" or
// "id_token" as a space-separated value falls under the fragment path.
func responseTypeImpliesFragment(responseType string) bool {
	for i := 0; i < len(responseType); {
		// Skip leading spaces.
		for i < len(responseType) && responseType[i] == ' ' {
			i++
		}
		j := i
		for j < len(responseType) && responseType[j] != ' ' {
			j++
		}
		if i == j {
			break
		}
		token := responseType[i:j]
		if token == "token" || token == "id_token" {
			return true
		}
		i = j
	}
	return false
}

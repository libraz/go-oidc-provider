package authorize

import (
	"net/http"
	"net/url"
	"strings"
)

// ParseRequest extracts the canonical [Request] from r. For GET it reads
// r.URL.Query(); for POST it parses the form body via [http.Request.ParseForm]
// and reads r.PostForm. Other methods produce no parameters and the parser
// will surface the request-level errors that follow.
//
// ParseRequest does NOT validate against any client. Its sole job is to
// turn the wire form into a normalised value, plus the structural checks
// that have no client dependency (duplicate single-valued parameters,
// repeated multi-valued parameters, malformed max_age).
func ParseRequest(r *http.Request) (*Request, error) {
	values, err := extractValues(r)
	if err != nil {
		return nil, err
	}
	return ParseValues(values)
}

// ParseValues parses the same [Request] shape from a pre-extracted
// [url.Values]. It is the kernel that [ParseRequest] delegates to and is
// exported so tests and adjacent packages (PAR, JAR) can reuse the parser
// without constructing a real *http.Request.
func ParseValues(v url.Values) (*Request, error) {
	singles, err := parseSingleValues(v)
	if err != nil {
		return nil, err
	}
	multis, err := parseMultiValues(v)
	if err != nil {
		return nil, err
	}
	maxAge, err := parseMaxAge(v)
	if err != nil {
		return nil, err
	}
	claims, err := ParseClaimsRequest(singles["claims"])
	if err != nil {
		return nil, err
	}
	return &Request{
		ClientID:            singles["client_id"],
		ResponseType:        singles["response_type"],
		RedirectURI:         singles["redirect_uri"],
		Scope:               dedupePreserve(strings.Fields(multis["scope"])),
		Resource:            singles["resource"],
		State:               singles["state"],
		Nonce:               singles["nonce"],
		CodeChallenge:       singles["code_challenge"],
		CodeChallengeMethod: singles["code_challenge_method"],
		Prompt:              splitPrompt(multis["prompt"]),
		MaxAge:              maxAge,
		LoginHint:           singles["login_hint"],
		UILocales:           strings.Fields(multis["ui_locales"]),
		ACRValues:           strings.Fields(multis["acr_values"]),
		ResponseMode:        singles["response_mode"],
		RequestObject:       singles["request"],
		RequestURI:          singles["request_uri"],
		DPoPJKT:             singles["dpop_jkt"],
		Claims:              claims,
	}, nil
}

// singleParseFields is the closed list of single-valued parameters
// [parseSingleValues] reads. Centralising the list keeps the parser
// loop short enough to stay under the project complexity gate.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var singleParseFields = []string{
	"client_id",
	"response_type",
	"redirect_uri",
	"state",
	"nonce",
	"code_challenge",
	"code_challenge_method",
	"login_hint",
	"response_mode",
	"request",
	"request_uri",
	"dpop_jkt",
	"claims",
	"resource",
}

// parseSingleValues extracts every single-valued parameter from v,
// surfacing [ErrDuplicateParameter] on the first conflict it finds.
func parseSingleValues(v url.Values) (map[string]string, error) {
	out := make(map[string]string, len(singleParseFields))
	for _, name := range singleParseFields {
		val, err := singleValue(v, name)
		if err != nil {
			return nil, err
		}
		out[name] = val
	}
	return out, nil
}

// multiParseFields lists the multi-valued parameters [parseMultiValues]
// reads. Each member is admitted at most once in the wire form
// (multi-valued semantics live inside the value, not the [url.Values]
// entry); the helpers below enforce that contract.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var multiParseFields = []string{"scope", "prompt", "ui_locales", "acr_values"}

// parseMultiValues extracts every multi-valued parameter from v.
// "scope" / "ui_locales" / "acr_values" are read via [multiValue] and
// "prompt" is read via [singleEntry]; the difference is documented on
// the helpers themselves.
func parseMultiValues(v url.Values) (map[string]string, error) {
	out := make(map[string]string, len(multiParseFields))
	for _, name := range multiParseFields {
		var (
			val string
			err error
		)
		if name == "prompt" {
			val, err = singleEntry(v, name)
		} else {
			val, err = multiValue(v, name)
		}
		if err != nil {
			return nil, err
		}
		out[name] = val
	}
	return out, nil
}

// extractValues returns the [url.Values] the parser should consume.
// GET requests use [http.Request.URL.Query()]; POST requests use the parsed
// form. Other methods return an empty value set so the per-parameter
// "required" checks fire in the validator.
func extractValues(r *http.Request) (url.Values, error) {
	if r == nil {
		return nil, ErrClientIDRequired
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		return r.PostForm, nil
	}
	return r.URL.Query(), nil
}

// singleValue returns the value of a single-valued parameter. Multiple
// occurrences are tolerated only when every value is byte-equal; differing
// values produce [ErrDuplicateParameter].
func singleValue(v url.Values, key string) (string, error) {
	values, ok := v[key]
	if !ok || len(values) == 0 {
		return "", nil
	}
	first := values[0]
	for _, candidate := range values[1:] {
		if candidate != first {
			return "", ErrDuplicateParameter
		}
	}
	return first, nil
}

// singleEntry returns the single occurrence of a multi-valued parameter
// that is permitted to appear at most once in [url.Values]. Repeated entries
// are rejected with [ErrDuplicateParameter] (concatenating would mask the
// case where a client legitimately needed to repeat the parameter, which
// the spec does not require).
func singleEntry(v url.Values, key string) (string, error) {
	values, ok := v[key]
	if !ok || len(values) == 0 {
		return "", nil
	}
	if len(values) > 1 {
		return "", ErrDuplicateParameter
	}
	return values[0], nil
}

// multiValue returns the single space-delimited string for a multi-valued
// parameter. Like [singleEntry], it rejects repetition rather than
// concatenating.
func multiValue(v url.Values, key string) (string, error) {
	return singleEntry(v, key)
}

package jar

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// mergeIgnoredClaims is the set of registered JWT claims [Merge] does
// not project onto the wire form. The members are JOSE machinery, not
// authorization parameters; ignoring them keeps an attacker from using
// a "jti" or "iat" claim to inject an unexpected request parameter.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var mergeIgnoredClaims = map[string]struct{}{
	"iss":         {},
	"aud":         {},
	"exp":         {},
	"nbf":         {},
	"iat":         {},
	"jti":         {},
	"client_id":   {},
	"request":     {},
	"request_uri": {},
}

// Merge folds the verified [Object]'s claims onto the wire-level form
// values, returning a fresh [url.Values] suitable for the existing
// authorize parser. Per RFC 9101 §6.1:
//
//   - Every authorization parameter inside the request object overrides
//     the wire-level value of the same name.
//   - "request" / "request_uri" inside the request object are forbidden;
//     [Verifier.Verify] already rejects them, but Merge re-checks for
//     defence in depth.
//   - "client_id" MUST agree between the wire and the request object.
//     A missing "client_id" inside the JWT is acceptable (the wire value
//     stands), but a present-and-different value is an error.
//
// Merge does NOT validate the merged result; that is the authorize
// parser's job.
func Merge(wire url.Values, obj *Object) (url.Values, error) {
	if obj == nil {
		return nil, fmt.Errorf("%w: nil object", ErrParse)
	}
	if _, has := obj.Claims["request"]; has {
		return nil, ErrNestedRequest
	}
	if _, has := obj.Claims["request_uri"]; has {
		return nil, ErrNestedRequest
	}
	if err := assertClientIDAgrees(wire, obj); err != nil {
		return nil, err
	}
	out := cloneValues(wire)
	// "request" / "request_uri" on the wire are stripped; the merged
	// values are presented to the authorize parser as if the request
	// arrived in the clear.
	out.Del("request")
	out.Del("request_uri")
	for name, raw := range obj.Claims {
		if _, ignored := mergeIgnoredClaims[name]; ignored {
			continue
		}
		s, ok := stringifyClaim(raw)
		if !ok {
			// A claim shape the projector cannot lower onto a query
			// string is a programming bug on the RP side, not a
			// signature failure. Surface it as a parse error so the
			// HTTP layer returns invalid_request_object rather than
			// silently dropping the value.
			return nil, fmt.Errorf("%w: claim %q has unsupported shape %T", ErrParse, name, raw)
		}
		out.Set(name, s)
	}
	// The wire client_id always wins after the merge: even if the
	// request object carried a matching client_id, we re-stamp the
	// trusted wire value so the downstream parser sees a single
	// authoritative source.
	if id := wire.Get("client_id"); id != "" {
		out.Set("client_id", id)
	}
	return out, nil
}

// assertClientIDAgrees enforces RFC 9101 §6.1 client_id matching. A
// missing "client_id" inside the JWT is permitted: the wire value is
// authoritative. An empty wire value is permitted too (the request
// object stands in), but a present-and-different value is a hard
// rejection.
func assertClientIDAgrees(wire url.Values, obj *Object) error {
	wireID := wire.Get("client_id")
	objID, _ := obj.Claims["client_id"].(string)
	if objID == "" {
		return nil
	}
	if wireID != "" && wireID != objID {
		return fmt.Errorf("%w: wire=%q jwt=%q", ErrClientIDMismatch, wireID, objID)
	}
	return nil
}

// cloneValues returns a deep copy of in so [Merge] can mutate the
// returned value without aliasing the caller's slice headers.
func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// stringifyClaim lowers a JSON claim value onto the wire-string form
// the authorize parser expects. The function accepts the shapes RFC
// 9101 admits at this layer:
//
//   - string: copied verbatim.
//   - json.Number: encoded as the canonical decimal form (matches
//     [strconv.FormatInt] / [strconv.FormatFloat]).
//   - bool: encoded as "true" / "false".
//   - []any (only for "scope" / "acr_values" / "ui_locales"): joined
//     on a single space — RPs that supply structured arrays must do so
//     in a way the authorize parser already tolerates.
//
// Any other shape returns ok=false so the caller can surface a typed
// error.
func stringifyClaim(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case int:
		return strconv.Itoa(x), true
	case []any:
		return joinStringArray(x)
	}
	return "", false
}

// joinStringArray returns a space-joined string when every element is
// a string. Mixed-type arrays fail with ok=false so the caller surfaces
// a typed error rather than silently dropping the values.
func joinStringArray(values []any) (string, bool) {
	parts := make([]string, 0, len(values))
	for _, raw := range values {
		s, ok := raw.(string)
		if !ok {
			return "", false
		}
		parts = append(parts, s)
	}
	return joinSpace(parts), true
}

// joinSpace concatenates parts with single ASCII spaces. The helper
// exists so the call site reads naturally; we delegate to
// [strings.Join] for the actual concatenation.
func joinSpace(parts []string) string {
	return strings.Join(parts, " ")
}

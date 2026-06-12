package authorize

import (
	"bytes"
	"encoding/json"
	"slices"
)

const maxClaimsRequestBytes = 16 * 1024

// ClaimsRequest is the parsed view of the OIDC Core 1.0 §5.5 "claims"
// request parameter. The wire form is a JSON object with optional
// "userinfo" and "id_token" top-level members; this struct exposes those
// two locations as Go maps keyed by claim name.
//
// A nil *ClaimsRequest means the wire form omitted the parameter
// entirely. An empty (non-nil) value means the parameter parsed but
// requested zero claims, which the projector treats identically to
// "omitted" — the distinction exists only so the discovery
// advertisement and the parser surface line up.
type ClaimsRequest struct {
	// IDToken is the parsed value of the top-level "id_token" member.
	// Keys are claim names (RFC 7519 / OIDC Core §5.1) verbatim,
	// including any optional language tag suffix ("name#ja-JP").
	IDToken map[string]ClaimSpec `json:"id_token,omitempty"`

	// UserInfo is the parsed value of the top-level "userinfo" member.
	UserInfo map[string]ClaimSpec `json:"userinfo,omitempty"`
}

// ClaimSpec is the parsed value of a single entry in a ClaimsRequest
// map. The wire form per OIDC Core §5.5.1 is either JSON null (voluntary
// request, no constraints) or a JSON object with optional "essential",
// "value", and "values" members.
type ClaimSpec struct {
	// Essential reports whether the wire form set "essential": true.
	// Per OIDC Core §5.5.1, an essential request asks the OP to MUST
	// attempt to provide the claim, but the spec stops short of
	// promising the claim will be present — the library renders this
	// as "omit on absent".
	Essential bool `json:"essential,omitempty"`

	// Value is the wire form's "value" member. The claims projector
	// uses it as a "MUST equal" constraint when present. Stored as
	// any so JSON numeric / string / bool inputs round-trip without
	// the parser having to commit to a Go type.
	Value any `json:"value,omitempty"`

	// Values is the wire form's "values" member. The claims projector
	// uses it as a "MUST be one of" constraint when present.
	Values []any `json:"values,omitempty"`
}

// HasIDToken reports whether the request asked for the named claim
// under id_token.
func (c *ClaimsRequest) HasIDToken(name string) bool {
	if c == nil {
		return false
	}
	_, ok := c.IDToken[name]
	return ok
}

// HasUserInfo reports whether the request asked for the named claim
// under userinfo.
func (c *ClaimsRequest) HasUserInfo(name string) bool {
	if c == nil {
		return false
	}
	_, ok := c.UserInfo[name]
	return ok
}

// IDTokenSpec returns the ClaimSpec stored under id_token for name and
// reports whether the entry exists. The returned spec is a copy; the
// caller may not mutate the underlying Value/Values payload (the
// parser already detached it from the JSON decoder buffer).
func (c *ClaimsRequest) IDTokenSpec(name string) (ClaimSpec, bool) {
	if c == nil {
		return ClaimSpec{}, false
	}
	spec, ok := c.IDToken[name]
	return spec, ok
}

// UserInfoSpec mirrors [ClaimsRequest.IDTokenSpec] for the userinfo
// projection.
func (c *ClaimsRequest) UserInfoSpec(name string) (ClaimSpec, bool) {
	if c == nil {
		return ClaimSpec{}, false
	}
	spec, ok := c.UserInfo[name]
	return spec, ok
}

// Allows reports whether v satisfies the spec's value/values
// constraint. A spec with no Value and no Values accepts any v. When
// both are present (the spec is silent on the combination) the
// projector treats them as conjunction: v MUST equal Value AND v
// MUST be in Values. The comparison is JSON-equality: numbers compare
// by float64 round-trip, strings by byte equality, bools by identity.
func (s ClaimSpec) Allows(v any) bool {
	if s.Value != nil && !jsonEqual(s.Value, v) {
		return false
	}
	if len(s.Values) > 0 {
		match := false
		for _, candidate := range s.Values {
			if jsonEqual(candidate, v) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

// ParseClaimsRequest parses the wire form of the OIDC Core §5.5
// "claims" parameter. An empty input returns (nil, nil) so the caller
// can treat "absent" identically. A malformed JSON document, or a
// document whose top-level shape is not an object, returns
// [ErrClaimsRequestInvalid].
//
// Top-level keys other than "userinfo" / "id_token" are silently
// ignored per §5.5 ("MAY be supplemented by additional members");
// per-claim entries that are neither null nor a JSON object are
// rejected so the parser can refuse a clearly malformed wire form
// without leaking the reason to the redirect channel.
func ParseClaimsRequest(raw string) (*ClaimsRequest, error) {
	trimmed := bytes.TrimSpace([]byte(raw))
	if len(trimmed) == 0 {
		return nil, nil //nolint:nilnil // documented contract: absent parameter
	}
	if len(trimmed) > maxClaimsRequestBytes {
		return nil, ErrClaimsRequestInvalid
	}
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return nil, ErrClaimsRequestInvalid
	}
	if dec.More() {
		// trailing garbage after the object — reject.
		return nil, ErrClaimsRequestInvalid
	}
	out := &ClaimsRequest{}
	idToken, err := parseClaimsLocation(top["id_token"])
	if err != nil {
		return nil, err
	}
	userInfo, err := parseClaimsLocation(top["userinfo"])
	if err != nil {
		return nil, err
	}
	out.IDToken = idToken
	out.UserInfo = userInfo
	if len(out.IDToken) == 0 && len(out.UserInfo) == 0 {
		// Both members absent or empty: treat as "no claims requested"
		// but still hand back the non-nil shell so the caller can
		// distinguish "parameter absent" (nil) from "parameter present
		// but empty" — the projector behaves identically either way,
		// but the discovery / audit layers may want the signal.
		return out, nil
	}
	return out, nil
}

// parseClaimsLocation parses one of the top-level "userinfo" or
// "id_token" members. A nil RawMessage means the member was absent
// (returns nil map, no error). A literal JSON null also returns nil
// map. Any other non-object value is rejected.
func parseClaimsLocation(raw json.RawMessage) (map[string]ClaimSpec, error) {
	if len(raw) == 0 {
		return nil, nil //nolint:nilnil // documented contract: absent member
	}
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return nil, nil //nolint:nilnil // documented contract: literal JSON null
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &entries); err != nil {
		return nil, ErrClaimsRequestInvalid
	}
	if len(entries) == 0 {
		return nil, nil //nolint:nilnil // documented contract: empty object
	}
	out := make(map[string]ClaimSpec, len(entries))
	for name, body := range entries {
		spec, err := parseClaimSpec(body)
		if err != nil {
			return nil, err
		}
		out[name] = spec
	}
	return out, nil
}

// parseClaimSpec parses one entry's body. A literal null means
// "voluntary, no constraint" (returns the zero ClaimSpec). A JSON
// object is decoded by hand so we can keep Value / Values as any and
// preserve numeric precision via json.Number on the wire side.
func parseClaimSpec(raw json.RawMessage) (ClaimSpec, error) {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return ClaimSpec{}, nil
	}
	var body struct {
		Essential *bool           `json:"essential"`
		Value     json.RawMessage `json:"value"`
		Values    json.RawMessage `json:"values"`
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
		return ClaimSpec{}, ErrClaimsRequestInvalid
	}
	spec := ClaimSpec{}
	if body.Essential != nil {
		spec.Essential = *body.Essential
	}
	if len(body.Value) > 0 {
		v, err := decodeJSONAny(body.Value)
		if err != nil {
			return ClaimSpec{}, ErrClaimsRequestInvalid
		}
		spec.Value = v
	}
	if len(body.Values) > 0 {
		var arr []json.RawMessage
		if err := json.Unmarshal(body.Values, &arr); err != nil {
			return ClaimSpec{}, ErrClaimsRequestInvalid
		}
		out := make([]any, 0, len(arr))
		for _, item := range arr {
			v, err := decodeJSONAny(item)
			if err != nil {
				return ClaimSpec{}, ErrClaimsRequestInvalid
			}
			out = append(out, v)
		}
		spec.Values = out
	}
	return spec, nil
}

// decodeJSONAny turns a JSON value into a Go any with json.Number
// preserved (so the projector can compare integer / fractional values
// without precision loss). Used for both ClaimSpec.Value and each
// element of ClaimSpec.Values.
func decodeJSONAny(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// jsonEqual implements JSON-equality for ClaimSpec.Allows. Numbers
// compare via json.Number string form (post-UseNumber); strings and
// bools by Go equality; slices and maps element-wise. Mixed types
// always disagree.
//
//nolint:gocognit,cyclop // exhaustive type switch over JSON shapes
func jsonEqual(a, b any) bool {
	switch av := a.(type) {
	case json.Number:
		bv, ok := b.(json.Number)
		return ok && av.String() == bv.String()
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case nil:
		return b == nil
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !jsonEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, val := range av {
			other, found := bv[k]
			if !found || !jsonEqual(val, other) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// CloneClaimsRequest returns a deep copy of c suitable for handing to
// downstream code that may mutate the maps. A nil receiver returns nil.
func CloneClaimsRequest(c *ClaimsRequest) *ClaimsRequest {
	if c == nil {
		return nil
	}
	return &ClaimsRequest{
		IDToken:  cloneClaimSpecMap(c.IDToken),
		UserInfo: cloneClaimSpecMap(c.UserInfo),
	}
}

func cloneClaimSpecMap(in map[string]ClaimSpec) map[string]ClaimSpec {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]ClaimSpec, len(in))
	for k, v := range in {
		out[k] = ClaimSpec{
			Essential: v.Essential,
			Value:     v.Value,
			Values:    slices.Clone(v.Values),
		}
	}
	return out
}

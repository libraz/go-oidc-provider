package authorize

// claimsGrantKey is the well-known sub-key the library uses inside
// [op/store.Grant.Claims] to persist a parsed [ClaimsRequest]. Other
// per-claim consent metadata may live alongside it; reserving a single
// stable key keeps the round-trip stable across library versions
// without claiming the entire map for the §5.5 payload.
const claimsGrantKey = "request"

// EncodeClaimsToGrant returns the [op/store.Grant.Claims] payload that
// records c. A nil receiver returns nil so the caller can leave the
// grant's Claims map empty (the wire form omits it). The encoded shape
// mirrors OIDC Core 1.0 §5.5 verbatim under the [claimsGrantKey] sub-
// key, so a storage backend that JSON-marshals the grant gets a payload
// readable by humans and external tools.
func EncodeClaimsToGrant(c *ClaimsRequest) map[string]any {
	if c == nil {
		return nil
	}
	if len(c.IDToken) == 0 && len(c.UserInfo) == 0 {
		return nil
	}
	body := map[string]any{}
	if encoded := encodeClaimsLocation(c.IDToken); encoded != nil {
		body["id_token"] = encoded
	}
	if encoded := encodeClaimsLocation(c.UserInfo); encoded != nil {
		body["userinfo"] = encoded
	}
	if len(body) == 0 {
		return nil
	}
	return map[string]any{claimsGrantKey: body}
}

// DecodeClaimsFromGrant rebuilds a [*ClaimsRequest] from a payload
// produced by [EncodeClaimsToGrant]. A nil or empty input returns nil
// so callers can treat "absent" identically. A payload whose shape
// disagrees with the encoder contract returns nil too — the helper is
// best-effort by design, because grant records persist for the life
// of a refresh token and the library reserves the right to evolve the
// schema in v0.x without breaking older records.
func DecodeClaimsFromGrant(g map[string]any) *ClaimsRequest {
	if len(g) == 0 {
		return nil
	}
	bodyAny, ok := g[claimsGrantKey]
	if !ok {
		return nil
	}
	body, ok := bodyAny.(map[string]any)
	if !ok {
		return nil
	}
	out := &ClaimsRequest{
		IDToken:  decodeClaimsLocation(body["id_token"]),
		UserInfo: decodeClaimsLocation(body["userinfo"]),
	}
	if len(out.IDToken) == 0 && len(out.UserInfo) == 0 {
		return nil
	}
	return out
}

// encodeClaimsLocation lowers a parsed location map onto the
// [map[string]any] shape suitable for [op/store.Grant.Claims]. Empty
// inputs return nil so the caller can omit the corresponding key.
func encodeClaimsLocation(in map[string]ClaimSpec) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for name, spec := range in {
		out[name] = encodeClaimSpec(spec)
	}
	return out
}

// encodeClaimSpec lowers a ClaimSpec onto the JSON object shape OIDC
// Core §5.5.1 documents. The zero spec returns nil so the encoder
// emits a literal JSON null — the wire form for a voluntary request
// without constraints.
func encodeClaimSpec(s ClaimSpec) any {
	if !s.Essential && s.Value == nil && len(s.Values) == 0 {
		return nil
	}
	out := map[string]any{}
	if s.Essential {
		out["essential"] = true
	}
	if s.Value != nil {
		out["value"] = s.Value
	}
	if len(s.Values) > 0 {
		out["values"] = append([]any(nil), s.Values...)
	}
	return out
}

// decodeClaimsLocation parses one of the top-level "id_token" or
// "userinfo" sub-objects from a previously-encoded grant payload.
// Entries with the wrong shape are skipped silently — see
// [DecodeClaimsFromGrant] for the rationale.
func decodeClaimsLocation(raw any) map[string]ClaimSpec {
	body, ok := raw.(map[string]any)
	if !ok || len(body) == 0 {
		return nil
	}
	out := make(map[string]ClaimSpec, len(body))
	for name, entry := range body {
		out[name] = decodeClaimSpec(entry)
	}
	return out
}

// decodeClaimSpec rebuilds a ClaimSpec from a single grant entry. A
// JSON-null entry yields the zero spec.
func decodeClaimSpec(raw any) ClaimSpec {
	body, ok := raw.(map[string]any)
	if !ok {
		return ClaimSpec{}
	}
	spec := ClaimSpec{}
	if v, ok := body["essential"].(bool); ok {
		spec.Essential = v
	}
	if v, present := body["value"]; present {
		spec.Value = v
	}
	if v, ok := body["values"].([]any); ok {
		spec.Values = append([]any(nil), v...)
	}
	return spec
}

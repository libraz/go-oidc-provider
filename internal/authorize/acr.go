package authorize

import "slices"

// RequestedACRValues is the single source of truth for "which
// authentication context did this request ask for". OIDC Core 1.0
// §5.5.1.1 lets a relying party name it two ways — the acr_values
// parameter, or an "acr" entry under the claims parameter's id_token
// member — and the two are alternative spellings of the same ask.
// Reading only acr_values would hand a claims-only request an acr the
// OP never agreed to: the step-up gate honours both spellings, so a
// policy that sees only one can approve a context the gate rejected.
//
// Ordering is acr_values first (the parameter form carries the RP's
// preference order) followed by the claims spec's "value" and "values"
// entries. Duplicates are dropped so a value named through both
// spellings is offered to the policy once. Non-string claims entries
// are skipped: acr is a string claim, and a numeric or object entry
// names no context the OP could satisfy.
//
// The method lives here rather than on the authorization endpoint
// because every authentication-request surface — /authorize, /par,
// /bc-authorize — has to agree about which values a request names
// before any of them can decide whether it may honour them.
func (r *Request) RequestedACRValues() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.ACRValues))
	seen := make(map[string]struct{}, len(r.ACRValues))
	add := func(v string) {
		if v == "" {
			return
		}
		if _, dup := seen[v]; dup {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range r.ACRValues {
		add(v)
	}
	if spec, ok := r.Claims.IDTokenSpec("acr"); ok {
		if v, isString := spec.Value.(string); isString {
			add(v)
		}
		for _, candidate := range spec.Values {
			if v, isString := candidate.(string); isString {
				add(v)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// UnsupportedACRValue returns the first authentication context the
// request names that the OP has not advertised in supported, and
// whether such a value exists.
//
// An empty supported list means the OP published no
// `acr_values_supported` metadata; every value then passes verbatim,
// which is the posture a deployment that never opted into the
// advertisement has always had. A non-empty list is a closed set: a
// value outside it names a context the operator never enrolled, and
// honouring it would let the client drive the `acr` claim of the issued
// credentials — and the persisted authentication state behind them — to
// a string of its own choosing.
//
// Both spellings are checked, because both reach the ACR satisfaction
// seam: see [Request.RequestedACRValues].
func (r *Request) UnsupportedACRValue(supported []string) (string, bool) {
	if r == nil || len(supported) == 0 {
		return "", false
	}
	for _, v := range r.RequestedACRValues() {
		if !slices.Contains(supported, v) {
			return v, true
		}
	}
	return "", false
}

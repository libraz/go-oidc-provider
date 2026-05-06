package httpx

import "net/url"

// FirstDuplicateParameter scans values for a member of names that
// appears more than once. The second return is false when a duplicate
// was found; the first return then names the offending parameter so
// the caller can stamp the wire description.
//
// The helper centralises the RFC 6749 §3.2 "MUST NOT include any
// request parameter more than once" rule across the form-accepting
// endpoints (token, CIBA authorize, PAR, introspection, revocation,
// RP-initiated logout) and the shared client-authentication parser.
// Each caller declares its own list of single-valued parameter names
// — multi-valued parameters allowed by profile (e.g. RFC 8707
// "resource") MUST be omitted from that list so they pass through
// unchanged.
//
// Byte-equal repeats are NOT tolerated: the ambiguity the spec warns
// against exists regardless of whether the values agree, and the
// upstream proxy / WAF / audit tooling that disagrees with the OP on
// duplicate handling is the threat we close. Rejecting uniformly
// keeps the wire contract crisp.
//
// The helper lives in [internal/httpx] (rather than the
// protocol-aware [internal/endpointsupport] sibling) so the
// [internal/clientauth] parser can call it without forming an import
// cycle through endpointsupport's clientauth-error mapping. The
// behaviour is identical regardless of which package surfaces it.
func FirstDuplicateParameter(values url.Values, names []string) (string, bool) {
	for _, name := range names {
		if len(values[name]) > 1 {
			return name, false
		}
	}
	return "", true
}

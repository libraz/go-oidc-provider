package authorizeendpoint

import (
	"net/http"
	"net/netip"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/proxy"
)

// auditRemoteIP renders the request's resolved client IP for an audit
// event. An unresolvable address yields "" rather than netip.Addr's
// "invalid IP" placeholder, which audit.Event.IP documents as the
// unresolvable case and which a log reader would otherwise mistake for
// a literal address. Mirrors the guard [acrRemoteIP] applies on the
// interaction path.
func auditRemoteIP(r *http.Request, deps resolved) string {
	if ip := clientIPFromRequest(r, deps); ip.IsValid() {
		return ip.String()
	}
	return ""
}

// userAgentMaxLen caps the [http.Request] User-Agent string the
// orchestrator records on the chain state. The cap mirrors the
// length internal/sessions uses for its session record so the values
// remain comparable across the HTTP layer.
const userAgentMaxLen = 512

// truncateUserAgent enforces the [userAgentMaxLen] cap. Empty input
// passes through; over-long strings are sliced byte-wise.
func truncateUserAgent(ua string) string {
	if len(ua) <= userAgentMaxLen {
		return ua
	}
	return ua[:userAgentMaxLen]
}

// clientIPFromRequest returns the [netip.Addr] the OP considers
// authoritative for r. The function delegates to [proxy.Resolve],
// which:
//
//   - when [Deps.ProxyTrust] is configured AND r.RemoteAddr lies
//     inside a trusted CIDR: honours X-Forwarded-For per RFC 7239 §5.2
//     (first non-trusted hop wins, preventing a client from forging
//     its IP by writing fake values to the left of the chain);
//   - otherwise: falls back to r.RemoteAddr so a hostile client
//     cannot spoof its source IP merely by setting the header.
//
// The brute-force counter and audit-log fields downstream consume the
// returned value, so honouring the forwarded header behind a trusted
// proxy closes the fingerprinting gap (without the
// trust every authenticated request would attribute to the proxy IP,
// hiding the real client from the rate limiter).
func clientIPFromRequest(r *http.Request, deps resolved) netip.Addr {
	res := proxy.Resolve(r, deps.ProxyTrust)
	return res.ClientIP
}

// acrRemoteIP returns the client IP the ACR policy sees. The chain
// state carries the address /authorize resolved through the
// trusted-proxy chain when it created the interaction, which is the
// address the ceremony actually started from; it is preferred over
// re-resolving the terminal request so a policy sees one address for
// the whole login. The fallback re-resolves the current request
// through the same trusted-proxy path for chains that predate the
// recorded field. An unresolvable address yields "" rather than
// netip.Addr's "invalid IP" placeholder so the policy's no-hints
// branch stays reachable.
func acrRemoteIP(r *http.Request, deps resolved, st authn.State) string {
	if st.RemoteIP.IsValid() {
		return st.RemoteIP.String()
	}
	if ip := clientIPFromRequest(r, deps); ip.IsValid() {
		return ip.String()
	}
	return ""
}

// acrUserAgent mirrors [acrRemoteIP] for the User-Agent hint: the
// value recorded on the chain wins, and the terminal request's header
// (truncated to the same bound the chain applies) is the fallback.
func acrUserAgent(r *http.Request, st authn.State) string {
	if st.UserAgent != "" {
		return st.UserAgent
	}
	return truncateUserAgent(r.UserAgent())
}

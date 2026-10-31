package endsession

import (
	"net/http"
	"net/url"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
)

// endSessionSingleValuedParams enumerates the request parameters
// OIDC RP-Initiated Logout 1.0 §2 lists with single-valued
// semantics, plus the confirmation-token field the hint-less POST
// branch reads from the double-submit cookie. RFC 6749 §3.2 forbids
// duplicates for these names; the /end_session endpoint joins the
// same input-shape policy as the token / PAR / CIBA surfaces by
// rejecting any repeat at the dispatcher level.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var endSessionSingleValuedParams = []string{
	"id_token_hint",
	"client_id",
	"post_logout_redirect_uri",
	"state",
	"logout_hint",
	"ui_locales",
	"logout_scope",
	"logout_scope_fingerprint",
	"chooser_group_id",
	confirmTokenField,
}

const (
	logoutScopeAll     = "all"
	logoutScopeCurrent = "current"
)

// maxQueryBytes caps the byte-length of [http.Request.URL.RawQuery] on
// the GET branch of /end_session. RFC 9700 §2.4 recommends keeping
// query strings short to reduce log-leak amplification; 8 KiB is well
// above any legitimate payload (id_token_hint + post_logout_redirect_uri
// + state + client_id) and well below the practical browser / proxy
// query-length limits, so a hostile request that slips a multi-KiB
// state value through is rejected before any further processing.
const maxQueryBytes = 8 * 1024

// maxStateBytes caps the byte-length of the "state" query parameter
// the OP echoes back on the post-logout redirect. OIDC RP-Initiated
// Logout 1.0 §3 does not bound the value, but real RPs use 128 - 512
// byte opaque tokens; 2 KiB is comfortably above that while bounding
// the server-side reflection surface against a hostile RP that crafts
// an oversized state to amplify response size or leak data through
// the redirect target.
const maxStateBytes = 2 * 1024

// request carries the parsed parameters the handler operates on. The
// fields mirror the OIDC RP-Initiated Logout 1.0 §2 wire shape minus
// the parameters the handler ignores entirely (logout_hint — see the
// package godoc for why). Adding an ignored field back is purely
// additive when the library grows a chooser UX surface.
type request struct {
	idTokenHint      string
	clientID         string
	postLogout       string
	state            string
	logoutScope      string
	scopeFingerprint string
	chooserGroupID   string
	// uiLocales is the space-delimited OIDC RP-Initiated Logout §2
	// "ui_locales" preference. It feeds the confirmation page's locale
	// resolution and is read nowhere else.
	uiLocales string
}

// validateRequestBounds enforces the per-parameter size caps the
// /end_session endpoint applies to mitigate amplification / log-leak
// attacks against the post-logout redirect target. The bounds:
//
//   - state at [maxStateBytes] (2 KiB). The value is echoed back on
//     the post-logout redirect; an unbounded state amplifies the
//     attacker-controllable payload that lands in proxy logs and
//     browser history.
//
// Other parameters (id_token_hint, post_logout_redirect_uri,
// client_id) inherit the [maxQueryBytes] / [endpointsupport.MaxFormBytes]
// gate readValues installed; the per-field cap here applies to the one
// value that flows back to the user agent.
func validateRequestBounds(w http.ResponseWriter, req request) bool {
	if len(req.state) > maxStateBytes {
		writeLogoutError(w, http.StatusRequestURITooLong, descRequestTooLarge)
		return false
	}
	return true
}

// readValues enforces the method / content-type / size invariants and
// returns the parsed parameter map. The bool reports whether the
// caller should continue: false means a response was already written.
//
// On the GET branch the function caps [http.Request.URL.RawQuery] at
// [maxQueryBytes]: a hostile RP that crafts a multi-megabyte query
// string would otherwise force the OP to allocate megabytes of
// url-decoded form state before the per-field validation runs. The
// 8 KiB cap is well above the documented sum of legitimate parameters
// (id_token_hint + post_logout_redirect_uri + state + client_id) and
// well below the practical browser / proxy query-length limits.
func readValues(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead+", "+http.MethodPost)
		writeLogoutError(w, http.StatusMethodNotAllowed, descMethodNotAllowed)
		return nil, false
	}
	if r.Method == http.MethodPost {
		if !isFormContent(r.Header.Get("Content-Type")) {
			writeLogoutError(w, http.StatusBadRequest, descContentTypeRequired)
			return nil, false
		}
		endpointsupport.LimitFormBody(w, r)
		if err := r.ParseForm(); err != nil {
			writeLogoutError(w, http.StatusBadRequest, descMalformedForm)
			return nil, false
		}
		return r.PostForm, true
	}
	if r.URL != nil && len(r.URL.RawQuery) > maxQueryBytes {
		writeLogoutError(w, http.StatusRequestURITooLong, descRequestTooLarge)
		return nil, false
	}
	return r.URL.Query(), true
}

// parseRequest projects the raw parameter map onto the typed
// [request]. "ui_locales" is extracted because the confirmation page
// resolves its strings and the parameter is that chain's second link;
// the value reaches [i18n.Resolver.Resolve] and nothing else, so it is
// never logged or echoed. "logout_hint" is still intentionally not
// extracted: no surface consumes it, and storing the value would only
// invite a future regression that surfaces it through a log line or
// audit record without sanitisation.
func parseRequest(v url.Values) request {
	scope := logoutScopeAll
	if raw, ok := v["logout_scope"]; ok && len(raw) == 1 {
		scope = raw[0]
	}
	return request{
		idTokenHint:      v.Get("id_token_hint"),
		clientID:         v.Get("client_id"),
		postLogout:       v.Get("post_logout_redirect_uri"),
		state:            v.Get("state"),
		logoutScope:      scope,
		scopeFingerprint: v.Get("logout_scope_fingerprint"),
		chooserGroupID:   v.Get("chooser_group_id"),
		uiLocales:        v.Get("ui_locales"),
	}
}

func validateLogoutScope(w http.ResponseWriter, values url.Values, scope string) bool {
	if _, present := values["logout_scope"]; !present {
		return true
	}
	if scope == logoutScopeCurrent {
		return true
	}
	writeLogoutError(w, http.StatusBadRequest, descInvalidLogoutScope)
	return false
}

// isFormContent reports whether ct is application/x-www-form-urlencoded,
// tolerating optional parameters. Mirrors the helper in the sibling
// endpoints so the form-content contract stays uniform.
func isFormContent(ct string) bool {
	return endpointsupport.IsFormContent(ct)
}

package authorizeendpoint

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// errBadQValue signals a malformed q-value in an Accept header. The
// caller's contract is to fall back to the default (q=1) so a single
// bad entry does not poison the rest of the negotiation.
var errBadQValue = errors.New("authorizeendpoint: malformed q-value")

// OAuth wire codes the /authorize and /interaction handlers emit
// directly. The list is closed; ad-hoc codes are forbidden so the
// discoverable error surface stays auditable. Codes the endpoint emits
// through another package's catalogue are absent so there is exactly one
// definition of each: the request-gate codes — RFC 9396 §5's
// "invalid_authorization_details" among them — come from
// [internal/authorize]'s sentinels, whose Code
// [validateRequestExtensions] renders verbatim.
const (
	errInvalidRequest           = "invalid_request"
	errLoginRequired            = "login_required"
	errConsentRequired          = "consent_required"
	errInteractionRequired      = "interaction_required"
	errAccessDenied             = "access_denied"
	errAccountSelectionRequired = "account_selection_required"
	errServerError              = "server_error"
	errUnsupportedResponseType  = "unsupported_response_type"
	errUnsupportedResponseMode  = "unsupported_response_mode"
	errInvalidScope             = "invalid_scope"
	errInvalidRequestObject     = "invalid_request_object"
	errInvalidRequestURI        = "invalid_request_uri"
	// errInvalidGrant is the OAuth wire code the Grant Management draft
	// returns when a grant_management_action references a grant_id the
	// authenticated client does not own.
	errInvalidGrant = "invalid_grant"
	// errUnmetAuthenticationRequirements is the OIDC wire code for
	// "the authentication that ran cannot satisfy the authentication
	// context the request required". The OP emits it when the resolved
	// acr fails an acr the request marked essential (OIDC Core 1.0
	// §5.5.1.1); a voluntary request is instead served with the acr
	// claim omitted. Registered by the OpenID Connect Core Error Code
	// unmet_authentication_requirements 1.0 extension and referenced by
	// RFC 9470 §4 for the step-up case.
	errUnmetAuthenticationRequirements = "unmet_authentication_requirements"
)

// errorResponse mirrors the token endpoint's failure envelope so embedders
// see a single shape across both endpoints.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// renderJSONError writes an RFC 6749 §5.2-shaped envelope. It exists for
// failure paths that cannot redirect to the RP — typically pre-redirect_uri
// validation or a structurally malformed /interaction request.
func renderJSONError(w http.ResponseWriter, status int, code, description string) {
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: code, ErrorDescription: description})
}

// renderBrowserError is the content-negotiating counterpart to
// renderJSONError. When the request advertises text/html and the
// configured [interaction.Driver] satisfies [interaction.ErrorRenderer]
// the function delegates to RenderError so the embedder's UI layer
// (HTML or SPA) owns the rendered surface; otherwise it falls back to
// the canonical JSON envelope.
//
// state is the RP-supplied "state" parameter when one parsed cleanly
// before the failure; an empty string skips the field on the wire.
//
// Use this on /authorize-side failure paths where the user is reached
// via a browser navigation (no safe redirect target). The /interaction
// helpers stay on renderJSONError because their callers are XHR / fetch
// from the SPA.
func renderBrowserError(w http.ResponseWriter, r *http.Request, driver interaction.Driver, status int, code, description, state string) {
	if driver != nil && wantsHTMLResponse(r) {
		if er, ok := driver.(interaction.ErrorRenderer); ok {
			if err := er.RenderError(w, r, interaction.ErrorPrompt{
				Code:        code,
				Description: description,
				State:       state,
				Status:      status,
			}); err == nil {
				return
			}
			// Fall through to JSON: a partial HTML write may have
			// already touched the response, but renderJSONError is
			// idempotent against headers already stamped and a second
			// status code call is a no-op on net/http.
		}
	}
	renderJSONError(w, status, code, description)
}

// wantsHTMLResponse reports whether the request's Accept header gives
// text/html priority over application/json. The check is deliberately
// coarse: any Accept that names text/html with a non-zero q-value and
// does not name application/json with a strictly higher q-value tips
// the response to HTML. An absent or "*/*"-only Accept stays on the
// JSON path so XHR / cURL / API clients keep their existing envelope.
func wantsHTMLResponse(r *http.Request) bool {
	if r == nil {
		return false
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	htmlQ, htmlOK := acceptQuality(accept, "text/html")
	jsonQ, jsonOK := acceptQuality(accept, "application/json")
	if !htmlOK {
		return false
	}
	if jsonOK && jsonQ > htmlQ {
		return false
	}
	return true
}

// acceptQuality returns the q-value associated with the named media
// type in the Accept header, or 0/false when the type is absent. Only
// exact type/subtype matches count; "*/*" and "text/*" are ignored so
// a generic accept does not push a JSON-default endpoint into HTML.
func acceptQuality(accept, target string) (float64, bool) {
	for _, raw := range strings.Split(accept, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		mediaType, params, _ := strings.Cut(entry, ";")
		if !strings.EqualFold(strings.TrimSpace(mediaType), target) {
			continue
		}
		q := 1.0
		for _, p := range strings.Split(params, ";") {
			kv := strings.TrimSpace(p)
			if !strings.HasPrefix(strings.ToLower(kv), "q=") {
				continue
			}
			val := strings.TrimSpace(kv[2:])
			parsed, err := parseQValue(val)
			if err != nil {
				continue
			}
			q = parsed
		}
		return q, true
	}
	return 0, false
}

// parseQValue accepts the digits-and-decimal subset RFC 7231 §5.3.1
// permits ("0", "0.5", "1", "1.000"). It exists rather than calling
// strconv directly so a malformed q-value does not silently ride
// through with an unrelated default.
func parseQValue(s string) (float64, error) {
	var (
		val      float64
		dec      float64 = 1
		afterDot bool
	)
	for _, ch := range s {
		switch {
		case ch == '.':
			if afterDot {
				return 0, errBadQValue
			}
			afterDot = true
		case ch >= '0' && ch <= '9':
			if afterDot {
				dec /= 10
				val += float64(ch-'0') * dec
			} else {
				val = val*10 + float64(ch-'0')
			}
		default:
			return 0, errBadQValue
		}
	}
	if val < 0 || val > 1 {
		return 0, errBadQValue
	}
	return val, nil
}

// mergeRedirectParams merges params into the query string of
// redirectURI, preserving any parameters the registered URI already
// carried (a static analytics suffix is a common registration). It is
// the single query-merge used by every redirect-mode authorization
// response, success and error alike, so the two cannot drift on
// encoding or on the treatment of a pre-existing query.
//
// Empty values are skipped: an absent state or iss must not surface as
// a stray "state=" on the wire.
func mergeRedirectParams(redirectURI string, params url.Values) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for name := range params {
		if v := params.Get(name); v != "" {
			q.Set(name, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// stampNoStore writes the cache headers every authorize / interaction
// response carries. The values match the token endpoint so embedders that
// monitor "no-store" presence see a uniform posture.
func stampNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

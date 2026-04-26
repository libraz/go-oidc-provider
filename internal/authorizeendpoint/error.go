package authorizeendpoint

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// OAuth wire codes the /authorize and /interaction handlers emit. The list
// is closed; ad-hoc codes are forbidden so the discoverable error surface
// stays auditable.
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

// redirectError emits a 302 to the RP's redirect_uri with the OAuth error
// parameters attached. The state parameter is echoed verbatim per OAuth
// 2.0 §4.1.2.1; an empty state is omitted entirely.
//
// The function never inspects the existing query string of redirectURI: the
// authorize parser has already verified that the URI parses cleanly, and we
// preserve any existing query the client registered.
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, code, description, state string) {
	target, err := buildRedirectError(redirectURI, code, description, state)
	if err != nil {
		// The redirect target is unparseable; fall back to the JSON
		// envelope so the operator gets a useful diagnostic instead of
		// a silent 302-to-nothing.
		renderJSONError(w, http.StatusInternalServerError, errServerError, "redirect target rejected")
		return
	}
	stampNoStore(w)
	http.Redirect(w, r, target, http.StatusFound)
}

// buildRedirectError composes the redirect target. It is split out so the
// query-merge logic can be unit-tested without invoking the HTTP machinery.
func buildRedirectError(redirectURI, code, description, state string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
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

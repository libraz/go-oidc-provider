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
	errInvalidRequestObject     = "invalid_request_object"
	errInvalidRequestURI        = "invalid_request_uri"
	// errInvalidAuthorizationDetails is RFC 9396 §5's wire code for an
	// authorization_details parameter the OP cannot honour (unknown type,
	// malformed structure, validator rejection).
	errInvalidAuthorizationDetails = "invalid_authorization_details"
	// errInvalidGrant is the OAuth wire code the Grant Management draft
	// returns when a grant_management_action references a grant_id the
	// authenticated client does not own.
	errInvalidGrant = "invalid_grant"
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

// redirectError emits a 302 to the RP's redirect_uri with the OAuth error
// parameters attached. The state parameter is echoed verbatim per OAuth
// 2.0 §4.1.2.1; an empty state is omitted entirely.
//
// The function never inspects the existing query string of redirectURI: the
// authorize parser has already verified that the URI parses cleanly, and we
// preserve any existing query the client registered.
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, code, description, state, issuer string) {
	target, err := buildRedirectError(redirectURI, code, description, state, issuer)
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
func buildRedirectError(redirectURI, code, description, state, issuer string) (string, error) {
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
	if issuer != "" {
		// RFC 9207 §2.4: error responses also carry "iss". Skipping
		// it on the error path would defeat the mix-up protection the
		// success path already has.
		q.Set("iss", issuer)
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

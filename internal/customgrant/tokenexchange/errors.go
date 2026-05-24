package tokenexchange

import (
	"net/http"
)

// wireError is the local error shape that satisfies the structural
// op.Error contract (OAuthCode + WriteOAuthError). The public op.Error
// type is owned by the op package; internal/* cannot import op so we
// emit values whose dispatch through the tokenendpoint wire writer
// goes through the same opErrorWriter interface check.
type wireError struct {
	code        string
	description string
}

// Error implements the error interface in the canonical
// "<code>: <description>" shape op.Error.Error uses.
func (e *wireError) Error() string {
	if e.description == "" {
		return e.code
	}
	return e.code + ": " + e.description
}

// OAuthCode returns the wire code so the handler-side oauthCoded
// detection picks the value up.
func (e *wireError) OAuthCode() string {
	return e.code
}

// WriteOAuthError renders the receiver as an RFC 6749 §5.2 envelope.
// The signature mirrors the public op.Error.WriteOAuthError so the
// tokenendpoint wire writer's opErrorWriter assertion fires.
func (e *wireError) WriteOAuthError(w http.ResponseWriter) {
	status := http.StatusBadRequest
	switch e.code {
	case "invalid_client":
		status = http.StatusUnauthorized
	case "server_error", "temporarily_unavailable", "configuration_error":
		status = http.StatusInternalServerError
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := `{"error":"` + e.code + `"`
	if e.description != "" {
		body += `,"error_description":"` + jsonEscape(e.description) + `"`
	}
	body += `}` + "\n"
	_, _ = w.Write([]byte(body))
}

// jsonEscape escapes a string for safe inclusion inside a JSON value.
// We avoid the encoding/json import here because every emission path
// is a fixed-shape envelope; the helper is intentionally minimal.
func jsonEscape(s string) string {
	out := make([]byte, 0, len(s)+8)
	for i := range len(s) {
		c := s[i]
		switch c {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if c < 0x20 {
				continue
			}
			out = append(out, c)
		}
	}
	return string(out)
}

// invalidRequest builds an invalid_request wireError.
func invalidRequest(description string) error {
	return &wireError{code: "invalid_request", description: description}
}

// invalidGrant builds an invalid_grant wireError.
func invalidGrant(description string) error {
	return &wireError{code: "invalid_grant", description: description}
}

// invalidScope builds an invalid_scope wireError.
func invalidScope(description string) error {
	return &wireError{code: "invalid_scope", description: description}
}

// invalidTarget builds an invalid_target wireError. RFC 8707 §4 named
// the code; the dispatcher's wire writer recognises it without further
// translation.
func invalidTarget(description string) error {
	return &wireError{code: "invalid_target", description: description}
}

package tokenexchange

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
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
	endpointsupport.WriteOAuthError(w, status, e.code, e.description)
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

// serverError builds a server_error wireError for a store the exchange
// could not read.
func serverError() error {
	return &wireError{code: "server_error"}
}

// invalidTarget builds an invalid_target wireError. RFC 8707 §4 named
// the code; the dispatcher's wire writer recognises it without further
// translation.
func invalidTarget(description string) error {
	return &wireError{code: "invalid_target", description: description}
}

// accessDenied builds an access_denied wireError for an issuance the
// embedder's policy refused.
func accessDenied(description string) error {
	return &wireError{code: "access_denied", description: description}
}

// invalidClient builds an invalid_client wireError, written with 401.
func invalidClient(description string) error {
	return &wireError{code: "invalid_client", description: description}
}

package registrationendpoint

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
)

// RFC 7591 §3.2.2 / RFC 6749 §5.2 wire codes the handler emits. The
// list is closed; ad-hoc codes are forbidden so the discoverable error
// surface stays auditable.
const (
	codeInvalidRequest        = "invalid_request"
	codeInvalidToken          = "invalid_token"
	codeInvalidClientMetadata = "invalid_client_metadata"
	codeInvalidRedirectURI    = "invalid_redirect_uri"
	codeInvalidSoftwareStmt   = "invalid_software_statement"
	codeServerError           = "server_error"
)

// errorResponse is the JSON envelope every failure path returns. The
// shape mirrors the token / PAR endpoint envelopes so embedders see a
// single error surface across the library.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeRegistrationError emits the §3.2.2 envelope with the supplied
// status, code, and description. Cache-Control: no-store is stamped
// here so every registration failure response is uncacheable without
// each call site repeating the header; callers MUST NOT re-stamp it.
func writeRegistrationError(w http.ResponseWriter, status int, code, description string) {
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := errorResponse{Error: code, ErrorDescription: description}
	// Encoding a tiny fixed-shape struct into a buffered writer never
	// fails in practice; an error here would be a programmer bug, not
	// a runtime fault. Drop the error rather than risk a partial body
	// collision with the WriteHeader call we already issued.
	_ = json.NewEncoder(w).Encode(body)
}

// writeInvalidToken is the dedicated 401 path for the "invalid_token"
// code. RFC 6750 §3 mandates a WWW-Authenticate Bearer challenge so
// RP libraries that follow the bearer state machine retry intelligently.
// The realm value is the OP issuer, which names the protection space
// unambiguously even when several OPs sit behind one host. Every value
// passes the shared challenge sanitiser.
func writeInvalidToken(w http.ResponseWriter, issuer, description string) {
	w.Header().Set("WWW-Authenticate", endpointsupport.BuildBearerChallenge(endpointsupport.BearerSchemeBearer,
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeRealm, Value: issuer},
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeError, Value: codeInvalidToken},
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeErrorDescription, Value: sanitizeDescription(description)},
	))
	writeRegistrationError(w, http.StatusUnauthorized, codeInvalidToken, description)
}

// stampNoStore writes the cache-control headers RFC 7591 §3.2 mandates
// on every registration response; the OP applies them to failures as
// well so no intermediary caches an error envelope.
// Splitting the helper keeps the success and error paths from drifting.
func stampNoStore(w http.ResponseWriter) {
	endpointsupport.StampNoStore(w)
}

// sanitizeDescription scrubs an embedder-supplied error string so it is
// safe to embed in error_description without leaking internal details
// (DB names, SQL fragments, stack traces). The rules are: strip control
// characters and CR/LF, collapse whitespace, and truncate to 200
// characters.
func sanitizeDescription(s string) string {
	if s == "" {
		return s
	}
	// Remove CR/LF first so multi-line errors collapse to a single
	// line; then trim to control character allowlist.
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxDescriptionBytes {
		s = s[:maxDescriptionBytes]
	}
	return s
}

// maxDescriptionBytes is the ceiling applied to embedder-supplied
// error_description strings. 200 is enough for an operator hint while
// short enough to defeat accidental exposure of multi-kilobyte stack
// traces in error logs.
const maxDescriptionBytes = 200

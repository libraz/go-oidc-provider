package registrationendpoint

import (
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
)

// RFC 7591 §3.2.2 / RFC 6750 §3.1 wire codes the handler emits beyond
// the RFC 6749 §5.2 set in endpointsupport. The list is closed; ad-hoc
// codes are forbidden so the discoverable error surface stays auditable.
const (
	codeInvalidToken          = "invalid_token"
	codeInvalidClientMetadata = "invalid_client_metadata"
	codeInvalidRedirectURI    = "invalid_redirect_uri"
	codeInvalidSoftwareStmt   = "invalid_software_statement"
)

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
	endpointsupport.WriteOAuthError(w, http.StatusUnauthorized, codeInvalidToken, description)
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

package rs

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// Error codes the package reports in [Error.Code].
const (
	codeInvalidRequest    = "invalid_request"
	codeInvalidToken      = "invalid_token"
	codeInsufficientScope = "insufficient_scope"
	codeInsufficientAuthn = "insufficient_user_authentication"
	codeInvalidDPoPProof  = "invalid_dpop_proof"
)

const (
	schemeNameBearer = "Bearer"
	schemeNameDPoP   = "DPoP"
)

// authScheme is the authorization scheme a request presented its token
// under. It decides which challenge carries the error attributes.
type authScheme int

const (
	schemeNone authScheme = iota
	schemeBearer
	schemeDPoP
	schemeOther
)

// Error is a failed verification. Status is the HTTP status the
// middleware writes; Code is the error code of the challenge, empty when
// the request carried no credentials (RFC 6750 §3.1) or when the failure
// is the server's own (Status 503: discovery, JWK Set, introspection or
// the replay store was unreachable).
//
// Stable since v1.5.
type Error struct {
	// Status is the HTTP status code: 400, 401, 403 or 503.
	Status int

	// Code is one of invalid_request, invalid_token, insufficient_scope
	// (RFC 6750 §3.1), insufficient_user_authentication (RFC 9470 §3) and
	// invalid_dpop_proof (RFC 9449 §7.1), or empty.
	Code string

	// Description is a fixed, human-readable explanation. It never
	// echoes request data and is safe to return to the client.
	Description string

	// Scope lists the scopes the request needed, for insufficient_scope.
	Scope []string

	// ACRValues lists the acr values the request needed, for
	// insufficient_user_authentication.
	ACRValues []string

	// MaxAge is the authentication age the request needed, for
	// insufficient_user_authentication. Zero omits the attribute.
	MaxAge time.Duration

	mode   DPoPMode
	realm  string
	scheme authScheme
}

// Error implements the error interface.
//
// Stable since v1.5.
func (e *Error) Error() string {
	if e.Code == "" {
		return "rs: " + e.Description
	}
	return "rs: " + e.Code + ": " + e.Description
}

// WWWAuthenticate returns the WWW-Authenticate header value for e.
//
// Under [DPoPAllowed] it holds two challenges, Bearer (with the
// verifier's audience as realm) and DPoP (with the accepted proof algs),
// and the error attributes ride only on the challenge of the scheme the
// client used; a request without credentials gets neither challenge's
// error attributes. Under [DPoPRequired] it holds the DPoP challenge
// alone. Scope, ACRValues and MaxAge become the scope, acr_values and
// max_age attributes.
//
// Stable since v1.5.
func (e *Error) WWWAuthenticate() string {
	attrs := e.errorParams()
	dpopParams := []string{quotedParam("algs", strings.Join(dpop.SupportedProofAlgs(), " "))}
	if e.mode == DPoPRequired {
		if e.scheme != schemeNone {
			dpopParams = append(dpopParams, attrs...)
		}
		return challenge(schemeNameDPoP, dpopParams)
	}
	var bearerParams []string
	if e.realm != "" {
		bearerParams = append(bearerParams, quotedParam("realm", e.realm))
	}
	switch e.scheme {
	case schemeBearer:
		bearerParams = append(bearerParams, attrs...)
	case schemeDPoP:
		dpopParams = append(dpopParams, attrs...)
	case schemeOther:
		bearerParams = append(bearerParams, attrs...)
		dpopParams = append(dpopParams, attrs...)
	case schemeNone:
	}
	return challenge(schemeNameBearer, bearerParams) + ", " + challenge(schemeNameDPoP, dpopParams)
}

// errorParams renders the error attributes, or nothing when there is no
// error code to report.
func (e *Error) errorParams() []string {
	if e.Code == "" {
		return nil
	}
	out := []string{quotedParam("error", e.Code)}
	if e.Description != "" {
		out = append(out, quotedParam("error_description", e.Description))
	}
	if len(e.Scope) > 0 {
		out = append(out, quotedParam("scope", strings.Join(e.Scope, " ")))
	}
	if len(e.ACRValues) > 0 {
		out = append(out, quotedParam("acr_values", strings.Join(e.ACRValues, " ")))
	}
	if e.MaxAge > 0 {
		out = append(out, quotedParam("max_age", strconv.FormatInt(int64(e.MaxAge/time.Second), 10)))
	}
	return out
}

// writesChallenge reports whether the status is one a challenge belongs to.
func (e *Error) writesChallenge() bool {
	switch e.Status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return true
	default:
		return false
	}
}

func challenge(scheme string, params []string) string {
	if len(params) == 0 {
		return scheme
	}
	return scheme + " " + strings.Join(params, ", ")
}

// quotedParam renders name="value" with value as an RFC 9110 §5.6.4
// quoted-string.
func quotedParam(name, value string) string {
	var b strings.Builder
	b.Grow(len(name) + len(value) + 3)
	b.WriteString(name)
	b.WriteString(`="`)
	for i := range len(value) {
		if c := value[i]; c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(value[i])
	}
	b.WriteByte('"')
	return b.String()
}

func invalidRequest(desc string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Description: desc}
}

func invalidToken(desc string) *Error {
	return &Error{Status: http.StatusUnauthorized, Code: codeInvalidToken, Description: desc}
}

func invalidProof(desc string) *Error {
	return &Error{Status: http.StatusUnauthorized, Code: codeInvalidDPoPProof, Description: desc}
}

func unavailable(desc string) *Error {
	return &Error{Status: http.StatusServiceUnavailable, Description: desc}
}

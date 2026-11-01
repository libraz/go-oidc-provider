package ssf

import (
	"errors"
	"io"
	"net/http"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// Scopes a receiver obtains through client_credentials. ssf.manage
// implies ssf.read.
const (
	ScopeRead   = "ssf.read"
	ScopeManage = "ssf.manage"
)

// mgmtMaxBody caps every management and poll request body; it is the cap
// [endpointsupport.LimitFormBody] enforces.
const mgmtMaxBody = endpointsupport.MaxFormBytes

// authLevel is the scope an endpoint operation requires.
type authLevel int

const (
	// authRead admits ssf.read or ssf.manage.
	authRead authLevel = iota
	// authManage admits ssf.manage only.
	authManage
)

const (
	authDescAudience = "The access token is not issued for this transmitter"
	authDescScope    = "The access token lacks the required scope"
)

// authorize accepts the request's access token and checks that its
// audience contains the issuer and its scope covers level. It returns
// the receiver's client_id, or writes the RFC 6750 §3.1 rejection and
// reports false.
func (h *Handlers) authorize(w http.ResponseWriter, r *http.Request, level authLevel) (string, bool) {
	access, err := endpointsupport.AcceptBearer(r, h.bearer)
	if err != nil {
		httpx.StampNoStore(w)
		var be *endpointsupport.BearerError
		if errors.As(err, &be) {
			be.WriteResponse(w)
			return "", false
		}
		_ = httpx.WriteError(w, http.StatusInternalServerError, "server_error", "")
		return "", false
	}
	claims := access.Claims
	scheme := authScheme(claims)
	// AcceptBearer admits an absent audience; a management token must
	// name this OP, so a token minted for a resource (RFC 8707) is refused.
	if claims.ClientID == "" || !slices.Contains(claims.Audience, h.issuer) {
		authChallenge(w, http.StatusUnauthorized, scheme, "invalid_token", authDescAudience, "")
		return "", false
	}
	if !authScopeCovers(claims.Scope, level) {
		want := ScopeRead
		if level == authManage {
			want = ScopeManage
		}
		authChallenge(w, http.StatusForbidden, scheme, "insufficient_scope", authDescScope, want)
		return "", false
	}
	return claims.ClientID, true
}

// authScopeCovers reports whether scope grants level.
func authScopeCovers(scope []string, level authLevel) bool {
	if slices.Contains(scope, ScopeManage) {
		return true
	}
	return level == authRead && slices.Contains(scope, ScopeRead)
}

// authScheme is the challenge scheme matching how the token is bound.
func authScheme(c *tokens.AccessTokenClaims) string {
	if c.Confirmation[tokens.CnfJKT] != "" {
		return endpointsupport.BearerSchemeDPoP
	}
	return endpointsupport.BearerSchemeBearer
}

// authChallenge writes a WWW-Authenticate challenge with an OAuth error body.
func authChallenge(w http.ResponseWriter, status int, scheme, code, desc, scope string) {
	w.Header().Set("WWW-Authenticate", endpointsupport.BuildBearerChallenge(scheme,
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeError, Value: code},
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeErrorDescription, Value: desc},
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeScope, Value: scope},
	))
	_ = httpx.WriteError(w, status, code, desc)
}

// errMgmtBodyTooLarge reports a request body past [mgmtMaxBody].
var errMgmtBodyTooLarge = errors.New("ssf: request body too large")

// mgmtReadBody reads the bounded request body. An empty body is returned as
// nil without error.
func mgmtReadBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	endpointsupport.LimitFormBody(w, r)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errMgmtBodyTooLarge
		}
		return nil, err
	}
	return b, nil
}

// mgmtWriteBodyError maps a [mgmtReadBody] or decode failure onto 413 or 400.
func mgmtWriteBodyError(w http.ResponseWriter, err error) {
	if errors.Is(err, errMgmtBodyTooLarge) {
		_ = httpx.WriteError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
		return
	}
	var re *mgmtRequestError
	if errors.As(err, &re) {
		_ = httpx.WriteError(w, http.StatusBadRequest, "invalid_request", re.desc)
		return
	}
	_ = httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
}

// mgmtRequestError is a 400 with a description safe to return.
type mgmtRequestError struct{ desc string }

func (e *mgmtRequestError) Error() string { return "ssf: " + e.desc }

func mgmtBadRequest(desc string) error { return &mgmtRequestError{desc: desc} }

// mgmtServerError writes an opaque 500.
func mgmtServerError(w http.ResponseWriter) {
	_ = httpx.WriteError(w, http.StatusInternalServerError, "server_error", "")
}

// mgmtNotFound writes the 404 that hides another receiver's stream.
func mgmtNotFound(w http.ResponseWriter) {
	_ = httpx.WriteError(w, http.StatusNotFound, "not_found", "stream not found")
}

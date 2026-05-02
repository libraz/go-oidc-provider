package tokenendpoint

import (
	"errors"
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/customgrant"
)

// handleCustomGrant routes the request to the dispatcher the OP
// constructed from [op.WithCustomGrant] registrations. Authentication
// runs through the same chain the built-in grants use; DPoP / mTLS
// verification follows the same ordering so a custom grant inherits
// the FAPI 2.0 §3.1.4 sender-constraint posture without per-handler
// boilerplate. The function never mints tokens itself: the handler's
// returned access_token is written verbatim, the dispatcher having
// already enforced TTL / scope / audience invariants.
func handleCustomGrant(w http.ResponseWriter, r *http.Request, deps Deps, grantType string) {
	ctx := r.Context()
	client, _, ok := authenticate(ctx, w, r, deps)
	if !ok {
		return
	}
	dpopOut, ok := verifyTokenDPoP(w, r, deps)
	if !ok {
		return
	}
	mtlsOut, ok := verifyTokenMTLS(w, r, deps, dpopOut.JKT)
	if !ok {
		return
	}
	binding := tokenBinding{
		DPoPJKT:        dpopOut.JKT,
		MTLSThumbprint: mtlsOut.Thumbprint,
	}
	if !enforceSenderConstraint(w, deps, binding) {
		return
	}
	// DPoPJTI / MTLSCert ride into the dispatcher so handler audit
	// emission can correlate the wire request with the verified
	// proof / leaf cert. Both values are read-only by contract; the
	// wire response shape is unaffected because cnf.jkt /
	// cnf.x5t#S256 stamping happens in the binding pipeline
	// regardless.
	dispatchIn := customgrant.DispatchInput{
		GrantType: grantType,
		Client:    client,
		Form:      r.PostForm,
		DPoPJKT:   dpopOut.JKT,
		DPoPJTI:   dpopOut.JTI,
	}
	if mtlsOut.Cert != nil {
		dispatchIn.MTLSCert = mtlsOut.Cert
	}
	resp, err := deps.CustomGrants.Dispatch(ctx, dispatchIn)
	if err != nil {
		writeCustomGrantError(w, err)
		return
	}
	writeSuccess(w, successResponse{
		AccessToken:  resp.AccessToken,
		TokenType:    binding.tokenTypeFor(),
		ExpiresIn:    int64(resp.AccessTokenTTL.Seconds()),
		RefreshToken: resp.RefreshToken,
		IDToken:      resp.IDToken,
		Scope:        joinScope(resp.Scope),
	})
}

// writeCustomGrantError translates the dispatcher's typed sentinels
// into the RFC 6749 §5.2 wire envelope. Sentinels the dispatcher
// owns map onto deterministic codes; an upstream *Error returned by
// the handler is propagated verbatim through the [opErrorWriter]
// interface check so a handler that synthesises its own wire shape
// keeps it.
func writeCustomGrantError(w http.ResponseWriter, err error) {
	if hookErr, ok := err.(opErrorWriter); ok {
		hookErr.WriteOAuthError(w)
		return
	}
	switch {
	case errors.Is(err, customgrant.ErrUnknownGrant):
		writeError(w, http.StatusBadRequest, errUnsupportedGrantType,
			"grant_type is not supported")
	case errors.Is(err, customgrant.ErrClientGrantNotPermitted):
		writeError(w, http.StatusBadRequest, errUnauthorizedClient,
			"client is not authorized for this grant_type")
	case errors.Is(err, customgrant.ErrUnknownParameter),
		errors.Is(err, customgrant.ErrDuplicateParameter),
		errors.Is(err, customgrant.ErrDuplicateCapExceeded):
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			sanitizeMessage(err))
	case errors.Is(err, customgrant.ErrScopeNotAllowed):
		writeError(w, http.StatusBadRequest, errInvalidScope,
			"response scope exceeds the client's allowed set")
	case errors.Is(err, customgrant.ErrAudienceNotAllowed):
		writeError(w, http.StatusBadRequest, errInvalidTarget,
			"response audience exceeds the client's registered resources")
	case errors.Is(err, customgrant.ErrEmptyAccessToken),
		errors.Is(err, customgrant.ErrNegativeTTL),
		errors.Is(err, customgrant.ErrPanic):
		writeError(w, http.StatusInternalServerError, errServerError, "")
	default:
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"the supplied grant could not be honoured")
	}
}

// opErrorWriter is the structural interface a handler-supplied
// error MAY satisfy to pin the wire shape of its rejection. The
// op-side [op.Error] type implements it; a handler that returns
// such an error short-circuits the sentinel translation table.
type opErrorWriter interface {
	WriteOAuthError(w http.ResponseWriter)
}

// sanitizeMessage strips any embedded parameter name from the
// dispatcher's "%w: %q" error format so the wire response carries
// only the failure family. The dispatcher's audit emission keeps
// the original parameter name on the operator-facing record.
func sanitizeMessage(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ":"); i > 0 {
		return msg[:i]
	}
	return msg
}

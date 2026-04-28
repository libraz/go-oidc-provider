package authorizeendpoint

import (
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/jarm"
)

// jarmModeForRequest returns the resolved JARM response mode the
// authorize endpoint should use, or the empty string when the request
// did not opt into JARM. The bare "jwt" alias is resolved against the
// request's response_type via [jarm.Resolve] so the caller does not
// need to repeat that step.
//
// When the request asks for a JARM mode but [resolved.JARM] is nil
// (the feature is off), the function still returns the resolved mode
// so the caller can detect the mismatch and emit the
// "unsupported_response_mode" error in the legacy redirect mode.
func jarmModeForRequest(req *authorize.Request) jarm.ResponseMode {
	mode, ok := jarm.Parse(req.ResponseMode)
	if !ok {
		return ""
	}
	return jarm.Resolve(mode, req.ResponseType)
}

// jarmFeatureRequested reports whether the request asked for any JARM
// mode. Used to gate the "feature off but JARM requested" error path.
func jarmFeatureRequested(req *authorize.Request) bool {
	return jarm.IsJARM(req.ResponseMode)
}

// jarmModeMissing reports whether the active configuration requires
// every authorize response to be JARM-wrapped (Deps.RequireJARMResponseMode
// is true) and this request did not opt into a JARM response_mode.
// True means /authorize must reject the request with
// unsupported_response_mode; false means continue. Symmetric to
// [jarmFeatureRequested]: the two cover the four cells of the
// (RequireJARMResponseMode × IsJARM) matrix.
func jarmModeMissing(deps resolved, req *authorize.Request) bool {
	return deps.RequireJARMResponseMode && !jarmFeatureRequested(req)
}

// jarmEmitSuccess writes the success response as a JARM JWT in the
// resolved mode. The function returns an error when JWT signing or
// dispatch fails; callers translate the error into the legacy redirect
// path so the RP still receives a determinate outcome.
func jarmEmitSuccess(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	mode jarm.ResponseMode,
	code string,
) error {
	if deps.JARM == nil {
		return errors.New("authorizeendpoint: JARM signer not configured")
	}
	jwtToken, err := deps.JARM.SignDefault(jarm.Payload{
		Audience: req.ClientID,
		Code:     code,
		State:    req.State,
	})
	if err != nil {
		return err
	}
	return jarmDispatch(w, r, mode, req.RedirectURI, jwtToken)
}

// jarmEmitError writes the error response as a JARM JWT in the
// resolved mode. As with [jarmEmitSuccess], a failure to sign /
// dispatch is propagated up so the caller can fall back to the legacy
// redirect emit path.
func jarmEmitError(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	mode jarm.ResponseMode,
	code, description string,
) error {
	if deps.JARM == nil {
		return errors.New("authorizeendpoint: JARM signer not configured")
	}
	jwtToken, err := deps.JARM.SignDefault(jarm.Payload{
		Audience:         req.ClientID,
		Error:            code,
		ErrorDescription: description,
		State:            req.State,
	})
	if err != nil {
		return err
	}
	return jarmDispatch(w, r, mode, req.RedirectURI, jwtToken)
}

// jarmDispatch runs the JWT through the appropriate emitter for mode:
// query / fragment redirects through the standard redirect helper,
// form_post.jwt renders an HTML body via [jarm.WriteFormPost].
func jarmDispatch(
	w http.ResponseWriter,
	r *http.Request,
	mode jarm.ResponseMode,
	redirectURI, jwtToken string,
) error {
	if mode == jarm.ResponseModeFormPostJWT {
		return jarm.WriteFormPost(w, redirectURI, jwtToken)
	}
	target, err := jarm.BuildRedirect(mode, redirectURI, jwtToken)
	if err != nil {
		return err
	}
	stampNoStore(w)
	http.Redirect(w, r, target, http.StatusFound)
	return nil
}

// emitAuthorizeSuccess sends the success-path response. When the
// request opted into a JARM mode and the feature is enabled, the
// response is a signed JWT delivered through the resolved mode;
// otherwise the function falls back to the legacy
// "?code=...&state=..." redirect. JARM signing failures degrade to the
// legacy redirect so the RP always receives a determinate outcome
// (the alternative — a 500 — would strand the user mid-flow).
func emitAuthorizeSuccess(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	code string,
) {
	if mode := jarmModeForRequest(req); mode != "" && deps.JARM != nil {
		if err := jarmEmitSuccess(w, r, deps, req, mode, code); err == nil {
			return
		}
		// Fall through to legacy emit on signer / dispatch failure.
	}
	stampNoStore(w)
	http.Redirect(w, r, buildSuccessRedirect(req.RedirectURI, code, req.State, deps.Issuer), http.StatusFound)
}

// emitAuthorizeError sends the error-path response. The legacy path is
// the same redirect [buildRedirectError] composes; the JARM path
// signs the error claims and dispatches via the resolved mode.
//
// JARM-modes-without-the-feature is handled here too: when the request
// asked for a JARM mode but [resolved.JARM] is nil, the function
// rewrites the wire code to "unsupported_response_mode" and emits the
// legacy redirect so the RP can detect the misconfiguration. This is
// the boundary contract documented in the package overview.
func emitAuthorizeError(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	code, description string,
) {
	if jarmFeatureRequested(req) && deps.JARM == nil {
		// The request asked for JARM but the feature is off. Surface
		// "unsupported_response_mode" via the legacy redirect — JARM
		// can't be used to convey "JARM is not supported".
		redirectError(w, r, req.RedirectURI, errUnsupportedResponseMode,
			"response_mode is not supported by this OP", req.State, deps.Issuer)
		return
	}
	if mode := jarmModeForRequest(req); mode != "" && deps.JARM != nil {
		if err := jarmEmitError(w, r, deps, req, mode, code, description); err == nil {
			return
		}
		// Fall through to legacy redirect on signer / dispatch failure.
	}
	redirectError(w, r, req.RedirectURI, code, description, req.State, deps.Issuer)
}

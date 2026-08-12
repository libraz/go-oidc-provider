package authorizeendpoint

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/jarm"
)

// formPostResponseMode is the OIDC Core Form Post Response Mode 1.0
// wire token. Unlike the JARM modes (which carry a single signed
// "response" JWT), this mode delivers each authorization response
// parameter as a separate hidden input — see [jarm.WriteParamsFormPost].
const formPostResponseMode = "form_post"

// jarmModeForRequest returns the resolved JARM response mode the
// authorize endpoint should use, or the empty string when the request
// did not opt into JARM. The bare "jwt" alias is resolved against the
// request's response_type via [jarm.Resolve] so the caller does not
// need to repeat that step.
//
// When the request asks for a JARM mode but [resolved.JARM] is nil
// (the feature is off), the function still returns the resolved mode
// so the caller can detect the mismatch and emit the
// "unsupported_response_mode" error through the plain response path.
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

// responseModeUsesFormPost reports whether the request's response_mode
// delivers the authorization response through an auto-submitted HTML
// form: the OIDC Core "form_post" mode or the JARM "form_post.jwt"
// mode, including the bare "jwt" alias when it resolves to the latter.
//
// Every plain-response form-post decision MUST consult this predicate
// rather than comparing against the "form_post" literal.
// A client picks a form-post mode precisely so the response parameters
// never enter a URL — where they land in browser history, in the
// Referer of whatever the landing page loads, and in every proxy log on
// the path — and a bare string compare silently misses "form_post.jwt",
// turning that choice into a 302.
func responseModeUsesFormPost(req *authorize.Request) bool {
	if req.ResponseMode == formPostResponseMode {
		return true
	}
	return jarmModeForRequest(req) == jarm.ResponseModeFormPostJWT
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
// resolved mode. The function returns an error when JWT signing, key
// lookup, encryption, or dispatch fails; callers convert that failure
// into an endpoint-local 500 response.
//
// When the client registered authorization_encrypted_response_alg /
// _enc the signed JWT is wrapped in a JWE before dispatch.
// Encryption failure on the success path is surfaced to the caller;
// [emitAuthorizeSuccess] then fails closed locally rather than
// exposing a code, state, or unsigned error through a redirect or
// partial form response.
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
	client, err := lookupClientForJARM(r.Context(), deps.Clients, req.ClientID)
	if err != nil {
		return errors.Join(errJARMEncryptionFailed, err)
	}
	jwtToken, err = maybeEncryptJARM(r.Context(), deps.ClientEncJWKs, client, jwtToken)
	if err != nil {
		return err
	}
	return jarmDispatch(w, r, mode, req.RedirectURI, jwtToken)
}

// jarmEmitError writes the error response as a JARM JWT in the
// resolved mode. As with [jarmEmitSuccess], a failure to sign, key
// lookup, encrypt, or dispatch is propagated up so the caller can
// fail closed with an endpoint-local 500.
//
// When the client registered authorization_encrypted_response_alg /
// _enc the signed error JWT is wrapped in a JWE before dispatch.
// Client lookup and encryption failures are propagated so the caller
// can emit an endpoint-local 500 without silently downgrading the
// client's registered confidentiality requirement.
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
	signed, err := deps.JARM.SignDefault(jarm.Payload{
		Audience:         req.ClientID,
		Error:            code,
		ErrorDescription: description,
		State:            req.State,
	})
	if err != nil {
		return err
	}
	client, err := lookupClientForJARM(r.Context(), deps.Clients, req.ClientID)
	if err != nil {
		return errors.Join(errJARMEncryptionFailed, err)
	}
	wire, err := maybeEncryptJARM(r.Context(), deps.ClientEncJWKs, client, signed)
	if err != nil {
		return err
	}
	return jarmDispatch(w, r, mode, req.RedirectURI, wire)
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
		// jarm.WriteFormPost writes headers and status before it writes the
		// body. Render into a private buffer first so a renderer failure can
		// become an OP-local 500 without leaking a partial form or leaving
		// the real writer committed to a redirect-shaped response.
		buffer := newBufferedResponseWriter()
		if err := jarm.WriteFormPost(buffer, redirectURI, jwtToken); err != nil {
			return err
		}
		return buffer.commit(w)
	}
	target, err := jarm.BuildRedirect(mode, redirectURI, jwtToken)
	if err != nil {
		return err
	}
	stampNoStore(w)
	//nolint:gosec // G710: redirectURI already exact-matched a registered entry in authorize.Validate; nothing reaches here on a mismatch.
	http.Redirect(w, r, target, http.StatusFound)
	return nil
}

// emitAuthorizeSuccess sends the success-path response. When the
// request opted into a JARM mode and the feature is enabled, the
// response is a signed JWT delivered through the resolved mode;
// otherwise the function emits the plain "?code=...&state=..." redirect
// or, for response_mode=form_post, the equivalent auto-submitted form.
//
// A JARM emit that fails does NOT fall back to a plain success or
// OAuth-error response. Every such shape is weaker than what the
// client contracted for: an unsigned response drops the JARM binding
// that authenticates the response against a mix-up, and a redirect or
// partial form can expose response data through the wrong channel. The
// function therefore emits only an endpoint-local 500 with no
// Location, state, code, or OAuth error fields; the minted code is
// simply never delivered and expires unredeemed on its own TTL.
func emitAuthorizeSuccess(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	code string,
) {
	if mode := jarmModeForRequest(req); mode != "" {
		if deps.JARM == nil {
			writeJARMFailure(w)
			return
		}
		err := jarmEmitSuccess(w, r, deps, req, mode, code)
		if err == nil {
			return
		}
		// Once JARM was selected, every redirect/form response shape is a
		// downgrade. Keep signing, key resolution, encryption, and
		// rendering failures OP-local; do not expose state, code, or even
		// an unsigned OAuth error to the browser/RP.
		writeJARMFailure(w)
		return
	}
	emitPlainResponse(w, r, deps, req, url.Values{"code": {code}})
}

// emitPlainResponse delivers params to the RP's redirect_uri without a
// JARM wrapper, honouring the transport the request asked for: an
// auto-submitted HTML form for either form-post mode, a redirect
// otherwise. "state" and RFC 9207 §2.3 / §2.4 "iss" are stamped here so
// every plain emission carries them identically.
//
// A form-post emit that itself fails falls through to the redirect: at
// that point the response has already been reduced to an error envelope
// or the OP cannot write the body at all, and a determinate outcome is
// worth more than the transport preference. Callers MUST NOT route a
// credential-bearing payload here for a request whose contracted shape
// could not be produced — see [emitAuthorizeSuccess].
func emitPlainResponse(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	params url.Values,
) {
	if req.State != "" {
		params.Set("state", req.State)
	}
	if deps.Issuer != "" {
		params.Set("iss", deps.Issuer)
	}
	if responseModeUsesFormPost(req) {
		if err := jarm.WriteParamsFormPost(w, req.RedirectURI, params); err == nil {
			return
		}
	}
	target, err := mergeRedirectParams(req.RedirectURI, params)
	if err != nil {
		// The redirect target is unparseable; fall back to the JSON
		// envelope so the operator gets a useful diagnostic instead of
		// a silent 302-to-nothing.
		renderJSONError(w, http.StatusInternalServerError, errServerError, "redirect target rejected")
		return
	}
	stampNoStore(w)
	//nolint:gosec // G710: req.RedirectURI already exact-matched a registered entry in authorize.Validate; nothing reaches here on a mismatch.
	http.Redirect(w, r, target, http.StatusFound)
}

// emitAuthorizeError sends the error-path response. The plain path is
// the redirect (or form post) [emitPlainResponse] composes; the JARM
// path signs the error claims and dispatches via the resolved mode.
//
// JARM-modes-without-the-feature is handled here too: when the request
// asked for a JARM mode but [resolved.JARM] is nil, the function
// rewrites the wire code to "unsupported_response_mode" and emits the
// plain response so the RP can detect the misconfiguration. This is
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
		// "unsupported_response_mode" unwrapped — JARM can't be used to
		// convey "JARM is not supported".
		emitPlainResponse(w, r, deps, req, url.Values{
			"error":             {errUnsupportedResponseMode},
			"error_description": {"response_mode is not supported by this OP"},
		})
		return
	}
	if tryJARMErrorResponse(w, r, deps, req, code, description) {
		return
	}
	emitPlainResponse(w, r, deps, req, url.Values{
		"error":             {code},
		"error_description": {description},
	})
}

// tryJARMErrorResponse emits an error through the requested JARM
// transport. It returns false only when the request did not opt into
// JARM (or the feature is off) and the caller should emit the plain
// response.
//
// A failed JARM signing, key lookup, encryption, or rendering operation
// is terminal for this request. It must not be downgraded to a plain
// OAuth error, redirect, or partial form: those responses could expose
// state or error details without the response integrity the client
// requested. The caller emits only an endpoint-local 500 with no
// Location, state, code, or OAuth error fields.
func tryJARMErrorResponse(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	code, description string,
) bool {
	mode := jarmModeForRequest(req)
	if mode == "" || deps.JARM == nil {
		return false
	}
	err := jarmEmitError(w, r, deps, req, mode, code, description)
	if err == nil {
		return true
	}
	// The request selected JARM, so a failed signed/JWE/form response
	// cannot be downgraded to a plain OAuth error redirect. Keep the
	// failure local and avoid reflecting the request's state or error.
	writeJARMFailure(w)
	return true
}

// writeJARMFailure is the fail-closed endpoint-local response for every
// runtime JARM failure. It intentionally carries no OAuth error fields,
// state, code, redirect Location, or renderer output.
func writeJARMFailure(w http.ResponseWriter) {
	stampNoStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte("authorization response unavailable\n"))
}

type bufferedResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header)}
}

func (w *bufferedResponseWriter) Header() http.Header { return w.header }

func (w *bufferedResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *bufferedResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

func (w *bufferedResponseWriter) commit(dst http.ResponseWriter) error {
	for key, values := range w.header {
		copied := make([]string, len(values))
		copy(copied, values)
		dst.Header()[key] = copied
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	dst.WriteHeader(status)
	_, err := dst.Write(w.body.Bytes())
	return err
}

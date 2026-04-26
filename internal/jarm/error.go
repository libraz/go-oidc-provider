package jarm

import "errors"

// Sentinel errors returned by the encode / dispatch helpers in this
// package. Callers MUST branch on these via [errors.Is]; string-matching
// is forbidden because wrapped causes originate in third-party JOSE
// machinery whose wording is not stable.
var (
	// ErrUnsupportedResponseMode signals that the [ResponseMode] argument
	// passed to [BuildRedirect] or another dispatcher is not one of the
	// four JARM modes. The HTTP layer maps this onto the OAuth wire code
	// "unsupported_response_mode".
	ErrUnsupportedResponseMode = errors.New("jarm: response_mode is not a JARM mode")

	// ErrEncode signals that JWT serialisation failed. The wrapped cause
	// comes from the underlying signer; it is safe to log but never to
	// echo to clients.
	ErrEncode = errors.New("jarm: encode failed")

	// ErrInvalidRedirect signals that the redirect_uri argument is not a
	// parseable absolute URL. The validator at the authorize boundary
	// rejects malformed URIs long before they reach this package; the
	// sentinel exists so a programming bug surfaces with a stable
	// identity rather than a third-party wording.
	ErrInvalidRedirect = errors.New("jarm: redirect_uri is not parseable")

	// ErrUseFormPost signals that [BuildRedirect] was called with
	// [ResponseModeFormPostJWT]. The form_post path renders an HTML body
	// rather than a 302; callers that receive this error MUST switch to
	// [WriteFormPost] instead. The sentinel keeps the redirect helper's
	// signature single-purpose without forcing every caller to know
	// about the form-post fork.
	ErrUseFormPost = errors.New("jarm: form_post.jwt requires WriteFormPost")
)

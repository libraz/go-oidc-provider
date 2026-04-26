package jarm

import (
	"fmt"
	"net/url"
)

// BuildRedirect composes the redirect target the authorize endpoint
// emits when delivering a JARM response in a redirect-based mode. The
// JWT is placed in the query string for [ResponseModeQueryJWT] and in
// the fragment for [ResponseModeFragmentJWT].
//
// The function returns [ErrUseFormPost] when called with
// [ResponseModeFormPostJWT]: the form-post mode is not a redirect, and
// the caller MUST switch to [WriteFormPost] instead. [ResponseModeJWT]
// is rejected as well — callers are expected to resolve the bare alias
// via [Resolve] before reaching this helper.
//
// Existing query / fragment fragments on redirectURI are preserved so a
// client that registered a URI with a static query suffix (a common
// pattern for static analytics tracking) sees the JARM "response"
// parameter merged in alongside its existing parameters.
func BuildRedirect(mode ResponseMode, redirectURI, jwtToken string) (string, error) {
	switch mode {
	case ResponseModeQueryJWT:
		return mergeQueryJWT(redirectURI, jwtToken)
	case ResponseModeFragmentJWT:
		return mergeFragmentJWT(redirectURI, jwtToken)
	case ResponseModeFormPostJWT:
		return "", ErrUseFormPost
	case ResponseModeJWT:
		return "", fmt.Errorf("%w: bare 'jwt' must be resolved first", ErrUnsupportedResponseMode)
	default:
		return "", ErrUnsupportedResponseMode
	}
}

// mergeQueryJWT appends "response=<jwt>" to the existing query string
// of redirectURI, preserving any other parameters the URI carries.
func mergeQueryJWT(redirectURI, jwtToken string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidRedirect, err)
	}
	q := u.Query()
	q.Set("response", jwtToken)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// mergeFragmentJWT appends "response=<jwt>" to the URL fragment of
// redirectURI. JARM mandates the fragment carry the same URL-encoded
// form as the query mode, so the helper reuses [url.Values.Encode]
// rather than handcrafting the encoding.
//
// Existing fragment content is preserved when it parses cleanly as
// url.Values; otherwise it is replaced verbatim because mixing an
// unstructured fragment with form-encoded parameters would break both
// halves silently.
func mergeFragmentJWT(redirectURI, jwtToken string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidRedirect, err)
	}
	values := url.Values{}
	if u.Fragment != "" {
		// Best-effort merge: only honour an existing fragment when it
		// parses as form-encoded. Anything else is treated as opaque
		// and discarded so we do not concatenate "&" onto a free-form
		// hash.
		if parsed, perr := url.ParseQuery(u.Fragment); perr == nil {
			values = parsed
		}
	}
	values.Set("response", jwtToken)
	u.Fragment = ""
	u.RawFragment = ""
	out := u.String()
	return out + "#" + values.Encode(), nil
}

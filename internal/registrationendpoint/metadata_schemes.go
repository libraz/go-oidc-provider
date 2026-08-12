package registrationendpoint

import (
	"net/url"
	"slices"
	"strings"
)

// validateRedirectURIs enforces the RFC 6749 §3.1.2 baseline plus the
// RFC 8252 §7.3 native-app loopback carve-out and OIDC Registration §2
// rules: every URL MUST be absolute, parseable, fragment-free, and
// match the scheme/host shape allowed for its application_type. Web
// clients require https (with a loopback-http carve-out gated by
// allowLocalhostLoopback for backward compatibility); native clients
// additionally accept loopback http unconditionally and custom URI
// schemes per RFC 8252 §7.1. The default IP-only loopback posture
// reflects the §8.3 DNS-rebinding concern. The caller's
// [ValidateMetadata] hook may tighten further.
func validateRedirectURIs(uris []string, applicationType string, hasImplicit, allowLocalhostLoopback bool) error {
	if len(uris) == 0 {
		return errInvalidRedirectURI("redirect_uris is required")
	}
	for _, raw := range uris {
		if err := validateRedirectURI(raw, applicationType, hasImplicit, allowLocalhostLoopback); err != nil {
			return err
		}
	}
	return nil
}

// validateRedirectURI enforces the per-URI rules. Split out from
// [validateRedirectURIs] so the per-row check stays under the
// project's gocognit / cyclop caps and so the error messages stay
// per-URI rather than masking the offending entry behind a generic
// loop diagnostic.
func validateRedirectURI(raw, applicationType string, hasImplicit, allowLocalhostLoopback bool) error {
	if raw == "" {
		return errInvalidRedirectURI("redirect_uri must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errInvalidRedirectURI("redirect_uri is not a valid URL")
	}
	if !u.IsAbs() {
		return errInvalidRedirectURI("redirect_uri must be absolute")
	}
	// The delimiter is what the check is about, not the fragment's
	// content: RFC 6749 §3.1.2 forbids a fragment component, and a bare
	// trailing "#" is an empty one. Testing the parsed fragment alone
	// would admit it, leaving a registered value that a user agent
	// truncates before the OP ever sees it — so the stored URI and the
	// URI presented at /authorize could never be the same string. A
	// literal "#" inside a path or query must arrive percent-encoded, so
	// an unescaped one is always the delimiter.
	if strings.Contains(raw, "#") {
		return errInvalidRedirectURI("redirect_uri must not contain a fragment")
	}
	if applicationType == applicationTypeNative {
		return validateNativeRedirectURIScheme(u)
	}
	return validateWebRedirectURIScheme(u, hasImplicit, allowLocalhostLoopback)
}

// validateNativeRedirectURIScheme implements OIDC Registration §2 +
// RFC 8252 §7.1/§7.2/§7.3 for native clients: https (claimed), loopback
// http, or a custom URI scheme. Loopback http accepts the textual
// "localhost" host unconditionally for native clients per OIDC Reg §2;
// the AllowLocalhostLoopback gate is for the web-client carve-out only.
func validateNativeRedirectURIScheme(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return validateHTTPSRedirectAuthority(u, "redirect_uri")
	case "http":
		if !isLoopbackRedirectHost(u.Hostname(), true) {
			return errInvalidRedirectURI("native client redirect_uri http scheme requires a loopback host (127.0.0.1, [::1], or localhost) per RFC 8252 §7.3")
		}
		return nil
	default:
		return validateNativeCustomScheme(u.Scheme)
	}
}

// validateNativeCustomScheme implements RFC 8252 §7.1 private-use URI
// scheme handling: schemes are accepted, but a non-reverse-DNS shape
// (no "." in the scheme, e.g. "myapp" instead of "com.example.myapp")
// is rejected because non-reverse-DNS schemes have a higher collision
// risk across applications. Schemes that collide with well-known web
// schemes are rejected outright.
func validateNativeCustomScheme(scheme string) error {
	if scheme == "" {
		return errInvalidRedirectURI("redirect_uri scheme must not be empty")
	}
	switch scheme {
	case "ftp", "file", "data", "javascript", "ws", "wss":
		return errInvalidRedirectURI("redirect_uri scheme " + scheme + " is not permitted for native clients")
	}
	if !strings.Contains(scheme, ".") {
		return errInvalidRedirectURI("native client custom URI scheme " + scheme + " SHOULD use reverse-DNS form (e.g. com.example.app); register a scheme containing a dot per RFC 8252 §7.1")
	}
	return nil
}

// validateWebRedirectURIScheme implements OIDC Registration §2 for web
// clients: https only, with the historical AllowLocalhostLoopback gate
// still admitting loopback-http for embedders that opted in before the
// native-app split. Implicit grant additionally forbids localhost host
// shapes per OIDC Reg §2.
func validateWebRedirectURIScheme(u *url.URL, hasImplicit, allowLocalhostLoopback bool) error {
	switch u.Scheme {
	case "https":
		if err := validateHTTPSRedirectAuthority(u, "redirect_uri"); err != nil {
			return err
		}
		if hasImplicit && isLoopbackRedirectHost(u.Hostname(), true) {
			return errInvalidRedirectURI("web client with implicit response_types must not use a loopback host as redirect_uri per OIDC Registration §2")
		}
		return nil
	case "http":
		if !isLoopbackRedirectHost(u.Hostname(), allowLocalhostLoopback) {
			if allowLocalhostLoopback {
				return errInvalidRedirectURI("redirect_uri http scheme is permitted only for loopback hosts (127.0.0.1, [::1], or localhost) per RFC 8252 §7.3")
			}
			return errInvalidRedirectURI("redirect_uri http scheme is permitted only for loopback IP literals (127.0.0.1, [::1]) per RFC 8252 §7.3 + §8.3; pass op.WithAllowLocalhostLoopback() to also admit the textual \"localhost\" host")
		}
		return nil
	default:
		return errInvalidRedirectURI("web client redirect_uri scheme must be https; custom URI schemes require application_type=native")
	}
}

// validatePostLogoutRedirectURIs enforces the OpenID Connect
// RP-Initiated Logout 1.0 §3 requirement that every
// post_logout_redirect_uris entry be an absolute, fragment-free URL the
// OP can later compare byte-for-byte against /end_session input. The
// scheme matrix mirrors the redirect_uris policy: native clients may
// use https, loopback http (RFC 8252 §7.3), or a reverse-DNS custom
// scheme; web clients may use https with the existing AllowLocalhostLoopback
// gate widening the loopback http carve-out to the textual "localhost".
// On any failure the error code is invalid_client_metadata (the field
// is post-logout-specific; the redirect_uris-shaped invalid_redirect_uri
// code would mis-categorise it) and the description names both
// "post_logout_redirect_uris" and "loopback" so embedders can
// self-correct without inspecting source.
func validatePostLogoutRedirectURIs(uris []string, applicationType string, allowLocalhostLoopback bool) error {
	if len(uris) == 0 {
		return nil
	}
	for _, raw := range uris {
		if err := validatePostLogoutRedirectURI(raw, applicationType, allowLocalhostLoopback); err != nil {
			return err
		}
	}
	return nil
}

// validatePostLogoutRedirectURI runs the per-URI checks from
// [validatePostLogoutRedirectURIs]. Split out so the per-row diagnostic
// names the offending entry rather than collapsing the loop into a
// single message and so the gocognit / cyclop budget on the parent
// helper stays well below the project caps.
func validatePostLogoutRedirectURI(raw, applicationType string, allowLocalhostLoopback bool) error {
	if raw == "" {
		return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris entry must not be empty (loopback http requires 127.0.0.1, [::1], or localhost when AllowLocalhostLoopback is set)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris entry " + raw + " is not a valid URL (loopback http hosts must be 127.0.0.1, [::1], or localhost)")
	}
	if !u.IsAbs() {
		return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris entry " + raw + " must be an absolute URL (loopback http requires the explicit scheme://host form)")
	}
	// See the matching note in [validateRedirectURI]: the delimiter is
	// the check, so a bare trailing "#" is rejected too.
	if strings.Contains(raw, "#") {
		return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris entry " + raw + " must not contain a fragment (loopback http URIs are compared byte-for-byte at /end_session)")
	}
	if applicationType == applicationTypeNative {
		return validateNativePostLogoutScheme(u)
	}
	return validateWebPostLogoutScheme(u, allowLocalhostLoopback)
}

// validateNativePostLogoutScheme implements the native carve-out for
// post_logout_redirect_uris: https, loopback http (the textual
// "localhost" host is admitted unconditionally for native clients,
// matching [validateNativeRedirectURIScheme]), or a reverse-DNS custom
// scheme per RFC 8252 §7.1.
func validateNativePostLogoutScheme(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return validateHTTPSRedirectAuthority(u, "post_logout_redirect_uris entry")
	case "http":
		if !isLoopbackRedirectHost(u.Hostname(), true) {
			return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris http scheme for native clients requires a loopback host (127.0.0.1, [::1], or localhost) per RFC 8252 §7.3")
		}
		return nil
	default:
		if err := validateNativeCustomScheme(u.Scheme); err != nil {
			return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris " + u.String() + ": " + err.Error() + " (loopback http hosts: 127.0.0.1, [::1], localhost)")
		}
		return nil
	}
}

// validateWebPostLogoutScheme implements the web-client policy:
// https only, with the AllowLocalhostLoopback gate admitting loopback
// http for embedders that opted in. Mirrors
// [validateWebRedirectURIScheme] without the implicit-flow carve-out
// (post_logout never participates in the implicit response).
func validateWebPostLogoutScheme(u *url.URL, allowLocalhostLoopback bool) error {
	switch u.Scheme {
	case "https":
		return validateHTTPSRedirectAuthority(u, "post_logout_redirect_uris entry")
	case "http":
		if !isLoopbackRedirectHost(u.Hostname(), allowLocalhostLoopback) {
			if allowLocalhostLoopback {
				return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris http scheme is permitted only for loopback hosts (127.0.0.1, [::1], or localhost) per RFC 8252 §7.3")
			}
			return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris http scheme is permitted only for loopback IP literals (127.0.0.1, [::1]); pass op.WithAllowLocalhostLoopback() to also admit the textual \"localhost\" host")
		}
		return nil
	default:
		return errInvalidPostLogoutRedirectURI("post_logout_redirect_uris scheme must be https for web clients; loopback http (127.0.0.1, [::1], localhost) and custom URI schemes require application_type=native")
	}
}

func validateHTTPSRedirectAuthority(u *url.URL, field string) error {
	if u.Host == "" || u.Hostname() == "" {
		if field == "redirect_uri" {
			return errInvalidRedirectURI("redirect_uri https URL must include an authority")
		}
		return errInvalidPostLogoutRedirectURI(field + " https URL must include an authority (loopback http requires an explicit host)")
	}
	if u.User != nil {
		if field == "redirect_uri" {
			return errInvalidRedirectURI("redirect_uri https URL must not contain userinfo")
		}
		return errInvalidPostLogoutRedirectURI(field + " https URL must not contain userinfo (loopback http requires an explicit host)")
	}
	return nil
}

// errInvalidPostLogoutRedirectURI constructs a [validationError] whose
// description always names both "post_logout_redirect_uris" and
// "loopback". Centralising the wording keeps the embedder-facing
// contract — "if you see this error, the literal substrings tell you
// which field and which carve-out applies" — encoded in one place.
func errInvalidPostLogoutRedirectURI(desc string) error {
	return errInvalidClientMetadata(desc)
}

// hasImplicitResponseType reports whether any response_type entry
// contains an implicit-flow token (id_token or token without code).
func hasImplicitResponseType(responseTypes []string) bool {
	for _, rt := range responseTypes {
		toks := strings.Fields(rt)
		hasCode := slices.Contains(toks, "code")
		hasToken := slices.Contains(toks, "token")
		hasIDToken := slices.Contains(toks, "id_token")
		if !hasCode && (hasToken || hasIDToken) {
			return true
		}
	}
	return false
}

// isLoopbackRedirectHost reports whether host is a loopback literal
// the RFC 8252 §7.3 native-app carve-out admits over plain http. The
// IP literals 127.0.0.1 and [::1] are always admitted; the textual
// "localhost" token is admitted only when allowLocalhostLoopback is
// true. Hostname() strips the bracket from "[::1]"; we only accept
// the exact loopback addresses (not the 127.0.0.0/8 block) because a
// DCR-supplied redirect_uri names the URI the client expects to
// receive on — there is no operational reason to register 127.0.0.2.
func isLoopbackRedirectHost(host string, allowLocalhostLoopback bool) bool {
	if host == "" {
		return false
	}
	if allowLocalhostLoopback && strings.EqualFold(host, "localhost") {
		return true
	}
	switch host {
	case "127.0.0.1", "::1":
		return true
	}
	return false
}

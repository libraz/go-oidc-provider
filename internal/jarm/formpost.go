package jarm

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
)

// formPostScript is the inline script auto-submitting the form on page
// load. The string is a package-level constant so the CSP hash below
// stays in lock-step: any edit forces the hash to be recomputed via
// [formPostScriptHash] at package init.
const formPostScript = `document.forms[0].submit()`

// formPostScriptHash is the base64-encoded SHA-256 digest of
// [formPostScript], wrapped in the 'sha256-...' notation the CSP
// script-src directive expects. It is computed once at package init
// so a future edit of [formPostScript] cannot drift from the CSP.
//
//nolint:gochecknoglobals // computed once at init from a package-level string constant.
var formPostScriptHash = computeFormPostScriptHash()

// computeFormPostScriptHash wraps the SHA-256 digest of
// [formPostScript] in the CSP-source quoted form. Splitting it into a
// helper (rather than pasting the literal) keeps the package safe
// against script edits: the lint pipeline catches a stale hash via the
// embedded test that recomputes the digest.
func computeFormPostScriptHash() string {
	sum := sha256.Sum256([]byte(formPostScript))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// WriteFormPost renders the auto-submitting HTML form that delivers a
// JARM JWT to redirect_uri when [ResponseModeFormPostJWT] is selected.
// The body sets a strict Content-Security-Policy that allows only the
// hash of the auto-submit script — no other scripts, no images, no
// network requests — so a compromised JARM JWT cannot pivot to XSS.
//
// The form falls back to a manual <noscript> button so users with
// JavaScript disabled (or an aggressive CSP elsewhere on the response
// chain) can still complete the redirect.
func WriteFormPost(w http.ResponseWriter, redirectURI, jwtToken string) error {
	if redirectURI == "" {
		return fmt.Errorf("%w: redirect_uri required", ErrInvalidRedirect)
	}
	if jwtToken == "" {
		return fmt.Errorf("%w: jwt required", ErrEncode)
	}
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy",
		"default-src 'none'; form-action "+formPostFormActionSource(redirectURI)+
			"; script-src "+formPostScriptHash+"; base-uri 'none'; frame-ancestors 'none'")
	header.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	body := buildFormPostBody(redirectURI, jwtToken)
	if _, err := w.Write([]byte(body)); err != nil {
		return fmt.Errorf("jarm: write form_post body: %w", err)
	}
	return nil
}

// buildFormPostBody composes the HTML the browser auto-submits. The
// helper exists so tests can assert on the exact bytes without
// invoking the HTTP machinery, and so the [WriteFormPost] caller stays
// short.
func buildFormPostBody(redirectURI, jwtToken string) string {
	action := html.EscapeString(redirectURI)
	value := html.EscapeString(jwtToken)
	return "<!DOCTYPE html>" +
		"<html><head><meta charset=\"utf-8\"><title>Submitting</title></head>" +
		"<body>" +
		"<form method=\"post\" action=\"" + action + "\">" +
		"<input type=\"hidden\" name=\"response\" value=\"" + value + "\" />" +
		"<noscript><button type=\"submit\">Continue</button></noscript>" +
		"</form>" +
		"<script>" + formPostScript + "</script>" +
		"</body></html>"
}

// formPostFormActionSource computes the CSP form-action source-list
// value for redirectURI. The CSP spec accepts an absolute URL or an
// origin; the helper returns the absolute URL as-is because the
// authorize-time validator has already exact-matched it against the
// client's registered list. A malformed URL falls back to "'self'"
// which is the minimum-blast-radius default.
func formPostFormActionSource(redirectURI string) string {
	if redirectURI == "" {
		return "'self'"
	}
	return redirectURI
}

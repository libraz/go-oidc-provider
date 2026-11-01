package jarm

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/httpx"
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

// WriteParamsFormPost renders the OIDC Core Form Post Response Mode
// 1.0 body — a self-submitting HTML form with one hidden input per
// authorization response parameter (`code`, `state`, `iss`, `error`,
// `error_description`, ...). The JARM `form_post.jwt` mode carries its
// JWT as the lone `response` parameter.
//
// The response sets a strict Content-Security-Policy that allows only
// the hash of the auto-submit script, plus no-store and no-referrer,
// and falls back to a <noscript> button. Field order is sorted by name
// for a deterministic body — tests can assert on the exact bytes without
// observing map-iteration jitter, and a future regression that flips
// the order is loud rather than silent.
func WriteParamsFormPost(w http.ResponseWriter, redirectURI string, params url.Values) error {
	if redirectURI == "" {
		return fmt.Errorf("%w: redirect_uri required", ErrInvalidRedirect)
	}
	if len(params) == 0 {
		return fmt.Errorf("%w: at least one param required", ErrEncode)
	}
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	httpx.StampNoStore(w)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy",
		"default-src 'none'; form-action "+formPostFormActionSource(redirectURI)+
			"; script-src "+formPostScriptHash+"; base-uri 'none'; frame-ancestors 'none'")
	header.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	body := buildParamsFormPostBody(redirectURI, params)
	if _, err := w.Write([]byte(body)); err != nil {
		return fmt.Errorf("jarm: write form_post params body: %w", err)
	}
	return nil
}

// buildParamsFormPostBody composes the HTML the browser auto-submits.
// Hidden inputs are emitted in sorted-by-name order so the body is
// deterministic and tests can match exact bytes.
func buildParamsFormPostBody(redirectURI string, params url.Values) string {
	action := html.EscapeString(redirectURI)
	names := make([]string, 0, len(params))
	for k := range params {
		names = append(names, k)
	}
	sort.Strings(names)
	var inputs strings.Builder
	for _, name := range names {
		// url.Values is a map[string][]string; OIDC authorization
		// responses are single-valued so emit the first entry. Empty
		// values are skipped so an absent state / iss does not produce
		// a stray empty hidden input.
		v := params.Get(name)
		if v == "" {
			continue
		}
		inputs.WriteString("<input type=\"hidden\" name=\"")
		inputs.WriteString(html.EscapeString(name))
		inputs.WriteString("\" value=\"")
		inputs.WriteString(html.EscapeString(v))
		inputs.WriteString("\" />")
	}
	return "<!DOCTYPE html>" +
		"<html><head><meta charset=\"utf-8\"><title>Submitting</title></head>" +
		"<body>" +
		"<form method=\"post\" action=\"" + action + "\">" +
		inputs.String() +
		"<noscript><button type=\"submit\">Continue</button></noscript>" +
		"</form>" +
		"<script>" + formPostScript + "</script>" +
		"</body></html>"
}

// formPostFormActionSource computes the CSP form-action source-list
// value for redirectURI. The CSP spec accepts origins, so the helper
// reduces the exact redirect_uri to scheme://host[:port]. Keeping
// path / query out of the directive avoids brittle intermediary
// handling while preserving the cross-origin allow-list shape. A
// malformed URL falls back to "'self'", the minimum-blast-radius
// default.
func formPostFormActionSource(redirectURI string) string {
	if redirectURI == "" {
		return "'self'"
	}
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "'self'"
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host
}

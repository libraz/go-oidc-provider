package interaction

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
)

// ErrorPrompt is the terminal-error counterpart to [Prompt]. The HTTP
// layer passes one to [ErrorRenderer.RenderError] when an authorize
// request fails before a redirect target can be trusted (RFC 6749
// §4.1.2.1: "if the request fails due to a missing, invalid, or
// mismatching redirection URI [...] the authorization server SHOULD
// inform the resource owner of the error").
//
// Field semantics:
//
//   - Code mirrors the OAuth/OIDC error code (e.g.,
//     "invalid_request_uri", "invalid_request"). Embedders treat it as
//     a stable identifier, not a prose message.
//   - Description is a short human-readable explanation. The library
//     populates it from the same source that feeds the JSON envelope's
//     "error_description". May be empty.
//   - Status is the HTTP status the response carries. Drivers MUST
//     stamp this onto [http.ResponseWriter] before writing the body.
//   - State is the RP-supplied state parameter when one was parsed
//     successfully. The HTML / SPA layer surfaces it so a user can
//     correlate the failure with their RP-side flow without exposing
//     server-internal identifiers.
//
// # State is attacker-controlled
//
// State is the value as it arrived on the wire. It is NOT validated,
// sanitised, or length-bounded, and on the error paths that fire before
// the client and redirect_uri are trusted — a refused request object,
// an unregistered client_id — it has not been tied to any registered
// party either. Anyone who can get a browser to issue the request
// chooses it.
//
// An implementation that interpolates it into markup MUST escape it for
// the context it lands in. The bundled drivers do; a driver written
// against this type is on its own. Getting this wrong turns a rejected
// authorization request into reflected XSS on the OP's own origin,
// which is where the session cookie lives. A driver that has no use for
// the value should drop it rather than echo it.
type ErrorPrompt struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	State       string `json:"state,omitempty"`
	Status      int    `json:"-"`
}

// ErrorRenderer is the optional [Driver] extension that owns terminal-
// error rendering. The library type-asserts the configured Driver to
// this interface; implementations that do not satisfy it fall back to
// the canonical RFC 6749 §5.2 JSON envelope.
//
// The interface is additive (separate from [Driver]) so embedders that
// shipped a [Driver] before this contract existed do not silently lose
// their HTML or SPA error surface when they upgrade — they keep the
// JSON fallback until they add RenderError of their own.
//
// Implementations MUST be safe for concurrent use; the library calls
// the method from request-scoped goroutines.
type ErrorRenderer interface {
	// RenderError writes a response describing prompt to w. The
	// implementation owns the Content-Type and stamps the status code
	// from prompt.Status before any byte hits the wire. Returning a
	// non-nil error tells the HTTP layer to fall back to its JSON
	// envelope; partial writes are not retried.
	RenderError(w http.ResponseWriter, r *http.Request, prompt ErrorPrompt) error
}

// Compile-time confirmation that the bundled drivers satisfy
// ErrorRenderer in addition to [Driver].
var (
	_ ErrorRenderer = JSONDriver{}
	_ ErrorRenderer = HTMLDriver{}
)

// RenderError implements [ErrorRenderer] for JSONDriver. The output is
// the canonical RFC 6749 §5.2 / OIDC Core 1.0 §3.1.2.6 envelope so
// SPAs that fetched the URL via XHR get the same shape they would have
// seen from the legacy free-function path.
func (JSONDriver) RenderError(w http.ResponseWriter, _ *http.Request, prompt ErrorPrompt) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if prompt.Status > 0 {
		w.WriteHeader(prompt.Status)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
	if err := json.NewEncoder(w).Encode(prompt); err != nil {
		return fmt.Errorf("interaction: render json error: %w", err)
	}
	return nil
}

// RenderError implements [ErrorRenderer] for HTMLDriver. The output is
// a self-contained HTML document that:
//
//   - declares the error visually for an MPA-style consumer;
//   - exposes the same machine-readable fields as data-* attributes on
//     a single root element so a SPA host can read them without
//     parsing arbitrary markup or relaxing CSP (data attributes are
//     plain HTML — they do not require script-src to be loosened);
//   - carries no <script>, <style>, <img>, or inline event handlers, so
//     the page renders cleanly under
//     "default-src 'none'; style-src 'unsafe-inline'" or stricter.
//
// All variable byte sequences pass through [html.EscapeString].
func (HTMLDriver) RenderError(w http.ResponseWriter, _ *http.Request, prompt ErrorPrompt) error {
	body := buildErrorDocument(prompt)
	stampHTMLHeaders(w)
	if prompt.Status > 0 {
		w.WriteHeader(prompt.Status)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
	if _, err := io.WriteString(w, body); err != nil {
		return fmt.Errorf("interaction: render html error: %w", err)
	}
	return nil
}

// buildErrorDocument renders prompt as a self-contained HTML document.
// SPA hosts read the data-* attributes off the #op-error root; MPA
// consumers see the rendered text. There is no scripted layer.
func buildErrorDocument(prompt ErrorPrompt) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>`)
	b.WriteString(html.EscapeString(errorTitleFor(prompt.Code)))
	b.WriteString(`</title></head><body>`)
	b.WriteString(`<div id="op-error"`)
	writeDataAttr(&b, "code", prompt.Code)
	writeDataAttr(&b, "description", prompt.Description)
	writeDataAttr(&b, "state", prompt.State)
	b.WriteString(`>`)
	b.WriteString(`<h1>`)
	b.WriteString(html.EscapeString(errorTitleFor(prompt.Code)))
	b.WriteString(`</h1>`)
	if prompt.Code != "" {
		b.WriteString(`<p><strong>`)
		b.WriteString(html.EscapeString(prompt.Code))
		b.WriteString(`</strong></p>`)
	}
	if prompt.Description != "" {
		b.WriteString(`<p>`)
		b.WriteString(html.EscapeString(prompt.Description))
		b.WriteString(`</p>`)
	}
	b.WriteString(`</div></body></html>`)
	return b.String()
}

// writeDataAttr emits a single data-* attribute, omitting it entirely
// when the value is empty so the rendered DOM does not carry stub
// attributes that a SPA would treat as "field present, empty string".
func writeDataAttr(b *strings.Builder, key, value string) {
	if value == "" {
		return
	}
	b.WriteString(` data-`)
	b.WriteString(html.EscapeString(key))
	b.WriteString(`="`)
	b.WriteString(html.EscapeString(value))
	b.WriteString(`"`)
}

// errorTitleFor returns the page heading used in <title> and <h1>. The
// mapping covers the common pre-redirect-trust failure codes; unknown
// codes fall through to a generic heading rather than reflecting the
// raw code (which is still surfaced as data-code and within the body).
func errorTitleFor(code string) string {
	switch code {
	case "invalid_request":
		return "Authorization request rejected"
	case "invalid_request_uri":
		return "Authorization request rejected"
	case "invalid_request_object":
		return "Authorization request rejected"
	case "invalid_redirect_uri":
		return "Authorization request rejected"
	case "unauthorized_client":
		return "Client not permitted"
	case "server_error":
		return "Server error"
	default:
		return "Authorization request failed"
	}
}

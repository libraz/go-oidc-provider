package interaction_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestJSONDriver_RenderErrorEnvelope confirms the JSON shape matches
// the RFC 6749 §5.2 / OIDC Core 1.0 §3.1.2.6 envelope. Embedders that
// already consume the legacy free-function path keep their wire shape.
func TestJSONDriver_RenderErrorEnvelope(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/auth", nil)

	if err := (interaction.JSONDriver{}).RenderError(rec, req, interaction.ErrorPrompt{
		Code:        "invalid_request_uri",
		Description: "request_uri expired",
		State:       "abc",
		Status:      http.StatusBadRequest,
	}); err != nil {
		t.Fatalf("RenderError: %v", err)
	}

	if got := rec.Code; got != http.StatusBadRequest {
		t.Errorf("status=%d want 400", got)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q want application/json", ct)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "invalid_request_uri" {
		t.Errorf("error=%v want invalid_request_uri", body["error"])
	}
	if body["error_description"] != "request_uri expired" {
		t.Errorf("error_description=%v want request_uri expired", body["error_description"])
	}
	if body["state"] != "abc" {
		t.Errorf("state=%v want abc", body["state"])
	}
}

// TestJSONDriver_RenderErrorDefaultStatus covers the zero-Status case:
// the canonical 400 stamps so callers that forget to fill Status do
// not silently emit 200.
func TestJSONDriver_RenderErrorDefaultStatus(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	if err := (interaction.JSONDriver{}).RenderError(rec, req, interaction.ErrorPrompt{
		Code: "invalid_request",
	}); err != nil {
		t.Fatalf("RenderError: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400", rec.Code)
	}
}

// TestHTMLDriver_RenderErrorEmitsDataAttributes covers the SPA-friendly
// path: the rendered HTML carries the error data on a stable anchor
// (#op-error) as data-* attributes so a SPA host can read them with
// document.querySelector without parsing arbitrary markup.
func TestHTMLDriver_RenderErrorEmitsDataAttributes(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/auth", nil)
	if err := (interaction.HTMLDriver{}).RenderError(rec, req, interaction.ErrorPrompt{
		Code:        "invalid_request_uri",
		Description: "request_uri has expired",
		State:       "abc",
		Status:      http.StatusBadRequest,
	}); err != nil {
		t.Fatalf("RenderError: %v", err)
	}

	body := rec.Body.String()
	wants := []string{
		`id="op-error"`,
		`data-code="invalid_request_uri"`,
		`data-description="request_uri has expired"`,
		`data-state="abc"`,
	}
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("body missing %q\n%s", w, body)
		}
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400", rec.Code)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options=%q want DENY", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options=%q want nosniff", got)
	}
}

// TestHTMLDriver_RenderErrorEscapesHostileInput is the XSS regression.
// Hostile values in code / description / state must reach the page
// HTML-escaped: any "<", ">", or '"' that survives unescaped breaks
// out of the attribute / element it sits in and lets an attacker who
// influences error params plant markup.
func TestHTMLDriver_RenderErrorEscapesHostileInput(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/auth", nil)
	if err := (interaction.HTMLDriver{}).RenderError(rec, req, interaction.ErrorPrompt{
		Code:        `<script>alert(1)</script>`,
		Description: `"><img src=x onerror=alert(1)>`,
		State:       `</div><script>1</script>`,
		Status:      http.StatusBadRequest,
	}); err != nil {
		t.Fatalf("RenderError: %v", err)
	}

	body := rec.Body.String()
	// No raw start-tag may exist anywhere in the output that we did
	// not emit ourselves. The driver only emits <!doctype>, <html>,
	// <head>, <meta>, <title>, <body>, <div>, <h1>, <p>, <strong> —
	// so if any of these "tag-like" patterns appear they came from
	// reflection.
	forbiddenTags := []string{
		"<script", "<img", "<style", "<iframe", "<object", "<embed",
	}
	for _, tag := range forbiddenTags {
		if strings.Contains(body, tag) {
			t.Errorf("body leaked unescaped tag %q\n%s", tag, body)
		}
	}
	// And confirm that the canonical escapes appear, proving the
	// escape ran rather than the field being silently dropped.
	wantEscapes := []string{
		`&lt;script&gt;`,
		`&lt;img src=x`,
		`&lt;/div&gt;`,
	}
	for _, want := range wantEscapes {
		if !strings.Contains(body, want) {
			t.Errorf("expected escaped form %q missing\n%s", want, body)
		}
	}
}

// TestHTMLDriver_RenderErrorCSPCompliance mirrors the prompt-render
// CSP guarantees for the error path. Embedders running under a
// "default-src 'none'; style-src 'unsafe-inline'" CSP must see no
// scripts, no inline styles, no event handlers, and no img loads.
func TestHTMLDriver_RenderErrorCSPCompliance(t *testing.T) {
	t.Parallel()

	cases := []interaction.ErrorPrompt{
		{Code: "invalid_request"},
		{Code: "invalid_request_uri", Description: "expired", State: "abc"},
		{Code: "server_error", Description: "internal failure"},
	}
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script\b`),
		regexp.MustCompile(`(?i)<style\b`),
		regexp.MustCompile(`(?i)<img\b`),
		regexp.MustCompile(`(?i)\sstyle\s*=`),
		regexp.MustCompile(`(?i)\son[a-z]+\s*=`),
		regexp.MustCompile(`(?i)javascript:`),
	}

	for _, prompt := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		if err := (interaction.HTMLDriver{}).RenderError(rec, req, prompt); err != nil {
			t.Fatalf("RenderError(%q): %v", prompt.Code, err)
		}
		body := rec.Body.String()
		for _, re := range forbidden {
			if re.MatchString(body) {
				t.Errorf("CSP violation for code=%q: pattern %q matched\n%s", prompt.Code, re.String(), body)
			}
		}
	}
}

// TestHTMLDriver_RenderErrorSkipsEmptyDataAttrs covers the explicit
// design choice that an empty optional value omits the data-* slot
// rather than emitting a stub. SPA hosts treat presence as
// "field set"; absence means "no value".
func TestHTMLDriver_RenderErrorSkipsEmptyDataAttrs(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	if err := (interaction.HTMLDriver{}).RenderError(rec, req, interaction.ErrorPrompt{
		Code: "invalid_request",
	}); err != nil {
		t.Fatalf("RenderError: %v", err)
	}
	body := rec.Body.String()
	if strings.Contains(body, "data-description=") {
		t.Errorf("data-description should be omitted for empty Description\n%s", body)
	}
	if strings.Contains(body, "data-state=") {
		t.Errorf("data-state should be omitted for empty State\n%s", body)
	}
	if !strings.Contains(body, `data-code="invalid_request"`) {
		t.Errorf("data-code missing\n%s", body)
	}
}

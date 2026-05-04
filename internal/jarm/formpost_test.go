package jarm_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jarm"
)

func TestWriteFormPost_HappyPath(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	if err := jarm.WriteFormPost(w, "https://rp.example.com/cb", "compact-jwt-token"); err != nil {
		t.Fatalf("WriteFormPost: %v", err)
	}
	resp := w.Result()
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type=%q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q", got)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("CSP header missing")
	}
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP missing default-src 'none': %q", csp)
	}
	if !strings.Contains(csp, "form-action https://rp.example.com/cb") {
		t.Errorf("CSP missing form-action: %q", csp)
	}
	if !strings.Contains(csp, "script-src 'sha256-") {
		t.Errorf("CSP missing script-src hash: %q", csp)
	}

	body := w.Body.String()
	if !strings.Contains(body, `action="https://rp.example.com/cb"`) {
		t.Errorf("body missing form action: %s", body)
	}
	if !strings.Contains(body, `name="response"`) {
		t.Errorf("body missing response field: %s", body)
	}
	if !strings.Contains(body, `value="compact-jwt-token"`) {
		t.Errorf("body missing jwt value: %s", body)
	}
	if !strings.Contains(body, "<noscript>") {
		t.Errorf("body missing noscript fallback: %s", body)
	}
}

// TestWriteFormPost_EscapesRedirectAndJWT pins the defensive HTML
// escape on every value flowing into the form_post body. Both action=
// (redirect_uri) and value= (the JARM JWT or any echoed param) MUST
// pass through [html.EscapeString] before reaching the wire — without
// it, a malformed value that survived earlier validation could inject
// markup into the auto-submit page.
//
// Tracks: GHSA-27gc-wj6x-9w55 (Keycloak, 2024) — error_description
// was reflected into HTML error pages without escaping, enabling
// phishing / open-redirect chains. CWE-79. The form_post surface here
// is the analogous emit point in this library; the test exercises
// the same threat shape (raw "<script>"-bearing input → must not
// appear unescaped in the response body).
func TestWriteFormPost_EscapesRedirectAndJWT(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	// The authorize-time validator rejects malformed redirect_uris long
	// before they reach this helper, but the HTML escaping must still
	// be in place defensively. We feed a payload that would inject HTML
	// if escaping were missing.
	hostile := `https://rp.example.com/cb"><script>alert(1)</script>`
	if err := jarm.WriteFormPost(w, hostile, `"><img src=x>`); err != nil {
		t.Fatalf("WriteFormPost: %v", err)
	}
	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("redirect not escaped: %s", body)
	}
	if strings.Contains(body, `<img src=x>`) {
		t.Errorf("jwt not escaped: %s", body)
	}
}

func TestWriteFormPost_RejectsEmptyRedirect(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	err := jarm.WriteFormPost(w, "", "j")
	if !errors.Is(err, jarm.ErrInvalidRedirect) {
		t.Errorf("err=%v want ErrInvalidRedirect", err)
	}
}

func TestWriteFormPost_RejectsEmptyJWT(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	err := jarm.WriteFormPost(w, "https://rp.example.com/cb", "")
	if !errors.Is(err, jarm.ErrEncode) {
		t.Errorf("err=%v want ErrEncode", err)
	}
}

func TestWriteParamsFormPost_HappyPath(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	params := url.Values{
		"code":  {"abc123"},
		"state": {"xyz"},
		"iss":   {"https://op.example.com"},
	}
	if err := jarm.WriteParamsFormPost(w, "https://rp.example.com/cb", params); err != nil {
		t.Fatalf("WriteParamsFormPost: %v", err)
	}
	resp := w.Result()
	defer resp.Body.Close()

	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type=%q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q", got)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP missing default-src 'none': %q", csp)
	}
	if !strings.Contains(csp, "form-action https://rp.example.com/cb") {
		t.Errorf("CSP missing form-action: %q", csp)
	}

	body := w.Body.String()
	if !strings.Contains(body, `action="https://rp.example.com/cb"`) {
		t.Errorf("body missing form action: %s", body)
	}
	for _, want := range []string{
		`name="code" value="abc123"`,
		`name="iss" value="https://op.example.com"`,
		`name="state" value="xyz"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q: %s", want, body)
		}
	}
	// Sorted-by-name order is part of the contract: code < iss < state.
	codeIdx := strings.Index(body, `name="code"`)
	issIdx := strings.Index(body, `name="iss"`)
	stateIdx := strings.Index(body, `name="state"`)
	if codeIdx >= issIdx || issIdx >= stateIdx {
		t.Errorf("hidden inputs not in sorted order: code=%d iss=%d state=%d", codeIdx, issIdx, stateIdx)
	}
}

func TestWriteParamsFormPost_SkipsEmptyValues(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	params := url.Values{
		"code":  {"abc"},
		"state": {""}, // present but empty — must NOT emit a stray hidden input
	}
	if err := jarm.WriteParamsFormPost(w, "https://rp.example.com/cb", params); err != nil {
		t.Fatalf("WriteParamsFormPost: %v", err)
	}
	body := w.Body.String()
	if !strings.Contains(body, `name="code" value="abc"`) {
		t.Errorf("body missing code field: %s", body)
	}
	if strings.Contains(body, `name="state"`) {
		t.Errorf("empty state field leaked into body: %s", body)
	}
}

// TestWriteParamsFormPost_EscapesValues exercises the same defensive
// escape contract as [TestWriteFormPost_EscapesRedirectAndJWT] for the
// multi-field variant. Every hidden input value (and the form action)
// flows through html.EscapeString.
//
// Tracks: GHSA-27gc-wj6x-9w55 — analogous reflected-HTML class on the
// form_post emit point.
func TestWriteParamsFormPost_EscapesValues(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	hostile := `https://rp.example.com/cb"><script>alert(1)</script>`
	params := url.Values{
		"error":             {`<img src=x onerror=alert(1)>`},
		"error_description": {`"><script>x()</script>`},
	}
	if err := jarm.WriteParamsFormPost(w, hostile, params); err != nil {
		t.Fatalf("WriteParamsFormPost: %v", err)
	}
	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("redirect not escaped: %s", body)
	}
	if strings.Contains(body, "<img src=x onerror=alert(1)>") {
		t.Errorf("error value not escaped: %s", body)
	}
	if strings.Contains(body, "<script>x()</script>") {
		t.Errorf("error_description not escaped: %s", body)
	}
}

func TestWriteParamsFormPost_RejectsEmptyRedirect(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	err := jarm.WriteParamsFormPost(w, "", url.Values{"code": {"abc"}})
	if !errors.Is(err, jarm.ErrInvalidRedirect) {
		t.Errorf("err=%v want ErrInvalidRedirect", err)
	}
}

func TestWriteParamsFormPost_RejectsEmptyParams(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	err := jarm.WriteParamsFormPost(w, "https://rp.example.com/cb", url.Values{})
	if !errors.Is(err, jarm.ErrEncode) {
		t.Errorf("err=%v want ErrEncode", err)
	}
}

func TestWriteFormPost_CSPHashMatchesScript(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	if err := jarm.WriteFormPost(w, "https://rp.example.com/cb", "j"); err != nil {
		t.Fatalf("WriteFormPost: %v", err)
	}
	csp := w.Result().Header.Get("Content-Security-Policy")
	body := w.Body.String()
	// Recompute the digest from the actual <script>...</script>
	// contents and assert the CSP advertises it. This catches drift
	// between the inline script and the CSP source-list.
	startTag := "<script>"
	endTag := "</script>"
	start := strings.Index(body, startTag)
	if start < 0 {
		t.Fatal("script tag missing")
	}
	end := strings.Index(body, endTag)
	if end < 0 || end <= start {
		t.Fatal("malformed script tag")
	}
	script := body[start+len(startTag) : end]
	sum := sha256.Sum256([]byte(script))
	expected := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(csp, expected) {
		t.Errorf("CSP=%q missing expected hash %q", csp, expected)
	}
}

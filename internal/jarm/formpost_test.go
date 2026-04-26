package jarm_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http/httptest"
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

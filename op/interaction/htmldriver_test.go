package interaction_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// updateGoldens regenerates the testdata/htmldriver/*.golden.html files
// when set. Run "go test -update ./op/interaction/..." after a
// deliberate change to the HTMLDriver output, then commit the regen.
var updateGoldens = flag.Bool("update", false, "update HTMLDriver golden files")

// goldenCases enumerates the prompt fixtures the golden test pins. Each
// case maps to a single .golden.html file under testdata/htmldriver/;
// the file name is the prompt type with dotted segments rewritten to
// dashes so the path stays portable.
func goldenCases() []struct {
	name   string
	prompt interaction.Prompt
} {
	expires := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	return []struct {
		name   string
		prompt interaction.Prompt
	}{
		{
			name: "auth-password",
			prompt: interaction.Prompt{
				Type: "auth.password",
				Data: interaction.PasswordPromptData{UsernameHint: "alice@example.com"},
				Inputs: []interaction.FieldSpec{
					{Name: "username", Kind: interaction.FieldText, Label: "Username", Required: true, MaxLen: 254},
					{Name: "password", Kind: interaction.FieldPassword, Label: "Password", Required: true, MinLen: 8, MaxLen: 256},
				},
				StateRef:  "ref-pw",
				CSRFToken: "csrf-1",
			},
		},
		{
			name: "auth-totp",
			prompt: interaction.Prompt{
				Type: "auth.totp",
				Data: interaction.TOTPPromptData{AttemptsRemaining: 3},
				Inputs: []interaction.FieldSpec{
					{Name: "code", Kind: interaction.FieldOTPCode, Label: "Authenticator code", Required: true, MinLen: 6, MaxLen: 6},
				},
				StateRef: "ref-totp",
			},
		},
		{
			name: "auth-email-otp-send",
			prompt: interaction.Prompt{
				Type: "auth.email_otp.send",
				Data: interaction.EmailOTPSendPromptData{},
				Inputs: []interaction.FieldSpec{
					{Name: "email", Kind: interaction.FieldEmail, Label: "Email address", Required: true, MaxLen: 254},
				},
				StateRef:  "ref-otp-send",
				CSRFToken: "csrf-2",
			},
		},
		{
			name: "auth-email-otp-verify",
			prompt: interaction.Prompt{
				Type: "auth.email_otp.verify",
				Data: interaction.EmailOTPVerifyPromptData{MaskedEmail: "a***@e***", ExpiresAt: expires},
				Inputs: []interaction.FieldSpec{
					{Name: "code", Kind: interaction.FieldOTPCode, Label: "Email code", Required: true, MinLen: 6, MaxLen: 8},
				},
				StateRef: "ref-otp-verify",
			},
		},
		{
			name: "auth-passkey",
			prompt: interaction.Prompt{
				Type:     "auth.passkey",
				Data:     interaction.PasskeyPromptData{Challenge: []byte{0x01, 0x02, 0x03, 0x04}},
				Inputs:   []interaction.FieldSpec{{Name: "assertion", Kind: interaction.FieldHidden}},
				StateRef: "ref-passkey",
			},
		},
		{
			name: "auth-recovery-code",
			prompt: interaction.Prompt{
				Type: "auth.recovery_code",
				Data: interaction.RecoveryCodePromptData{AttemptsRemaining: 2},
				Inputs: []interaction.FieldSpec{
					{Name: "recovery_code", Kind: interaction.FieldText, Label: "Recovery code", Required: true, MinLen: 8, MaxLen: 64},
				},
				StateRef: "ref-recovery",
			},
		},
		{
			name: "captcha",
			prompt: interaction.Prompt{
				Type: "captcha",
				Data: interaction.CaptchaPromptData{Provider: "turnstile", SiteKey: "test-site-key"},
				Inputs: []interaction.FieldSpec{
					{Name: "captcha_token", Kind: interaction.FieldHidden},
				},
				StateRef:  "ref-captcha",
				CSRFToken: "csrf-3",
			},
		},
		{
			name: "consent-scope",
			prompt: interaction.Prompt{
				Type: "consent.scope",
				Data: interaction.ConsentScopePromptData{Scopes: []interaction.ConsentScope{
					{Name: "openid", Description: "Sign you in", Required: true},
					{Name: "profile", Description: "Basic profile information"},
					{Name: "email", Description: "Email address"},
				}},
				StateRef:  "ref-consent",
				CSRFToken: "csrf-4",
			},
		},
		{
			name: "unknown-prompt",
			prompt: interaction.Prompt{
				Type: "myorg.custom.factor",
				Inputs: []interaction.FieldSpec{
					{Name: "secret", Kind: interaction.FieldText, Label: "Secret", Required: true},
				},
				StateRef: "ref-unknown",
			},
		},
		{
			name: "escaping",
			//nolint:gosec // G101: literal HTML payloads are escape-test fixtures, not credentials.
			prompt: interaction.Prompt{
				Type: "auth.password",
				Data: interaction.PasswordPromptData{UsernameHint: `<script>alert("x")</script>`},
				Inputs: []interaction.FieldSpec{
					{Name: "user<name>", Kind: interaction.FieldText, Label: `User & "name"`, Required: true},
				},
				StateRef:  `ref"&<>`,
				CSRFToken: `csrf"&<>`,
			},
		},
	}
}

func TestHTMLDriver_RenderGolden(t *testing.T) {
	t.Parallel()

	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), "GET", "/interaction/u-1", nil)
			if err := (interaction.HTMLDriver{}).Render(rec, req, tc.prompt); err != nil {
				t.Fatalf("Render: %v", err)
			}

			if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q, want text/html; charset=utf-8", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store, no-cache, must-revalidate" {
				t.Errorf("Cache-Control = %q, want no-store, no-cache, must-revalidate", got)
			}
			if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %q, want DENY", got)
			}

			path := filepath.Join("testdata", "htmldriver", tc.name+".golden.html")
			got := rec.Body.Bytes()

			if *updateGoldens {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				// Write with a trailing newline so the file conforms to
				// the repo-wide "files end with LF" convention even
				// though the rendered HTML body does not include one.
				payload := append(append([]byte{}, got...), '\n')
				if err := os.WriteFile(path, payload, 0o644); err != nil { //nolint:gosec // golden files are world-readable test fixtures.
					t.Fatalf("WriteFile %s: %v", path, err)
				}
				return
			}

			want, err := os.ReadFile(path) //nolint:gosec // golden path is fixed under testdata/.
			if err != nil {
				t.Fatalf("ReadFile %s: %v (run with -update to regenerate)", path, err)
			}
			// Trim a single trailing newline the on-disk fixture carries
			// for POSIX text-file convention; the renderer never emits
			// one, so the trim is purely cosmetic.
			want = bytes.TrimRight(want, "\n")
			if !bytes.Equal(got, want) {
				t.Errorf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", tc.name, want, got)
			}
		})
	}
}

func TestHTMLDriver_RenderDeterministic(t *testing.T) {
	t.Parallel()

	prompt := interaction.Prompt{
		Type: "auth.password",
		Data: interaction.PasswordPromptData{UsernameHint: "alice"},
		Inputs: []interaction.FieldSpec{
			{Name: "zeta", Kind: interaction.FieldText, Label: "Zeta"},
			{Name: "alpha", Kind: interaction.FieldText, Label: "Alpha"},
			{Name: "mike", Kind: interaction.FieldText, Label: "Mike"},
		},
		StateRef: "ref-d",
	}
	first := renderToString(t, prompt)
	second := renderToString(t, prompt)
	if first != second {
		t.Errorf("Render is not deterministic\nfirst:  %s\nsecond: %s", first, second)
	}
	// Field inputs MUST appear in name-sorted order so the golden test
	// is stable regardless of the slice the caller hands in.
	idxAlpha := strings.Index(first, `name="alpha"`)
	idxMike := strings.Index(first, `name="mike"`)
	idxZeta := strings.Index(first, `name="zeta"`)
	if idxAlpha < 0 || idxMike < 0 || idxZeta < 0 {
		t.Fatalf("inputs missing: %s", first)
	}
	if idxAlpha >= idxMike || idxMike >= idxZeta {
		t.Errorf("inputs not sorted: alpha=%d mike=%d zeta=%d", idxAlpha, idxMike, idxZeta)
	}
}

// TestHTMLDriver_RenderCSPCompliance is the regression test for the
// §3.4 CSP guarantees. The body must not carry any of the patterns
// that would force the embedder to relax script-src / style-src.
func TestHTMLDriver_RenderCSPCompliance(t *testing.T) {
	t.Parallel()

	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script\b`),
		regexp.MustCompile(`(?i)<style\b`),
		regexp.MustCompile(`(?i)<img\b`),
		regexp.MustCompile(`(?i)\sstyle\s*=`),
		regexp.MustCompile(`(?i)\son[a-z]+\s*=`),
		regexp.MustCompile(`(?i)javascript:`),
	}

	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := renderToString(t, tc.prompt)
			for _, re := range forbidden {
				if re.MatchString(out) {
					t.Errorf("CSP violation: pattern %q matched in output\n%s", re.String(), out)
				}
			}
		})
	}
}

func TestHTMLDriver_RenderSecurityHeaders(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	if err := (interaction.HTMLDriver{}).Render(rec, req, goldenCases()[0].prompt); err != nil {
		t.Fatalf("Render: %v", err)
	}
	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		// same-origin (not no-referrer): no-referrer would make the
		// browser send Origin: null on the form POST, which the
		// interaction CSRF Origin gate rejects. See htmldriver.go.
		"Referrer-Policy": "same-origin",
		"Pragma":          "no-cache",
	}
	for name, want := range headers {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s=%q want %q", name, got, want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("Content-Security-Policy=%q missing %q", csp, want)
		}
	}
	// form-action must NOT be pinned: it would block the post-consent
	// 302 to the relying party's cross-origin redirect_uri.
	if strings.Contains(csp, "form-action") {
		t.Errorf("Content-Security-Policy=%q must not pin form-action", csp)
	}
}

func TestHTMLDriver_ParseSubmission(t *testing.T) {
	t.Parallel()

	body := strings.NewReader("state_ref=ref-1&password=hunter2&csrf_token=tok")
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sub, err := (interaction.HTMLDriver{}).ParseSubmission(r)
	if err != nil {
		t.Fatalf("ParseSubmission: %v", err)
	}
	if sub.StateRef != "ref-1" {
		t.Errorf("StateRef = %q, want ref-1", sub.StateRef)
	}
	if sub.Values["password"] != "hunter2" {
		t.Errorf("Values[password] = %q, want hunter2", sub.Values["password"])
	}
	if sub.Values["csrf_token"] != "tok" {
		t.Errorf("Values[csrf_token] = %q, want tok", sub.Values["csrf_token"])
	}
	if _, ok := sub.Values["state_ref"]; ok {
		t.Errorf("state_ref leaked into Values: %v", sub.Values)
	}
}

func TestHTMLDriver_ParseSubmissionAcceptsCharsetParam(t *testing.T) {
	t.Parallel()

	body := strings.NewReader("state_ref=ref-1&password=hunter2")
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	sub, err := (interaction.HTMLDriver{}).ParseSubmission(r)
	if err != nil {
		t.Fatalf("ParseSubmission: %v", err)
	}
	if sub.StateRef != "ref-1" {
		t.Errorf("StateRef = %q, want ref-1", sub.StateRef)
	}
}

func TestHTMLDriver_ParseSubmissionRejectsNonForm(t *testing.T) {
	t.Parallel()

	body := strings.NewReader(`{"state_ref":"ref-1"}`)
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", body)
	r.Header.Set("Content-Type", "application/json")
	_, err := (interaction.HTMLDriver{}).ParseSubmission(r)
	if !errors.Is(err, interaction.ErrUnsupportedContentType) {
		t.Fatalf("err = %v, want ErrUnsupportedContentType", err)
	}
}

func TestHTMLDriver_ParseSubmissionRejectsMissingContentType(t *testing.T) {
	t.Parallel()

	body := strings.NewReader("state_ref=ref-1")
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", body)
	_, err := (interaction.HTMLDriver{}).ParseSubmission(r)
	if !errors.Is(err, interaction.ErrUnsupportedContentType) {
		t.Fatalf("err = %v, want ErrUnsupportedContentType", err)
	}
}

func TestHTMLDriver_ParseSubmissionRejectsMissingStateRef(t *testing.T) {
	t.Parallel()

	body := strings.NewReader("password=hunter2")
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err := (interaction.HTMLDriver{}).ParseSubmission(r)
	if !errors.Is(err, interaction.ErrMissingStateRef) {
		t.Fatalf("err = %v, want ErrMissingStateRef", err)
	}
}

// TestHTMLDriver_ResolvesLibraryLabelKeys pins the fallback that turns
// the i18n keys library-shipped authenticators emit into short English
// strings. Without this, a zero-config OP renders password forms with
// raw "auth.password.username" / "auth.password.password" labels —
// distracting in the demo and the default zero-config UI.
func TestHTMLDriver_ResolvesLibraryLabelKeys(t *testing.T) {
	t.Parallel()

	cases := []struct {
		labelKey string
		want     string
	}{
		{"auth.password.username", "Username"},
		{"auth.password.password", "Password"},
		{"auth.totp.code", "Authenticator code"},
		{"auth.email_otp.email", "Email address"},
		{"auth.email_otp.code", "Email code"},
		{"auth.recovery_code.code", "Recovery code"},
		{"auth.passkey.response", "Passkey response"},
	}
	for _, tc := range cases {
		t.Run(tc.labelKey, func(t *testing.T) {
			t.Parallel()
			out := renderToString(t, interaction.Prompt{
				Type: "auth.password",
				Data: interaction.PasswordPromptData{},
				Inputs: []interaction.FieldSpec{
					{Name: "field", Kind: interaction.FieldText, Label: tc.labelKey, Required: true},
				},
				StateRef: "ref",
			})
			if !strings.Contains(out, "<label>"+tc.want+"<br>") {
				t.Errorf("rendered HTML does not contain <label>%s<br>; got:\n%s", tc.want, out)
			}
			if strings.Contains(out, tc.labelKey) {
				t.Errorf("rendered HTML still echoes raw i18n key %q; got:\n%s", tc.labelKey, out)
			}
		})
	}
}

// TestHTMLDriver_PreservesUnknownLabels confirms the fallback is
// strictly additive: an embedder-defined key (or a literal English
// label) flows through untouched so embedders shipping their own
// catalog stay in control of the displayed text.
func TestHTMLDriver_PreservesUnknownLabels(t *testing.T) {
	t.Parallel()

	out := renderToString(t, interaction.Prompt{
		Type: "auth.password",
		Data: interaction.PasswordPromptData{},
		Inputs: []interaction.FieldSpec{
			{Name: "f", Kind: interaction.FieldText, Label: "embedder.custom.key", Required: true},
		},
		StateRef: "ref",
	})
	if !strings.Contains(out, "<label>embedder.custom.key<br>") {
		t.Errorf("custom label was rewritten; got:\n%s", out)
	}
}

func renderToString(t *testing.T, prompt interaction.Prompt) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/interaction/u-1", nil)
	if err := (interaction.HTMLDriver{}).Render(rec, req, prompt); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return rec.Body.String()
}

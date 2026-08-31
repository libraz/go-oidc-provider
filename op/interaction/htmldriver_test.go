package interaction_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/i18n"
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
				// Mirrors the field spec the orchestrator's captcha
				// prompt and StepCaptcha both emit: hidden, required.
				// The golden pins that this driver still renders it as
				// something the user can fill in, because it ships no
				// script that could fill it for them.
				Inputs: []interaction.FieldSpec{
					{
						Name:     "captcha_token",
						Kind:     interaction.FieldHidden,
						Label:    "auth.captcha.token",
						Required: true,
						MaxLen:   4096,
					},
				},
				StateRef:  "ref-captcha",
				CSRFToken: "csrf-3",
			},
		},
		{
			name: "consent-scope",
			prompt: interaction.Prompt{
				Type: "consent.scope",
				Data: interaction.ConsentScopePromptData{
					Client: interaction.ClientView{ClientID: "rp-1", Name: "Example RP"},
					Scopes: []interaction.ConsentScope{
						{Name: "openid", Description: "Sign you in", Required: true},
						{Name: "profile", Description: "Basic profile information"},
						{Name: "email", Description: "Email address"},
					},
				},
				StateRef:  "ref-consent",
				CSRFToken: "csrf-4",
			},
		},
		{
			// The picker the built-in chooser interaction emits. The
			// golden pins that every account is a submit control of its
			// own and that the add-account link is present, because the
			// alternative this driver used to render — a lone text input
			// asking for an opaque session identifier — is a page no
			// user can complete.
			name: "interaction-chooser",
			prompt: interaction.Prompt{
				Type: "interaction.chooser",
				Data: interaction.ChooserPromptData{
					Accounts: []interaction.ChooserAccount{
						{SessionID: "sess-A", Subject: "alice", DisplayName: "Alice Example", AuthTime: expires},
						// No display name: the row must still be pickable,
						// labelled by its subject.
						{SessionID: "sess-B", Subject: "bob", AuthTime: expires},
					},
					AddAccountURL: "/oidc/auth?prompt=login&client_id=rp-1",
				},
				Inputs: []interaction.FieldSpec{
					{Name: "session_id", Kind: interaction.FieldText, Label: "chooser.session_id", Required: true, MaxLen: 64},
				},
				StateRef:  "ref-chooser",
				CSRFToken: "csrf-5",
			},
		},
		{
			// The empty chooser group. There is nothing to submit, so
			// the page is the explanatory line plus the link out; a form
			// here would be a control that cannot do anything.
			name: "interaction-chooser-empty",
			prompt: interaction.Prompt{
				Type: "interaction.chooser",
				Data: interaction.ChooserPromptData{
					AddAccountURL: "/oidc/auth?prompt=login&client_id=rp-1",
				},
				Inputs: []interaction.FieldSpec{
					{Name: "session_id", Kind: interaction.FieldText, Label: "chooser.session_id", Required: true, MaxLen: 64},
				},
				StateRef: "ref-chooser-empty",
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

func TestHTMLDriver_ConsentClientNameEscaped(t *testing.T) {
	t.Parallel()

	prompt := interaction.Prompt{
		Type: "consent.scope",
		Data: interaction.ConsentScopePromptData{
			Client: interaction.ClientView{
				ClientID: "rp-fallback",
				Name:     `<script>alert("rp")</script>`,
			},
			Scopes: []interaction.ConsentScope{{Name: "openid"}},
		},
		StateRef: "ref-consent",
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/interaction/u-1", nil)
	if err := (interaction.HTMLDriver{}).Render(rec, req, prompt); err != nil {
		t.Fatalf("Render: %v", err)
	}
	body := rec.Body.String()
	if strings.Contains(body, `<script>`) || strings.Contains(body, `alert("rp")`) {
		t.Fatalf("client name was not escaped:\n%s", body)
	}
	if !strings.Contains(body, `&lt;script&gt;alert(&#34;rp&#34;)&lt;/script&gt;`) {
		t.Fatalf("escaped client name missing:\n%s", body)
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

func TestHTMLDriver_ParseSubmissionJoinsRepeatedFields(t *testing.T) {
	t.Parallel()

	body := strings.NewReader("state_ref=ref-1&approved_scopes=openid&approved_scopes=profile&approved_scopes=email")
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sub, err := (interaction.HTMLDriver{}).ParseSubmission(r)
	if err != nil {
		t.Fatalf("ParseSubmission: %v", err)
	}
	if got := sub.Values[interaction.ConsentApprovedScopesField]; got != "openid profile email" {
		t.Fatalf("approved_scopes=%q want %q", got, "openid profile email")
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

func TestHTMLDriver_TranslatorLocalizesAndEscapesPasswordSurface(t *testing.T) {
	t.Parallel()

	messages := map[string]string{ //nolint:gosec // G101: UI translation keys and labels, not authentication credentials.
		"login.title":            "Connexion <Acme>",
		"login.identifier.label": "Identifiant & compte",
		"login.password.label":   "Passphrase & personnalisée",
		"login.button.submit":    "Entrer & continuer",
	}
	driver := interaction.HTMLDriver{
		Translator: func(locale, key string, _ map[string]string) (string, bool) {
			if locale != "fr" {
				return "", false
			}
			message, ok := messages[key]
			return message, ok
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/interaction/u-1", nil)
	err := driver.Render(rec, req, interaction.Prompt{
		Type:   "auth.password",
		Locale: "fr",
		Inputs: []interaction.FieldSpec{
			{Name: "username", Kind: interaction.FieldText, Label: "auth.password.username", Required: true},
			{Name: "password", Kind: interaction.FieldPassword, Label: "auth.password.password", Required: true},
		},
		StateRef: "ref",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := rec.Body.String()
	for _, escaped := range []string{
		`<html lang="fr">`,
		`<title>Connexion &lt;Acme&gt;</title>`,
		`<label>Identifiant &amp; compte<br>`,
		`<label>Passphrase &amp; personnalisée<br>`,
		`<button type="submit">Entrer &amp; continuer</button>`,
	} {
		if !strings.Contains(out, escaped) {
			t.Errorf("rendered HTML missing %q; got:\n%s", escaped, out)
		}
	}
	if strings.Contains(out, "<Acme>") {
		t.Errorf("translator output reached HTML without escaping:\n%s", out)
	}
}

func TestHTMLDriver_TranslatorMissingKeyRetainsEnglishFallback(t *testing.T) {
	t.Parallel()

	driver := interaction.HTMLDriver{
		Translator: func(_, _ string, _ map[string]string) (string, bool) {
			return "", false
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/interaction/u-1", nil)
	err := driver.Render(rec, req, interaction.Prompt{
		Type: "auth.password",
		Inputs: []interaction.FieldSpec{{
			Name: "password", Kind: interaction.FieldPassword, Label: "auth.password.password",
		}},
		StateRef: "ref",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := rec.Body.String()
	for _, fallback := range []string{"<title>Sign in</title>", "<label>Password<br>", ">Continue</button>"} {
		if !strings.Contains(out, fallback) {
			t.Errorf("rendered HTML missing fallback %q; got:\n%s", fallback, out)
		}
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

// TestHTMLDriver_RequiredHiddenFieldIsAnswerable pins the property the
// captcha gate depends on: a field the prompt declares Required must be
// something a user of this surface can actually fill in.
//
// The driver ships no client-side script, so a hidden input stays at the
// empty value it was rendered with. For the captcha challenge that is
// not a cosmetic defect — the orchestrator counts every rejected answer
// and abandons the chain when the attempts run out, so a page whose
// token field can never hold a value locks out every user who reaches
// the challenge.
func TestHTMLDriver_RequiredHiddenFieldIsAnswerable(t *testing.T) {
	t.Parallel()

	prompt := interaction.Prompt{
		Type: "captcha",
		Data: interaction.CaptchaPromptData{Provider: "turnstile"},
		Inputs: []interaction.FieldSpec{{
			Name:     "captcha_token",
			Kind:     interaction.FieldHidden,
			Label:    "auth.captcha.token",
			Required: true,
			MaxLen:   4096,
		}},
		StateRef: "ref-captcha",
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/interaction/u-1", nil)
	if err := (interaction.HTMLDriver{}).Render(rec, req, prompt); err != nil {
		t.Fatalf("Render: %v", err)
	}
	body := rec.Body.String()

	if strings.Contains(body, `<input type="hidden" name="captcha_token"`) {
		t.Fatalf("required captcha field rendered as a hidden input; no user of this surface can answer it:\n%s", body)
	}
	if !strings.Contains(body, `<input name="captcha_token" type="text" required maxlength="4096">`) {
		t.Errorf("required captcha field is not a fillable text input:\n%s", body)
	}
	if !strings.Contains(body, `Verification token`) {
		t.Errorf("promoted field carries no label, so the user is shown an unexplained box:\n%s", body)
	}
}

// TestHTMLDriver_OptionalHiddenFieldStaysHidden is the counterweight:
// only a Required field is promoted. A hidden field the step does not
// insist on stays out of the user's way.
func TestHTMLDriver_OptionalHiddenFieldStaysHidden(t *testing.T) {
	t.Parallel()

	prompt := interaction.Prompt{
		Type:     "myorg.custom",
		Inputs:   []interaction.FieldSpec{{Name: "opaque", Kind: interaction.FieldHidden}},
		StateRef: "ref-x",
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/interaction/u-1", nil)
	if err := (interaction.HTMLDriver{}).Render(rec, req, prompt); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if body := rec.Body.String(); !strings.Contains(body, `<input type="hidden" name="opaque" value="">`) {
		t.Errorf("optional hidden field was promoted to a visible input:\n%s", body)
	}
}

// TestHTMLDriver_PromotedFieldRoundTripsThroughParseSubmission closes
// the loop: what the promoted input posts has to come back out of the
// driver's own parser under the name the orchestrator reads.
func TestHTMLDriver_PromotedFieldRoundTripsThroughParseSubmission(t *testing.T) {
	t.Parallel()

	form := url.Values{
		"state_ref":     {"ref-captcha"},
		"captcha_token": {"typed-by-the-user"},
	}
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	got, err := (interaction.HTMLDriver{}).ParseSubmission(req)
	if err != nil {
		t.Fatalf("ParseSubmission: %v", err)
	}
	if got.Values["captcha_token"] != "typed-by-the-user" {
		t.Errorf("captcha_token = %q, want the value the user typed", got.Values["captcha_token"])
	}
}

// seedTranslator resolves against the catalogues the library embeds, so
// the localization tests below assert what a deployment that registers
// nothing actually renders — not what a fixture map says it would.
func seedTranslator(tb testing.TB) interaction.MessageTranslator {
	tb.Helper()
	bundles, err := i18n.DefaultBundles()
	if err != nil {
		tb.Fatalf("i18n.DefaultBundles: %v", err)
	}
	byTag := make(map[string]*i18n.Bundle, len(bundles))
	for _, bundle := range bundles {
		byTag[string(bundle.Tag())] = bundle
	}
	return func(locale, key string, data map[string]string) (string, bool) {
		bundle, ok := byTag[locale]
		if !ok {
			return "", false
		}
		return bundle.Get(key, data)
	}
}

// TestHTMLDriver_ConsentPageIsFullyLocalized pins the property a
// registered locale is supposed to buy: one locale selects one language
// for the whole page. The consent screen is where it is easiest to lose,
// because the title and the submit button come from the catalogue while
// the client line and the required marker are the driver's own prose —
// a Japanese user of a zero-configuration deployment must not get a
// Japanese frame around English body lines.
//
// The check is by fallback string rather than by character class: scope
// names are the embedder's protocol identifiers and stay ASCII in every
// locale, so their presence says nothing about the translation.
func TestHTMLDriver_ConsentPageIsFullyLocalized(t *testing.T) {
	t.Parallel()

	driver := interaction.HTMLDriver{Translator: seedTranslator(t)}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/interaction/u-1", nil)
	err := driver.Render(rec, req, interaction.Prompt{
		Type:   "consent.scope",
		Locale: "ja",
		Data: interaction.ConsentScopePromptData{
			Client: interaction.ClientView{ClientID: "rp-1", Name: "Example RP"},
			Scopes: []interaction.ConsentScope{
				{Name: "openid", Required: true},
				{Name: "profile"},
			},
		},
		StateRef: "ref-consent",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := rec.Body.String()

	for _, want := range []string{
		`<html lang="ja">`,
		`<title>Example RP を承認</title>`,
		`<h1>Example RP を承認</h1>`,
		`<p>Example RP が次の情報へのアクセスを求めています:</p>`,
		`<li>openid （必須）</li>`,
		`<button type="submit">許可する</button>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ja consent page missing %q; got:\n%s", want, out)
		}
	}
	for _, english := range []string{"Client: ", "(required)", "Authorize access", ">Continue<"} {
		if strings.Contains(out, english) {
			t.Errorf("ja consent page still carries the English fallback %q; got:\n%s", english, out)
		}
	}
}

// TestHTMLDriver_ConsentFallbacksStayEnglishWithoutCatalogue is the
// other half: routing the two lines through the catalogue must not make
// them disappear for a deployment whose translator answers nothing.
func TestHTMLDriver_ConsentFallbacksStayEnglishWithoutCatalogue(t *testing.T) {
	t.Parallel()

	driver := interaction.HTMLDriver{
		Translator: func(_, _ string, _ map[string]string) (string, bool) {
			return "", false
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/interaction/u-1", nil)
	err := driver.Render(rec, req, interaction.Prompt{
		Type: "consent.scope",
		Data: interaction.ConsentScopePromptData{
			Client: interaction.ClientView{ClientID: "rp-1", Name: "Example RP"},
			Scopes: []interaction.ConsentScope{{Name: "openid", Required: true}},
		},
		StateRef: "ref-consent",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := rec.Body.String()
	for _, fallback := range []string{`<p>Client: Example RP</p>`, `<li>openid (required)</li>`} {
		if !strings.Contains(out, fallback) {
			t.Errorf("consent page missing fallback %q; got:\n%s", fallback, out)
		}
	}
}

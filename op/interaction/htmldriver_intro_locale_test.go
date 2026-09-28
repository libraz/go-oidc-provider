package interaction_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestHTMLDriver_FactorPagesAreFullyLocalized extends the consent page's
// one-locale-one-language property to the factor prompts: the
// informational line above the form and the submit button resolve
// through the catalogue like the title and field labels do, so a
// Japanese user never sees an English line or a "Continue" button on an
// otherwise Japanese page.
func TestHTMLDriver_FactorPagesAreFullyLocalized(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name    string
		prompt  interaction.Prompt
		want    []string
		english string
	}{
		{
			name:    "password hint",
			prompt:  interaction.Prompt{Type: "auth.password", Data: interaction.PasswordPromptData{UsernameHint: "alice"}},
			want:    []string{"<p>ヒント: alice</p>"},
			english: "Hint: ",
		},
		{
			name:    "totp attempts",
			prompt:  interaction.Prompt{Type: "auth.totp", Data: interaction.TOTPPromptData{AttemptsRemaining: 3}},
			want:    []string{"<p>残り試行回数: 3</p>", `<button type="submit">続行</button>`},
			english: "Attempts remaining",
		},
		{
			name:    "recovery attempts",
			prompt:  interaction.Prompt{Type: "auth.recovery_code", Data: interaction.RecoveryCodePromptData{AttemptsRemaining: 7}},
			want:    []string{"<p>残り試行回数: 7</p>", `<button type="submit">続行</button>`},
			english: "Attempts remaining",
		},
		{
			name:    "email code destination",
			prompt:  interaction.Prompt{Type: "auth.email_otp.verify", Data: interaction.EmailOTPVerifyPromptData{MaskedEmail: "a***@example.com"}},
			want:    []string{"<p>a***@example.com にコードを送信しました。</p>", `<button type="submit">続行</button>`},
			english: "Code sent to",
		},
		{
			name:    "captcha provider",
			prompt:  interaction.Prompt{Type: "captcha", Data: interaction.CaptchaPromptData{Provider: "turnstile"}},
			want:    []string{"<p>CAPTCHA プロバイダー: turnstile</p>", `<button type="submit">続行</button>`},
			english: "Captcha provider",
		},
	}
	driver := interaction.HTMLDriver{Translator: seedTranslator(t)}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			prompt := row.prompt
			prompt.Locale = "ja"
			prompt.StateRef = "ref-" + strings.ReplaceAll(row.name, " ", "-")
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/interaction/u-1", nil)
			if err := driver.Render(rec, req, prompt); err != nil {
				t.Fatalf("Render: %v", err)
			}
			out := rec.Body.String()
			for _, want := range row.want {
				if !strings.Contains(out, want) {
					t.Errorf("ja page missing %q; got:\n%s", want, out)
				}
			}
			for _, english := range []string{row.english, ">Continue<"} {
				if strings.Contains(out, english) {
					t.Errorf("ja page still carries the English fallback %q; got:\n%s", english, out)
				}
			}
		})
	}
}

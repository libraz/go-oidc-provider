package interaction_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

func chooseFactorPrompt() interaction.Prompt {
	return interaction.Prompt{
		Type: interaction.PromptTypeChooseFactor,
		Data: interaction.FactorChoicePromptData{
			Options: []interaction.FactorOption{
				{Kind: "totp", Label: "auth.factor.totp"},
				{Kind: "myorg.sms", Label: "auth.factor.myorg.sms"},
				{Kind: `x"><b>`, Label: "auth.factor.hostile"},
			},
		},
		StateRef:  "ref-choose",
		CSRFToken: "csrf-6",
	}
}

func renderChooseFactor(t *testing.T, d interaction.HTMLDriver) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/interaction/u-1", nil)
	if err := d.Render(rec, req, chooseFactorPrompt()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return rec.Body.String()
}

func TestHTMLDriver_ChooseFactor(t *testing.T) {
	t.Parallel()

	t.Run("radio form without script", func(t *testing.T) {
		t.Parallel()
		body := renderChooseFactor(t, interaction.HTMLDriver{})

		for _, want := range []string{
			`<form method="post">`,
			`<input type="hidden" name="state_ref" value="ref-choose">`,
			`<input type="hidden" name="csrf_token" value="csrf-6">`,
			`<input type="radio" name="factor" value="totp" checked required>`,
			`<input type="radio" name="factor" value="myorg.sms" required>`,
			`<button type="submit">Continue</button>`,
			`<h1>Choose how to sign in</h1>`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("body lacks %q\n%s", want, body)
			}
		}
		if strings.Contains(body, "<script") {
			t.Errorf("body carries a script element:\n%s", body)
		}
		if n := strings.Count(body, "checked"); n != 1 {
			t.Errorf("checked appears %d times, want exactly the first option", n)
		}
	})

	t.Run("unresolved label shows the kind", func(t *testing.T) {
		t.Parallel()
		body := renderChooseFactor(t, interaction.HTMLDriver{})
		if !strings.Contains(body, `required> myorg.sms</label>`) {
			t.Errorf("an option with no catalogue entry should show its kind:\n%s", body)
		}
	})

	t.Run("translator resolves the label key", func(t *testing.T) {
		t.Parallel()
		d := interaction.HTMLDriver{Translator: func(_, key string, _ map[string]string) (string, bool) {
			if key == "auth.factor.totp" {
				return "Authenticator app", true
			}
			return "", false
		}}
		body := renderChooseFactor(t, d)
		if !strings.Contains(body, `checked required> Authenticator app</label>`) {
			t.Errorf("translated label missing:\n%s", body)
		}
		if !strings.Contains(body, `required> myorg.sms</label>`) {
			t.Errorf("untranslated option should fall back to its kind:\n%s", body)
		}
	})

	t.Run("kind is escaped", func(t *testing.T) {
		t.Parallel()
		body := renderChooseFactor(t, interaction.HTMLDriver{})
		if strings.Contains(body, `<b>`) {
			t.Errorf("hostile kind reached the page unescaped:\n%s", body)
		}
	})

	t.Run("submission carries the factor", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1",
			strings.NewReader("state_ref=ref-choose&factor=totp"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		sub, err := (interaction.HTMLDriver{}).ParseSubmission(r)
		if err != nil {
			t.Fatalf("ParseSubmission: %v", err)
		}
		if got := sub.Values[interaction.FactorChoiceField]; got != "totp" {
			t.Errorf("Values[%q] = %q, want totp", interaction.FactorChoiceField, got)
		}
	})
}

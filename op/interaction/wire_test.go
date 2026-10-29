package interaction_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestPromptWireKeys_Golden pins the JSON each PromptData shape marshals
// to. The member names are the contract SPA front ends read, so a rename
// of a Go field or tag must show up here as a golden diff. Regenerate with
// "go test -update ./op/interaction/..." after a deliberate change.
func TestPromptWireKeys_Golden(t *testing.T) {
	t.Parallel()

	stamp := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		value any
	}{
		{"auth-password", interaction.PasswordPromptData{UsernameHint: "alice@example.com"}},
		{"auth-totp", interaction.TOTPPromptData{AttemptsRemaining: 3}},
		{"auth-email-otp-send", interaction.EmailOTPSendPromptData{}},
		{"auth-email-otp-verify", interaction.EmailOTPVerifyPromptData{MaskedEmail: "a***@e***", ExpiresAt: stamp}},
		{"auth-passkey", interaction.PasskeyPromptData{
			Challenge: []byte{0x01, 0x02, 0x03, 0x04},
			AllowCredentials: []interaction.PasskeyCredentialDescriptor{
				{ID: []byte{0xff, 0xee}, Type: "public-key", Transports: []string{"usb", "internal"}},
			},
		}},
		{"auth-recovery-code", interaction.RecoveryCodePromptData{AttemptsRemaining: 2}},
		{"captcha", interaction.CaptchaPromptData{Provider: "turnstile", SiteKey: "test-site-key"}},
		{"consent-scope", interaction.ConsentScopePromptData{
			Client: interaction.ClientView{ClientID: "rp-1", Name: "Example RP"},
			Scopes: []interaction.ConsentScope{
				{Name: "openid", Description: "Sign you in", Required: true},
				{Name: "email", Description: "Email address"},
			},
		}},
		{"interaction-chooser", interaction.ChooserPromptData{
			Accounts: []interaction.ChooserAccount{
				{SessionID: "sess-A", Subject: "alice", DisplayName: "Alice Example", AuthTime: stamp},
			},
			AddAccountURL: "/oidc/auth?prompt=login",
		}},
		{"auth-choose-factor", interaction.FactorChoicePromptData{
			Options: []interaction.FactorOption{
				{Kind: "totp", Label: "auth.factor.totp"},
				{Kind: "passkey", Label: "auth.factor.passkey"},
			},
		}},
		{"prompt-error", interaction.Prompt{
			Type: "auth.password",
			Data: interaction.PasswordPromptData{UsernameHint: "alice"},
			Inputs: []interaction.FieldSpec{
				{Name: "password", Kind: interaction.FieldPassword, Label: "auth.password.password", LabelText: "Password", Required: true},
			},
			StateRef: "ref-1",
			Locale:   "en",
			Error: &interaction.PromptError{
				Code:    interaction.PromptErrorCredentialsRejected,
				Message: "The details you entered are incorrect. Try again.",
			},
		}},
		{"prompt-error-code-only", interaction.Prompt{
			Type:     "auth.password",
			StateRef: "ref-1",
			Error:    &interaction.PromptError{Code: interaction.PromptErrorCredentialsRejected},
		}},
		{"field-specs-label-text", []interaction.FieldSpec{
			{Name: "code", Kind: interaction.FieldOTPCode, Label: "auth.totp.code", LabelText: "Authenticator code", MaxLen: 6, MinLen: 6, Required: true, Pattern: "[0-9]{6}"},
		}},
		{"auth-choose-factor-label-text", interaction.FactorChoicePromptData{
			Options: []interaction.FactorOption{
				{Kind: "totp", Label: "auth.factor.totp", LabelText: "Authenticator app"},
				{Kind: "passkey", Label: "auth.factor.passkey", LabelText: "Passkey"},
			},
		}},
		{"field-specs", []interaction.FieldSpec{
			{Name: "code", Kind: interaction.FieldOTPCode, Label: "auth.totp.code", MaxLen: 6, MinLen: 6, Required: true, Pattern: "[0-9]{6}"},
			{Name: "password", Kind: interaction.FieldPassword, Label: "auth.password.password"},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			path := filepath.Join("testdata", "wire", tc.name+".golden.json")
			if *updateGoldens {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
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
			want = bytes.TrimRight(want, "\n")
			if !bytes.Equal(got, want) {
				t.Errorf("wire golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", tc.name, want, got)
			}
		})
	}
}

func TestFieldKind_TextRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		kind interaction.FieldKind
		text string
	}{
		{interaction.FieldText, "text"},
		{interaction.FieldPassword, "password"},
		{interaction.FieldOTPCode, "otp_code"},
		{interaction.FieldEmail, "email"},
		{interaction.FieldHidden, "hidden"},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()

			got, err := tc.kind.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText: %v", err)
			}
			if string(got) != tc.text {
				t.Errorf("MarshalText = %q, want %q", got, tc.text)
			}

			var back interaction.FieldKind
			if err := back.UnmarshalText([]byte(tc.text)); err != nil {
				t.Fatalf("UnmarshalText: %v", err)
			}
			if back != tc.kind {
				t.Errorf("UnmarshalText(%q) = %d, want %d", tc.text, back, tc.kind)
			}

			// The kind also survives inside a FieldSpec, where encoding/json
			// reaches it through the text interfaces.
			encoded, err := json.Marshal(interaction.FieldSpec{Name: "f", Kind: tc.kind})
			if err != nil {
				t.Fatalf("Marshal FieldSpec: %v", err)
			}
			var spec interaction.FieldSpec
			if err := json.Unmarshal(encoded, &spec); err != nil {
				t.Fatalf("Unmarshal FieldSpec: %v", err)
			}
			if spec.Kind != tc.kind {
				t.Errorf("FieldSpec round trip kind = %d, want %d", spec.Kind, tc.kind)
			}
		})
	}

	t.Run("unknown text is an error", func(t *testing.T) {
		t.Parallel()
		for _, text := range []string{"", "Text", "number", "1"} {
			var k interaction.FieldKind
			if err := k.UnmarshalText([]byte(text)); err == nil {
				t.Errorf("UnmarshalText(%q) succeeded, want an error", text)
			}
		}
	})

	t.Run("out of range value is an error", func(t *testing.T) {
		t.Parallel()
		for _, k := range []interaction.FieldKind{-1, 5, 99} {
			if _, err := k.MarshalText(); err == nil {
				t.Errorf("MarshalText(%d) succeeded, want an error", int(k))
			}
		}
	})
}

// TestFactorLabelKey pins the catalogue key every factor-choice label
// resolves through, built-in or external.
func TestFactorLabelKey(t *testing.T) {
	t.Parallel()

	//nolint:gosec // G101: catalogue keys, not credentials.
	for kind, want := range map[string]string{
		"password":      "auth.factor.password",
		"passkey":       "auth.factor.passkey",
		"totp":          "auth.factor.totp",
		"email_otp":     "auth.factor.email_otp",
		"recovery_code": "auth.factor.recovery_code",
		"myorg.sms":     "auth.factor.myorg.sms",
	} {
		if got := interaction.FactorLabelKey(kind); got != want {
			t.Errorf("FactorLabelKey(%q) = %q, want %q", kind, got, want)
		}
	}
}

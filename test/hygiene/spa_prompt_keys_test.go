package hygiene_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// The shipped SPA and the JSON driver are two halves of one contract
// that no compiler checks: the driver serialises a Go struct, the
// bundle reads the resulting member names out of a JavaScript object.
// When a renderer reads a spelling the driver never writes, the screen
// renders empty and the user approves — or picks from — a dialogue
// that showed them nothing. Nothing else in the tree would notice, so
// this test re-derives the wire keys from the driver itself and pins
// that the bundle names them.

// spaBundlePath is the hand-written bundle every SPA example serves.
const spaBundlePath = "../../examples/internal/webui/static/assets/main.js"

// TestSPABundleReadsDriverPromptKeys pins both halves at once. Each
// case names the members a renderer cannot do its job without; the
// test asserts the driver really emits those spellings (so renaming
// the Go field is caught) and that the renderer's source names them
// (so reading a spelling the driver never writes is caught). Purely
// decorative members — a logo URL, a relative timestamp — are left
// out on purpose: requiring every member would turn any additive
// field into a bundle edit.
//
// The check is by name rather than by render because the repo has no
// JavaScript runtime, and spelling drift — not rendering logic — is
// the failure this contract has actually suffered.
func TestSPABundleReadsDriverPromptKeys(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile(filepath.Clean(spaBundlePath))
	if err != nil {
		t.Fatalf("read SPA bundle: %v", err)
	}
	bundle := string(src)

	cases := []struct {
		name   string
		prompt interaction.Prompt
		// renderer is the bundle function that must read the keys.
		renderer string
		// required lists the payload members the screen is
		// meaningless without.
		required []string
	}{
		{
			name:     "consent",
			renderer: "renderConsent",
			required: []string{"scopes", "name", "description", "required", "client"},
			prompt: interaction.Prompt{
				Type: "consent.scope",
				Data: interaction.ConsentScopePromptData{
					Scopes: []interaction.ConsentScope{
						{Name: "openid", Description: "Sign you in", Required: true},
						{Name: "email", Description: "Read your address"},
					},
					Client: interaction.ClientView{ClientID: "rp-1", Name: "Example RP"},
				},
			},
		},
		{
			name:     "chooser",
			renderer: "renderChooser",
			required: []string{"accounts", "session_id", "display_name", "add_account_url"},
			prompt: interaction.Prompt{
				Type: "interaction.chooser",
				Data: interaction.ChooserPromptData{
					Accounts: []interaction.ChooserAccount{{
						SessionID:   "sess-1",
						Subject:     "user-1",
						DisplayName: "Alice",
						AuthTime:    time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
					}},
					AddAccountURL: "https://op.example/oidc/authorize?prompt=login",
				},
			},
		},
		{
			name:     "factor_choice",
			renderer: "renderFactorChoice",
			required: []string{"options", "kind", "label"},
			prompt: interaction.Prompt{
				Type: interaction.PromptTypeChooseFactor,
				Data: interaction.FactorChoicePromptData{
					Options: []interaction.FactorOption{
						{Kind: "totp", Label: "auth.factor.totp"},
						{Kind: "passkey", Label: "auth.factor.passkey"},
					},
				},
			},
		},
		{
			name:     "passkey",
			renderer: "requestAssertion",
			required: []string{"challenge", "allow_credentials", "id", "type", "transports"},
			prompt: interaction.Prompt{
				Type: "auth.passkey",
				Data: interaction.PasskeyPromptData{
					Challenge: []byte("challenge"),
					AllowCredentials: []interaction.PasskeyCredentialDescriptor{
						{ID: []byte("cred"), Type: "public-key", Transports: []string{"usb"}},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			emitted := dataKeys(t, renderPrompt(t, tc.prompt))
			fn := rendererBody(t, bundle, tc.renderer)
			for _, key := range tc.required {
				if !emitted[key] {
					t.Errorf("the JSON driver emits no %q for this prompt; the bundle is reading a "+
						"member the wire no longer carries (emitted: %v)", key, sortedKeys(emitted))
					continue
				}
				if !strings.Contains(fn, key) {
					t.Errorf("%s never reads %q, which is the spelling the JSON driver emits; "+
						"the screen renders that part of the dialogue empty", tc.renderer, key)
				}
			}
		})
	}
}

// TestSPABundleReadsPromptErrorAndLabelText pins the two members the
// credential screens depend on that sit outside "data": the resolved
// input label and the rejected-submission notice. Without them the bundle
// shows an i18n key as a label, or no hint that the password was wrong.
func TestSPABundleReadsPromptErrorAndLabelText(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile(filepath.Clean(spaBundlePath))
	if err != nil {
		t.Fatalf("read SPA bundle: %v", err)
	}
	bundle := string(src)

	type reader struct {
		fn   string
		keys []string
	}
	rejected := &interaction.PromptError{
		Code:    interaction.PromptErrorCredentialsRejected,
		Message: "The details you entered are incorrect. Try again.",
	}
	cases := []struct {
		name    string
		prompt  interaction.Prompt
		readers []reader
	}{
		{
			name: "password",
			prompt: interaction.Prompt{
				Type: "auth.password",
				Data: interaction.PasswordPromptData{},
				Inputs: []interaction.FieldSpec{
					{Name: "password", Kind: interaction.FieldPassword, Label: "auth.password.password", LabelText: "Password"},
				},
				Error: rejected,
			},
			readers: []reader{
				{fn: "buildField", keys: []string{"label_text"}},
				{fn: "renderPromptError", keys: []string{"error", "message"}},
			},
		},
		{
			name: "totp",
			prompt: interaction.Prompt{
				Type: "auth.totp",
				Data: interaction.TOTPPromptData{AttemptsRemaining: 2},
				Inputs: []interaction.FieldSpec{
					{Name: "code", Kind: interaction.FieldOTPCode, Label: "auth.totp.code", LabelText: "Authenticator code"},
				},
				Error: rejected,
			},
			readers: []reader{
				{fn: "buildField", keys: []string{"label_text"}},
				{fn: "renderPromptError", keys: []string{"error", "message"}},
			},
		},
		{
			name: "factor_choice",
			prompt: interaction.Prompt{
				Type: interaction.PromptTypeChooseFactor,
				Data: interaction.FactorChoicePromptData{
					Options: []interaction.FactorOption{{Kind: "totp", Label: "auth.factor.totp", LabelText: "Authenticator app"}},
				},
			},
			readers: []reader{{fn: "renderFactorChoice", keys: []string{"label_text"}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var decoded any
			if err := json.Unmarshal(renderPrompt(t, tc.prompt), &decoded); err != nil {
				t.Fatalf("decode prompt: %v", err)
			}
			emitted := map[string]bool{}
			collectKeys(decoded, emitted)
			for _, r := range tc.readers {
				fn := rendererBody(t, bundle, r.fn)
				for _, key := range r.keys {
					if !emitted[key] {
						t.Errorf("the JSON driver emits no %q for this prompt (emitted: %v)", key, sortedKeys(emitted))
						continue
					}
					if !strings.Contains(fn, key) {
						t.Errorf("%s never reads %q, which is the spelling the JSON driver emits", r.fn, key)
					}
				}
			}
		})
	}
}

// renderPrompt returns the JSON body JSONDriver writes for prompt.
func renderPrompt(tb testing.TB, prompt interaction.Prompt) []byte {
	tb.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(tb.Context(), http.MethodGet, "/oidc/interaction/uid", http.NoBody)
	if err := (interaction.JSONDriver{}).Render(rec, req, prompt); err != nil {
		tb.Fatalf("JSONDriver.Render: %v", err)
	}
	return rec.Body.Bytes()
}

// dataKeys returns the set of member names reachable under the
// prompt's "data" member, including members of objects nested inside
// arrays. The prompt envelope itself is excluded: its keys are read
// by the shared dispatch path, not by a per-prompt renderer.
func dataKeys(tb testing.TB, body []byte) map[string]bool {
	tb.Helper()
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		tb.Fatalf("decode prompt envelope: %v", err)
	}
	if len(envelope.Data) == 0 {
		tb.Fatalf("prompt carried no Data member: %s", body)
	}
	var decoded any
	if err := json.Unmarshal(envelope.Data, &decoded); err != nil {
		tb.Fatalf("decode prompt data: %v", err)
	}
	seen := map[string]bool{}
	collectKeys(decoded, seen)
	return seen
}

// sortedKeys renders a key set in a stable order for failure output.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// collectKeys walks the decoded JSON value and records every object
// member name it finds.
func collectKeys(v any, into map[string]bool) {
	switch typed := v.(type) {
	case map[string]any:
		for k, nested := range typed {
			into[k] = true
			collectKeys(nested, into)
		}
	case []any:
		for _, nested := range typed {
			collectKeys(nested, into)
		}
	}
}

// rendererBody returns the source text of the named bundle function,
// from its declaration to the closing brace at column zero. The
// bundle is hand-written with one function per line-start, so the
// brace scan is exact rather than heuristic.
func rendererBody(tb testing.TB, bundle, name string) string {
	tb.Helper()
	decl := "function " + name + "("
	start := strings.Index(bundle, decl)
	if start < 0 {
		tb.Fatalf("the SPA bundle declares no %s; the prompt has no renderer at all", name)
	}
	rest := bundle[start:]
	if end := strings.Index(rest, "\n}\n"); end >= 0 {
		return rest[:end]
	}
	return rest
}

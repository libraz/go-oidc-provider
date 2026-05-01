package interaction_test

import (
	"encoding/json"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestPrompt_LocaleEnvelopeRoundtrip pins the wire shape SPAs read on
// /interaction/{uid}: a populated Prompt round-trips through
// json.Marshal / Unmarshal with `locale`, `ui_locales_hint`, and
// `locales_available` populated. The orchestrator stamps these
// fields before [Driver.Render] (see plan 012); the test exists so a
// future refactor that drops a tag or renames a field fails loudly
// rather than silently breaking every embedder SPA.
func TestPrompt_LocaleEnvelopeRoundtrip(t *testing.T) {
	t.Parallel()

	prompt := interaction.Prompt{
		Type:             "auth.password",
		StateRef:         "ref-1",
		Locale:           "ja",
		UILocalesHint:    []string{"ja-JP", "en-US"},
		LocalesAvailable: []string{"en", "ja", "fr"},
	}
	out, err := json.Marshal(prompt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got, want := raw["locale"], "ja"; got != want {
		t.Errorf("locale = %v, want %v", got, want)
	}
	if hint, ok := raw["ui_locales_hint"].([]any); !ok || len(hint) != 2 {
		t.Errorf("ui_locales_hint shape unexpected: %v", raw["ui_locales_hint"])
	}
	if avail, ok := raw["locales_available"].([]any); !ok || len(avail) != 3 {
		t.Errorf("locales_available shape unexpected: %v", raw["locales_available"])
	}
}

// TestPrompt_LocaleFieldsOmitWhenEmpty pins that the orchestrator's
// "no resolver wired" branch (unit tests, embedders without i18n)
// produces a backward-compatible envelope. SPAs that pre-date the
// fields keep working because empty strings / slices stay off the
// wire.
func TestPrompt_LocaleFieldsOmitWhenEmpty(t *testing.T) {
	t.Parallel()

	prompt := interaction.Prompt{
		Type:     "auth.password",
		StateRef: "ref-1",
	}
	out, err := json.Marshal(prompt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"locale", "ui_locales_hint", "locales_available"} {
		if _, ok := raw[key]; ok {
			t.Errorf("empty Prompt should omit %q on the wire, got %v", key, raw[key])
		}
	}
}

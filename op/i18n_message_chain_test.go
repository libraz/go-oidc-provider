package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestProviderLocaleResolver_MessageEndsAtEnglish pins the last tier of
// the chain [op.Resolver.Message] documents: with a partial bundle as the
// default locale, a key neither the requested nor the default bundle
// defines still resolves from the library's English catalogue.
func TestProviderLocaleResolver_MessageEndsAtEnglish(t *testing.T) {
	t.Parallel()

	french, err := op.LocaleBundleFromMap("fr", map[string]string{"login.title": "Connexion"})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap(fr): %v", err)
	}
	provider, err := op.New(append(validBaseOpts(t), op.WithLocale(french), op.WithDefaultLocale("fr"))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	resolver := provider.LocaleResolver()
	if got, ok := resolver.Message("fr", "login.password.label", nil); !ok || got != "Password" {
		t.Errorf("Message(fr, login.password.label) = (%q, %v), want the English catalogue past the default", got, ok)
	}
	if got, ok := resolver.Message("fr", "missing.key", nil); ok || got != "" {
		t.Errorf("Message(fr, missing.key) = (%q, %v), want (empty, false)", got, ok)
	}
}

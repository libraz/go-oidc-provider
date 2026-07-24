package op_test

import (
	"context"
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// stubPreferredLocaleStore returns a fixed locale for any subject.
// The resolver tests do not exercise the error path through the
// public surface; the internal test in i18n_internal_test.go covers
// that branch.
type stubPreferredLocaleStore struct {
	tag op.Locale
}

func (s stubPreferredLocaleStore) PreferredLocale(_ context.Context, _ string) (op.Locale, error) {
	return s.tag, nil
}

func TestLocaleBundleFromMap_RejectsEmptyLocale(t *testing.T) {
	t.Parallel()
	if _, err := op.LocaleBundleFromMap("", map[string]string{"k": "v"}); err == nil {
		t.Fatalf("expected error on empty locale")
	}
}

func TestLocaleBundleFromMap_AcceptsEmptyMap(t *testing.T) {
	t.Parallel()
	b, err := op.LocaleBundleFromMap(op.LocaleEnglish, nil)
	if err != nil {
		t.Fatalf("LocaleBundleFromMap with nil map: %v", err)
	}
	if b.Locale() != op.LocaleEnglish {
		t.Fatalf("Locale = %q, want %q", b.Locale(), op.LocaleEnglish)
	}
}

func TestWithDefaultLocale_AcceptsSeed(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t), op.WithDefaultLocale(op.LocaleJapanese))...)
	if err != nil {
		t.Fatalf("op.New with default ja: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}

func TestWithDefaultLocale_RejectsUnregistered(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithDefaultLocale("zz"))...)
	if err == nil {
		t.Fatalf("expected error for unregistered default locale")
	}
}

func TestWithLocale_RegistersOverride(t *testing.T) {
	t.Parallel()

	bundle, err := op.LocaleBundleFromMap(op.LocaleEnglish, map[string]string{
		"consent.title": "OVERRIDDEN {client_name}",
	})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap: %v", err)
	}
	provider, err := op.New(append(validBaseOpts(t), op.WithLocale(bundle))...)
	if err != nil {
		t.Fatalf("op.New with override: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}

func TestProviderLocaleResolver_ReflectsRegistration(t *testing.T) {
	t.Parallel()

	bundle, err := op.LocaleBundleFromMap("fr", map[string]string{
		"login.title": "Connexion",
	})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap(fr): %v", err)
	}
	provider, err := op.New(append(validBaseOpts(t),
		op.WithLocale(bundle),
		op.WithDefaultLocale("fr"),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	r := provider.LocaleResolver()
	if r == nil {
		t.Fatalf("LocaleResolver() returned nil")
	}
	if got := r.Default(); got != "fr" {
		t.Errorf("Default() = %q, want %q", got, "fr")
	}
	if got := r.Available(); !slices.Contains(got, op.Locale("fr")) {
		t.Errorf("Available() %v missing fr", got)
	}
	if got := r.Available(); !slices.Contains(got, op.LocaleEnglish) || !slices.Contains(got, op.LocaleJapanese) {
		t.Errorf("Available() %v missing seed en/ja", got)
	}
}

func TestProviderLocaleResolver_ResolvesUILocales(t *testing.T) {
	t.Parallel()

	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	r := provider.LocaleResolver()
	if r == nil {
		t.Fatalf("LocaleResolver() returned nil")
	}
	got := r.Resolve(context.Background(), op.ResolveRequest{UILocales: []string{"ja"}})
	if got != op.LocaleJapanese {
		t.Errorf("Resolve() = %q, want %q (ui_locales=ja)", got, op.LocaleJapanese)
	}
}

func TestProviderLocaleResolver_MessageFallbackAndRawText(t *testing.T) {
	t.Parallel()

	french, err := op.LocaleBundleFromMap("fr", map[string]string{
		"login.title": "Connexion {brand}",
	})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap(fr): %v", err)
	}
	provider, err := op.New(append(validBaseOpts(t), op.WithLocale(french))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	resolver := provider.LocaleResolver()
	if got, ok := resolver.Message("fr", "login.title", map[string]string{"brand": "<Acme>"}); !ok ||
		got != "Connexion <Acme>" {
		t.Errorf("Message(fr, login.title) = (%q, %v), want raw substituted text", got, ok)
	}
	if got, ok := resolver.Message("FR-FR", "login.title", map[string]string{"brand": "Acme"}); !ok ||
		got != "Connexion Acme" {
		t.Errorf("Message(FR-FR, login.title) = (%q, %v), want canonicalized language-subtag match", got, ok)
	}
	if got, ok := resolver.Message("fr", "login.password.label", nil); !ok || got != "Password" {
		t.Errorf("Message(fr, login.password.label) = (%q, %v), want English default fallback", got, ok)
	}
	if got, ok := resolver.Message("fr", "missing.key", nil); ok || got != "" {
		t.Errorf("Message(fr, missing.key) = (%q, %v), want (empty, false)", got, ok)
	}
}

func TestWithPreferredLocaleStore_ChainHead(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithPreferredLocaleStore(stubPreferredLocaleStore{tag: op.LocaleJapanese}),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	got := provider.LocaleResolver().Resolve(context.Background(), op.ResolveRequest{
		Subject:        "user-1",
		AcceptLanguage: "en",
	})
	if got != op.LocaleJapanese {
		t.Errorf("Resolve() = %q, want %q (preferred store should win over Accept-Language)", got, op.LocaleJapanese)
	}
}

func TestWithPreferredLocaleStore_RejectsNil(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithPreferredLocaleStore(nil))...); err == nil {
		t.Fatalf("op.New with nil PreferredLocaleStore: expected error, got nil")
	}
}

func TestWithLocale_RegistersCustomLocale(t *testing.T) {
	t.Parallel()

	bundle, err := op.LocaleBundleFromMap("zh-CN", map[string]string{
		"consent.title": "授权 {client_name}",
	})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap: %v", err)
	}
	provider, err := op.New(append(validBaseOpts(t),
		op.WithLocale(bundle),
		op.WithDefaultLocale("zh-CN"),
	)...)
	if err != nil {
		t.Fatalf("op.New with custom locale + default: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}

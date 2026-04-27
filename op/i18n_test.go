package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

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

package op_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

func TestSetLocaleCookie_StoresARegisteredLocaleAddedByOption(t *testing.T) {
	t.Parallel()

	bundle, err := op.LocaleBundleFromMap("zh-CN", map[string]string{"consent.title": "授权"})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap: %v", err)
	}
	provider, err := op.New(append(validBaseOpts(t), op.WithLocale(bundle))...)
	if err != nil {
		t.Fatalf("op.New with zh-CN: %v", err)
	}

	rec := httptest.NewRecorder()
	if err := provider.SetLocaleCookie(rec, "zh-CN"); err != nil {
		t.Fatalf("SetLocaleCookie(zh-CN): %v", err)
	}
	// The stored value is the canonical registered tag, not the input
	// verbatim — the cookie has to be readable by the resolver, which
	// canonicalises everything it reads.
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != "zh-cn" {
		t.Fatalf("cookies = %v, want a single __Host-oidc_locale=zh-cn", cookies)
	}
}

// A Provider that never went through op.New has no registered locales,
// so every locale is unregistered. The guard exists because the zero
// value is reachable from embedder code (a struct field left unset)
// and a nil-map read would otherwise panic inside the resolver.
func TestSetLocaleCookie_RejectsEverythingOnAnUnbuiltProvider(t *testing.T) {
	t.Parallel()

	for name, provider := range map[string]*op.Provider{
		"nil provider":  nil,
		"zero provider": {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			if err := provider.SetLocaleCookie(rec, op.LocaleEnglish); !errors.Is(err, op.ErrLocaleNotRegistered) {
				t.Fatalf("SetLocaleCookie = %v, want ErrLocaleNotRegistered", err)
			}
			if cookies := rec.Result().Cookies(); len(cookies) != 0 {
				t.Errorf("wrote %d cookies on an unbuilt provider", len(cookies))
			}
		})
	}
}

// A region-qualified bundle has to be reachable from every entry point
// that names a locale, however the caller spells the tag. The four
// surfaces are joined end to end here because each one alone can look
// correct while the pair disagrees: SetLocaleCookie can report success
// for a tag the resolver later drops, and discovery can advertise a
// vocabulary the ui_locales parameter does not accept.
func TestLocale_RegionQualifiedBundleRoundTripsEverySurface(t *testing.T) {
	t.Parallel()

	const wantConsentTitle = "Autorizar {client_name}"

	bundle, err := op.LocaleBundleFromMap("pt-BR", map[string]string{
		"consent.title": wantConsentTitle,
	})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap(pt-BR): %v", err)
	}
	if got := bundle.Locale(); got != "pt-br" {
		t.Fatalf("bundle.Locale() = %q, want the canonical %q", got, "pt-br")
	}

	provider, err := op.New(append(validBaseOpts(t), op.WithLocale(bundle))...)
	if err != nil {
		t.Fatalf("op.New with pt-BR: %v", err)
	}
	resolver := provider.LocaleResolver()

	// A picker persists the user's choice in whatever casing its own UI
	// used, and the OP accepts it.
	rec := httptest.NewRecorder()
	if err := provider.SetLocaleCookie(rec, "PT-BR"); err != nil {
		t.Fatalf("SetLocaleCookie(PT-BR): %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("SetLocaleCookie wrote %d cookies, want 1", len(cookies))
	}

	// The next request carries exactly what was written, and must land
	// on the registered bundle rather than the default.
	got := resolver.Resolve(context.Background(), op.ResolveRequest{Cookie: cookies[0].Value})
	if got != "pt-br" {
		t.Fatalf("Resolve(cookie=%q) = %q, want pt-br", cookies[0].Value, got)
	}
	if msg, ok := resolver.Message(got, "consent.title", nil); !ok || msg != wantConsentTitle {
		t.Fatalf("Message(%q, consent.title) = (%q, %v), want (%q, true)", got, msg, ok, wantConsentTitle)
	}

	// Everything discovery advertises has to be selectable through the
	// parameter it describes, and pt-br has to be in that vocabulary.
	advertised := fetchUILocalesSupported(t, provider)
	if !slices.Contains(advertised, "pt-br") {
		t.Fatalf("ui_locales_supported = %v, want it to contain pt-br", advertised)
	}
	for _, locale := range advertised {
		resolved := resolver.Resolve(context.Background(), op.ResolveRequest{UILocales: []string{locale}})
		if !slices.Contains(resolver.Available(), resolved) {
			t.Errorf("advertised ui_locales_supported entry %q resolved to %q, which is not registered",
				locale, resolved)
		}
		if locale == "pt-br" && resolved != "pt-br" {
			t.Errorf("ui_locales=%q resolved to %q, want pt-br", locale, resolved)
		}
	}
}

// The spellings an RP, a browser or an embedder can legitimately send
// for one registered locale. BCP 47 lookup truncates and never
// extends, so a bare language does not reach a region-qualified
// bundle — "pt" falls through to the default.
func TestLocale_UILocalesSpellingsSelectTheSameBundle(t *testing.T) {
	t.Parallel()

	ptBR, err := op.LocaleBundleFromMap("pt-BR", map[string]string{"consent.title": "Autorizar"})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap(pt-BR): %v", err)
	}
	zhHant, err := op.LocaleBundleFromMap("zh-Hant", map[string]string{"consent.title": "授權"})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap(zh-Hant): %v", err)
	}
	provider, err := op.New(append(validBaseOpts(t), op.WithLocale(ptBR), op.WithLocale(zhHant))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	resolver := provider.LocaleResolver()

	cases := []struct {
		name string
		in   string
		want op.Locale
	}{
		{name: "canonical", in: "pt-br", want: "pt-br"},
		{name: "registration casing", in: "pt-BR", want: "pt-br"},
		{name: "shouting", in: "PT-BR", want: "pt-br"},
		{name: "underscore separator", in: "pt_BR", want: "pt-br"},
		{name: "private use suffix", in: "pt-BR-x-legal", want: "pt-br"},
		{name: "script subtag", in: "zh-Hant", want: "zh-hant"},
		{name: "region under a script", in: "zh-Hant-TW", want: "zh-hant"},
		{name: "seed locale region", in: "ja-JP", want: op.LocaleJapanese},
		{name: "bare language does not extend", in: "pt", want: op.LocaleEnglish},
		{name: "sibling script", in: "zh-Hans", want: op.LocaleEnglish},
		{name: "unknown tag", in: "xx-YY", want: op.LocaleEnglish},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := resolver.Resolve(context.Background(), op.ResolveRequest{UILocales: []string{tc.in}})
			if got != tc.want {
				t.Fatalf("Resolve(ui_locales=%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// An incomplete translation must degrade to another language, never to
// blank UI — including when the incomplete bundle is the configured
// default and so has nothing above it but English.
func TestWithDefaultLocale_PartialBundleFallsBackRatherThanBlanking(t *testing.T) {
	t.Parallel()

	const englishOnlyKey = "custom.untranslated_notice"

	enOverlay, err := op.LocaleBundleFromMap(op.LocaleEnglish, map[string]string{
		englishOnlyKey: "Your session stays signed in on this device.",
	})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap(en): %v", err)
	}
	french, err := op.LocaleBundleFromMap("fr", map[string]string{
		"consent.title": "Autoriser {client_name}",
	})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap(fr): %v", err)
	}
	provider, err := op.New(append(validBaseOpts(t),
		op.WithLocale(enOverlay),
		op.WithLocale(french),
		op.WithDefaultLocale("fr"),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	resolver := provider.LocaleResolver()

	if got := resolver.Default(); got != "fr" {
		t.Fatalf("Default() = %q, want fr", got)
	}
	if got, ok := resolver.Message("fr", "consent.title", nil); !ok || got != "Autoriser {client_name}" {
		t.Fatalf("Message(fr, consent.title) = (%q, %v), want the French entry", got, ok)
	}
	got, ok := resolver.Message("fr", englishOnlyKey, nil)
	if !ok || got == "" {
		t.Fatalf("Message(fr, %s) = (%q, %v); the default locale must fall back to English, not blank",
			englishOnlyKey, got, ok)
	}
	if got != "Your session stays signed in on this device." {
		t.Fatalf("Message(fr, %s) = %q, want the English entry", englishOnlyKey, got)
	}
}

// fetchUILocalesSupported reads the advertised locale vocabulary off
// the live discovery document, so the assertion covers the wire form
// an RP actually reads rather than the config it was derived from.
func fetchUILocalesSupported(t *testing.T, provider *op.Provider) []string {
	t.Helper()

	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200", resp.StatusCode)
	}
	var doc struct {
		UILocalesSupported []string `json:"ui_locales_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return doc.UILocalesSupported
}

// An explicit ui_locales_supported list is a promise the OP has to be
// able to keep: advertising a locale no bundle serves sends every RP
// that honours the advertisement to the default instead.
func TestWithDiscoveryMetadata_RejectsAnUnservedAdvertisedLocale(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithDiscoveryMetadata(op.DiscoveryMetadata{
			UILocalesSupported: []string{"en", "pt-BR"},
		}),
	)...)
	if err == nil {
		t.Fatalf("op.New advertised pt-BR without a bundle, want a configuration error")
	}
}

// SetLocaleCookie must never be reachable as a way to blank the cookie:
// an empty locale matches nothing, so it is rejected rather than
// silently clearing the user's choice. Clearing has its own method.
func TestSetLocaleCookie_RejectsTheEmptyLocale(t *testing.T) {
	t.Parallel()

	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	rec := httptest.NewRecorder()
	if err := provider.SetLocaleCookie(rec, ""); !errors.Is(err, op.ErrLocaleNotRegistered) {
		t.Fatalf("SetLocaleCookie(\"\") = %v, want ErrLocaleNotRegistered", err)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("empty locale wrote %d cookies", len(cookies))
	}
}

package op

// The tests in this file live in package op (not op_test) so they can
// reach [buildLocaleResolver] and inspect the merged locale catalogue
// directly. Pinning the merge semantics through the resolver gives a
// faster, narrower fixture than rendering an HTML interaction page.

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/i18n"
)

// TestBuildLocaleResolver_OverlayMergesIntoSeed confirms the H4
// ergonomic promise: an embedder who registers a partial bundle for a
// seeded locale only has to supply the keys they want to change. The
// keys the embedder omits inherit the seed verbatim, and the keys the
// embedder supplies win for that locale.
func TestBuildLocaleResolver_OverlayMergesIntoSeed(t *testing.T) {
	t.Parallel()

	overlay, err := i18n.NewBundle(i18n.English, map[string]string{
		"login.title": "Sign in to Acme",
	})
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}

	c := &config{
		defaultLocale: "en",
		localeBundles: []LocaleBundle{{internal: overlay}},
	}
	resolver, err := buildLocaleResolver(c)
	if err != nil {
		t.Fatalf("buildLocaleResolver: %v", err)
	}

	en, ok := resolver.Bundle(i18n.English)
	if !ok {
		t.Fatalf("resolver did not register the en bundle")
	}
	if got, _ := en.Get("login.title", nil); got != "Sign in to Acme" {
		t.Errorf("overlay key login.title = %q, want %q", got, "Sign in to Acme")
	}
	// Seed-only keys MUST survive the overlay.
	for _, key := range []string{
		"consent.title",
		"consent.button.allow",
		"login.password.label",
		"login.button.submit",
		"error.invalid_request.title",
	} {
		if _, ok := en.Get(key, map[string]string{"client_name": "Acme"}); !ok {
			t.Errorf("seed-only key %q dropped after merge", key)
		}
	}
}

// TestBuildLocaleResolver_LayeredOverlaysComposeLastWins verifies that
// repeated [WithLocale] calls for the same locale compose by repeated
// merge: the later overlay wins per key while earlier overlays remain
// authoritative for keys the later call did not redefine. Embedders
// who layer a regional overlay on top of a brand overlay rely on this
// ordering.
func TestBuildLocaleResolver_LayeredOverlaysComposeLastWins(t *testing.T) {
	t.Parallel()

	first, err := i18n.NewBundle(i18n.English, map[string]string{
		"login.title":          "Sign in to Acme",
		"consent.button.allow": "Approve",
	})
	if err != nil {
		t.Fatalf("first NewBundle: %v", err)
	}
	second, err := i18n.NewBundle(i18n.English, map[string]string{
		"login.title": "Sign in to Acme (US)",
	})
	if err != nil {
		t.Fatalf("second NewBundle: %v", err)
	}

	c := &config{
		defaultLocale: "en",
		localeBundles: []LocaleBundle{
			{internal: first},
			{internal: second},
		},
	}
	resolver, err := buildLocaleResolver(c)
	if err != nil {
		t.Fatalf("buildLocaleResolver: %v", err)
	}

	en, ok := resolver.Bundle(i18n.English)
	if !ok {
		t.Fatalf("resolver did not register the en bundle")
	}
	if got, _ := en.Get("login.title", nil); got != "Sign in to Acme (US)" {
		t.Errorf("layered overlay last-wins violated; login.title = %q", got)
	}
	if got, _ := en.Get("consent.button.allow", nil); got != "Approve" {
		t.Errorf("first-overlay key consent.button.allow dropped; got %q", got)
	}
	// Seed-only keys still survive both overlays.
	if got, _ := en.Get("consent.title", map[string]string{"client_name": "Acme"}); got != "Authorize Acme" {
		t.Errorf("seed key consent.title dropped after layered overlays; got %q", got)
	}
}

// TestBuildLocaleResolver_NewLocaleRegisteredAsIs verifies that a
// locale the seed catalogue does not ship is registered verbatim — no
// merge happens because there is nothing to merge with. This pins the
// example/15-i18n-locale shape (French registered fresh) against
// future regressions.
func TestBuildLocaleResolver_NewLocaleRegisteredAsIs(t *testing.T) {
	t.Parallel()

	french, err := i18n.NewBundle("fr", map[string]string{
		"login.title": "Connexion",
	})
	if err != nil {
		t.Fatalf("NewBundle(fr): %v", err)
	}
	c := &config{
		defaultLocale: "fr",
		localeBundles: []LocaleBundle{{internal: french}},
	}
	resolver, err := buildLocaleResolver(c)
	if err != nil {
		t.Fatalf("buildLocaleResolver: %v", err)
	}

	fr, ok := resolver.Bundle("fr")
	if !ok {
		t.Fatalf("resolver did not register the fr bundle")
	}
	if got, _ := fr.Get("login.title", nil); got != "Connexion" {
		t.Errorf("fr login.title = %q, want %q", got, "Connexion")
	}
	// fr does NOT inherit seed en entries — that fall-through is the
	// resolver's job at request time, not buildLocaleResolver's.
	if _, ok := fr.Get("consent.title", nil); ok {
		t.Errorf("fr bundle accidentally inherited seed en consent.title")
	}
}

// fakePreferredLocaleStore returns a fixed locale or a fixed error,
// letting the resolver tests exercise the head of the §L.2 chain
// without standing up a real user store.
type fakePreferredLocaleStore struct {
	tag Locale
	err error
}

func (f fakePreferredLocaleStore) PreferredLocale(_ context.Context, _ string) (Locale, error) {
	return f.tag, f.err
}

// TestWithPreferredLocaleStore_RejectsNil pins that callers cannot
// silently disable the resolver chain by passing nil. Returning the
// next-layer fall-through on a misconfigured option would make the
// chain best-effort to a fault: a typo "WithPreferredLocaleStore(nil)"
// would skip the head of the chain without any signal to the embedder.
func TestWithPreferredLocaleStore_RejectsNil(t *testing.T) {
	t.Parallel()

	c := &config{}
	if err := WithPreferredLocaleStore(nil).apply(c); err == nil {
		t.Fatalf("WithPreferredLocaleStore(nil) returned nil, want error")
	}
}

// TestBuildLocaleResolver_PreferredStoreWiresChainHead verifies the
// store reaches the resolver and is consulted at the top of the
// §L.2 chain. The fake returns "ja" so only the preferred-store
// branch could explain the resolved tag — none of the other inputs
// hint at Japanese.
func TestBuildLocaleResolver_PreferredStoreWiresChainHead(t *testing.T) {
	t.Parallel()

	c := &config{
		defaultLocale:        LocaleEnglish,
		preferredLocaleStore: fakePreferredLocaleStore{tag: LocaleJapanese},
	}
	resolver, err := buildLocaleResolver(c)
	if err != nil {
		t.Fatalf("buildLocaleResolver: %v", err)
	}
	got := resolver.Resolve(context.Background(), i18n.Request{Subject: "user-1"})
	if got != i18n.Tag(LocaleJapanese) {
		t.Errorf("resolver picked %q, want %q (preferred store should win)", got, LocaleJapanese)
	}
}

// TestBuildLocaleResolver_PreferredStoreErrorTreatedAsNoPreference
// pins design 002 §L.2: the store is best-effort, so a backend
// failure must not fail the resolve — instead the chain falls
// through to the next layer. Without this, an outage on the
// preferred-store backend (Redis / LDAP) would block every login
// with a 500.
func TestBuildLocaleResolver_PreferredStoreErrorTreatedAsNoPreference(t *testing.T) {
	t.Parallel()

	c := &config{
		defaultLocale:        LocaleEnglish,
		preferredLocaleStore: fakePreferredLocaleStore{err: errors.New("backend down")},
	}
	resolver, err := buildLocaleResolver(c)
	if err != nil {
		t.Fatalf("buildLocaleResolver: %v", err)
	}
	got := resolver.Resolve(context.Background(), i18n.Request{
		Subject:   "user-1",
		UILocales: []string{"ja"},
	})
	if got != i18n.Tag(LocaleJapanese) {
		t.Errorf("resolver picked %q despite ui_locales=ja, want %q", got, LocaleJapanese)
	}
}

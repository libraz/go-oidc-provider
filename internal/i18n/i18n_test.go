package i18n_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/i18n"
)

func TestParseTag(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want i18n.Tag
	}{
		{"en", "en"},
		{"EN", "en"},
		{"ja-JP", "ja-jp"},
		{"ja_JP", "ja-jp"},
		{"  zh-Hant  ", "zh-hant"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := i18n.ParseTag(tc.in); got != tc.want {
			t.Fatalf("ParseTag(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseTagRejectsOverlong(t *testing.T) {
	t.Parallel()

	if got := i18n.ParseTag(strings.Repeat("a", i18n.MaxTagLength+1)); got != "" {
		t.Fatalf("ParseTag(overlong) = %q, want empty", got)
	}
}

func TestTagLanguage(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   i18n.Tag
		want i18n.Tag
	}{
		{"en", "en"},
		{"ja-jp", "ja"},
		{"zh-hant-tw", "zh"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := tc.in.Language(); got != tc.want {
			t.Fatalf("Language(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTagFallback(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   i18n.Tag
		want []i18n.Tag
	}{
		{"language only", "en", []i18n.Tag{"en"}},
		{"region", "pt-br", []i18n.Tag{"pt-br", "pt"}},
		{"script", "zh-hant", []i18n.Tag{"zh-hant", "zh"}},
		{"script and region", "zh-hant-tw", []i18n.Tag{"zh-hant-tw", "zh-hant", "zh"}},
		{"private use singleton", "pt-br-x-legal", []i18n.Tag{"pt-br-x-legal", "pt-br", "pt"}},
		{"leading singleton", "x-private", []i18n.Tag{"x-private"}},
		{"empty", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.in.Fallback()
			if !slices.Equal(got, tc.want) {
				t.Fatalf("Fallback(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// Every locale signal the resolver reads — a bundle tag, a cookie, an
// ui_locales entry, an Accept-Language entry, an embedder's stored
// preference — is canonicalised by the same function, so a bundle that
// can be registered is a bundle that can be selected regardless of how
// the requester spells the tag.
func TestResolver_MatchNormalisesAndFallsBack(t *testing.T) {
	t.Parallel()

	ptBR, err := i18n.NewBundle("pt-BR", nil)
	if err != nil {
		t.Fatalf("NewBundle(pt-BR): %v", err)
	}
	if got := ptBR.Tag(); got != "pt-br" {
		t.Fatalf("NewBundle(pt-BR).Tag() = %q, want the canonical %q", got, "pt-br")
	}
	zhHant, _ := i18n.NewBundle("zh-Hant", nil)
	en, _ := i18n.NewBundle(i18n.English, nil)
	r, err := i18n.NewResolver(i18n.English, en, ptBR, zhHant)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	cases := []struct {
		name  string
		in    i18n.Tag
		want  i18n.Tag
		match bool
	}{
		{name: "exact canonical", in: "pt-br", want: "pt-br", match: true},
		{name: "registration casing", in: "pt-BR", want: "pt-br", match: true},
		{name: "shouting", in: "PT-BR", want: "pt-br", match: true},
		{name: "underscore separator", in: "pt_BR", want: "pt-br", match: true},
		{name: "surrounding space", in: "  pt-br  ", want: "pt-br", match: true},
		{name: "script subtag", in: "zh-Hant", want: "zh-hant", match: true},
		{name: "region under a script", in: "zh-Hant-TW", want: "zh-hant", match: true},
		{name: "region truncates to language", in: "en-US", want: "en", match: true},
		// Lookup only truncates, so a bare language does not reach a
		// more specific registration: "pt" is not "pt-br".
		{name: "language does not extend to region", in: "pt", match: false},
		{name: "sibling region", in: "zh-Hans", match: false},
		{name: "unknown tag", in: "xx-YY", match: false},
		{name: "empty", in: "", match: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := r.Match(tc.in)
			if ok != tc.match {
				t.Fatalf("Match(%q) matched = %v, want %v (got %q)", tc.in, ok, tc.match, got)
			}
			if ok && got != tc.want {
				t.Fatalf("Match(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A locale reaches the resolver through four transports. All four are
// canonicalised, so an RP, a browser, a picker and an embedder's own
// store all select the same bundle from the same spelling.
func TestResolver_EverySignalIsCanonicalised(t *testing.T) {
	t.Parallel()

	newResolver := func(t *testing.T, prefs i18n.PreferredLocaleStore) *i18n.Resolver {
		t.Helper()

		ptBR, _ := i18n.NewBundle("pt-BR", nil)
		en, _ := i18n.NewBundle(i18n.English, nil)
		r, err := i18n.NewResolver(i18n.English, en, ptBR)
		if err != nil {
			t.Fatalf("NewResolver: %v", err)
		}
		if prefs != nil {
			r.WithPreferredLocaleStore(prefs)
		}
		return r
	}

	cases := []struct {
		name  string
		prefs i18n.PreferredLocaleStore
		in    i18n.Request
	}{
		{name: "ui_locales", in: i18n.Request{UILocales: []string{"PT-BR"}}},
		{name: "cookie", in: i18n.Request{Cookie: "pt_BR"}},
		{name: "accept-language", in: i18n.Request{AcceptLanguage: "pt-BR;q=0.9, de;q=0.1"}},
		{
			name:  "preferred locale store",
			prefs: stubPrefs{tag: "Pt-Br"},
			in:    i18n.Request{Subject: "sub-1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newResolver(t, tc.prefs)
			if got := r.Resolve(context.Background(), tc.in); got != "pt-br" {
				t.Fatalf("Resolve(%s) = %q, want pt-br", tc.name, got)
			}
		})
	}
}

func TestBundle_GetSubstitutes(t *testing.T) {
	t.Parallel()

	b, err := i18n.NewBundle(i18n.English, map[string]string{
		"consent.title":  "Authorize {client_name}",
		"login.title":    "Sign in",
		"missing.var":    "Hello {name}, you have {count} messages",
		"unbalanced":     "stray {",
		"empty_braces":   "x{}y",
		"raw_left_brace": "{not-a-key} is literal",
	})
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}

	if got, _ := b.Get("consent.title", map[string]string{"client_name": "Acme"}); got != "Authorize Acme" {
		t.Fatalf("substituted: got %q", got)
	}
	if got, _ := b.Get("login.title", nil); got != "Sign in" {
		t.Fatalf("static: got %q", got)
	}
	if got, _ := b.Get("missing.var", map[string]string{"name": "Sam"}); got != "Hello Sam, you have {count} messages" {
		t.Fatalf("missing var should pass through: got %q", got)
	}
	if got, _ := b.Get("unbalanced", nil); got != "stray {" {
		t.Fatalf("unbalanced: got %q", got)
	}
	if _, ok := b.Get("nonexistent", nil); ok {
		t.Fatalf("expected missing key to return ok=false")
	}
}

func TestLoadBundle_RejectsNonString(t *testing.T) {
	t.Parallel()

	_, err := i18n.LoadBundle(i18n.English, []byte(`{"x": 42}`))
	if err == nil {
		t.Fatalf("expected error on non-string leaf")
	}
}

func TestBundle_MergeOverlay(t *testing.T) {
	t.Parallel()

	base, err := i18n.NewBundle(i18n.English, map[string]string{
		"consent.title":     "Authorize {client_name}",
		"consent.button.ok": "Allow",
		"login.title":       "Sign in",
		"login.password":    "Password",
		"error.invalid_req": "Invalid request",
	})
	if err != nil {
		t.Fatalf("base NewBundle: %v", err)
	}
	overlay, err := i18n.NewBundle(i18n.English, map[string]string{
		"consent.title":  "Authorize {client_name} on Acme",
		"login.password": "Passphrase",
	})
	if err != nil {
		t.Fatalf("overlay NewBundle: %v", err)
	}

	merged, err := base.Merge(overlay)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	if got, _ := merged.Get("consent.title", map[string]string{"client_name": "Acme"}); got != "Authorize Acme on Acme" {
		t.Errorf("overlay should win for consent.title; got %q", got)
	}
	if got, _ := merged.Get("login.password", nil); got != "Passphrase" {
		t.Errorf("overlay should win for login.password; got %q", got)
	}
	if got, _ := merged.Get("consent.button.ok", nil); got != "Allow" {
		t.Errorf("base-only key consent.button.ok dropped; got %q", got)
	}
	if got, _ := merged.Get("login.title", nil); got != "Sign in" {
		t.Errorf("base-only key login.title dropped; got %q", got)
	}
	if got, _ := merged.Get("error.invalid_req", nil); got != "Invalid request" {
		t.Errorf("base-only key error.invalid_req dropped; got %q", got)
	}

	// Mutating the returned bundle's surface keys via a fresh overlay
	// must not leak back into the base — the base must remain untouched.
	if got, _ := base.Get("consent.title", map[string]string{"client_name": "Acme"}); got != "Authorize Acme" {
		t.Errorf("base bundle was mutated by Merge; got %q", got)
	}
	if got, _ := base.Get("login.password", nil); got != "Password" {
		t.Errorf("base bundle was mutated by Merge; got %q", got)
	}
}

func TestBundle_MergeNilOverlay(t *testing.T) {
	t.Parallel()

	base, err := i18n.NewBundle(i18n.English, map[string]string{"login.title": "Sign in"})
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	merged, err := base.Merge(nil)
	if err != nil {
		t.Fatalf("Merge(nil): %v", err)
	}
	if got, _ := merged.Get("login.title", nil); got != "Sign in" {
		t.Errorf("nil overlay should preserve base entries; got %q", got)
	}
	if merged == base {
		t.Errorf("Merge(nil) must return a fresh bundle, not the receiver")
	}
}

func TestBundle_MergeRejectsTagMismatch(t *testing.T) {
	t.Parallel()

	en, err := i18n.NewBundle(i18n.English, map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("NewBundle(en): %v", err)
	}
	ja, err := i18n.NewBundle(i18n.Japanese, map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("NewBundle(ja): %v", err)
	}
	if _, err := en.Merge(ja); err == nil {
		t.Fatal("Merge across mismatched tags must error")
	}
}

func TestDefaultBundles_ContainsEnAndJa(t *testing.T) {
	t.Parallel()

	bundles, err := i18n.DefaultBundles()
	if err != nil {
		t.Fatalf("DefaultBundles: %v", err)
	}
	tags := make(map[i18n.Tag]bool, len(bundles))
	for _, b := range bundles {
		tags[b.Tag()] = true
		if !b.Has("consent.title") {
			t.Fatalf("bundle %q missing consent.title", b.Tag())
		}
	}
	if !tags[i18n.English] || !tags[i18n.Japanese] {
		t.Fatalf("expected en+ja in DefaultBundles, got %v", tags)
	}
}

func TestResolver_PriorityChain(t *testing.T) {
	t.Parallel()

	bundles, err := i18n.DefaultBundles()
	if err != nil {
		t.Fatalf("DefaultBundles: %v", err)
	}
	r, err := i18n.NewResolver(i18n.English, bundles...)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	cases := []struct {
		name string
		in   i18n.Request
		want i18n.Tag
	}{
		{
			name: "default_when_no_signal",
			in:   i18n.Request{},
			want: i18n.English,
		},
		{
			name: "ui_locales_wins_over_accept",
			in: i18n.Request{
				UILocales:      []string{"ja"},
				AcceptLanguage: "en;q=1.0",
			},
			want: i18n.Japanese,
		},
		{
			name: "cookie_used_when_no_ui_locales",
			in: i18n.Request{
				Cookie: "ja-JP",
			},
			want: i18n.Japanese,
		},
		{
			name: "accept_language_q_descending",
			in: i18n.Request{
				AcceptLanguage: "en;q=0.5, ja;q=0.9, fr;q=0.1",
			},
			want: i18n.Japanese,
		},
		{
			name: "language_prefix_match",
			in: i18n.Request{
				UILocales: []string{"ja-JP"},
			},
			want: i18n.Japanese,
		},
		{
			name: "fallback_when_unrecognised",
			in: i18n.Request{
				UILocales: []string{"zh-Hant", "ko"},
			},
			want: i18n.English,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := r.Resolve(context.Background(), tc.in)
			if got != tc.want {
				t.Fatalf("Resolve = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolver_PreferredLocaleStoreWins(t *testing.T) {
	t.Parallel()

	bundles, _ := i18n.DefaultBundles()
	r, _ := i18n.NewResolver(i18n.English, bundles...)
	r.WithPreferredLocaleStore(stubPrefs{tag: "ja"})

	got := r.Resolve(context.Background(), i18n.Request{
		Subject:        "user-1",
		UILocales:      []string{"en"},
		AcceptLanguage: "en",
	})
	if got != i18n.Japanese {
		t.Fatalf("PreferredLocale should outrank ui_locales, got %q", got)
	}
}

func TestResolver_PreferredLocaleErrorIsIgnored(t *testing.T) {
	t.Parallel()

	bundles, _ := i18n.DefaultBundles()
	r, _ := i18n.NewResolver(i18n.English, bundles...)
	r.WithPreferredLocaleStore(stubPrefs{err: errors.New("backend down")})

	got := r.Resolve(context.Background(), i18n.Request{
		Subject:   "user-1",
		UILocales: []string{"ja"},
	})
	if got != i18n.Japanese {
		t.Fatalf("error should fall through to ui_locales, got %q", got)
	}
}

func TestResolver_RejectsMalformedLocaleCookie(t *testing.T) {
	t.Parallel()

	en, _ := i18n.NewBundle(i18n.English, nil)
	poison, _ := i18n.NewBundle(i18n.Tag("ja<script>"), nil)
	r, err := i18n.NewResolver(i18n.English, en, poison)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	got := r.Resolve(context.Background(), i18n.Request{
		Cookie:         "ja<script>",
		AcceptLanguage: "en",
	})
	if got != i18n.English {
		t.Fatalf("Resolve=%q want en; malformed cookie must be ignored", got)
	}
}

func TestResolver_AcceptLanguageCapsWork(t *testing.T) {
	t.Parallel()

	en, _ := i18n.NewBundle(i18n.English, nil)
	ja, _ := i18n.NewBundle(i18n.Japanese, nil)
	r, err := i18n.NewResolver(i18n.English, en, ja)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	parts := make([]string, 0, 25)
	for i := range 20 {
		parts = append(parts, fmt.Sprintf("zz-%02d;q=1", i))
	}
	parts = append(parts, "ja;q=1")

	got := r.Resolve(context.Background(), i18n.Request{
		AcceptLanguage: strings.Join(parts, ","),
	})
	if got != i18n.English {
		t.Fatalf("Resolve with matching tag past cap = %q, want default en", got)
	}

	got = r.Resolve(context.Background(), i18n.Request{
		AcceptLanguage: strings.Repeat("a", i18n.MaxTagLength+1) + ";q=1,ja;q=0.9",
	})
	if got != i18n.Japanese {
		t.Fatalf("Resolve should skip overlong tag and use ja, got %q", got)
	}
}

func TestResolver_RejectsOverlongLocaleCookie(t *testing.T) {
	t.Parallel()

	longTag := i18n.Tag("en-" + strings.Repeat("a", 80))

	// A tag past the cap cannot be registered in the first place: the
	// cookie / Accept-Language side would canonicalise it to the empty
	// Tag, so a bundle under it could never be selected.
	if _, err := i18n.NewBundle(longTag, nil); err == nil {
		t.Fatalf("NewBundle(overlong tag) = nil error, want rejection")
	}

	en, _ := i18n.NewBundle(i18n.English, nil)
	r, err := i18n.NewResolver(i18n.English, en)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	got := r.Resolve(context.Background(), i18n.Request{Cookie: longTag.String()})
	if got != i18n.English {
		t.Fatalf("Resolve=%q want en; overlong cookie must be ignored", got)
	}
}

func TestResolver_BundleFallbackReportsMatch(t *testing.T) {
	t.Parallel()

	bundles, _ := i18n.DefaultBundles()
	r, _ := i18n.NewResolver(i18n.English, bundles...)

	if _, ok := r.Bundle(i18n.Japanese); !ok {
		t.Fatalf("ja should be a direct match")
	}
	if _, ok := r.Bundle("zz"); ok {
		t.Fatalf("unknown tag should be a fall-back, got direct match")
	}
}

// A partial bundle is the normal case — an embedder translates the
// handful of strings it cares about — so every tier of the lookup
// chain has to keep going when a key is missing, including the last
// two. A partial bundle chosen as the *default* is the case that has
// no tier above it except English; without that terminal tier the OP
// renders empty strings for every key the default does not translate.
func TestResolver_MessageChainRunsToEnglish(t *testing.T) {
	t.Parallel()

	en, _ := i18n.NewBundle(i18n.English, map[string]string{
		"only.english":     "Sign in",
		"shared.key":       "English",
		"login.identifier": "Email",
	})
	pt, _ := i18n.NewBundle("pt", map[string]string{
		"shared.key":       "Português",
		"login.identifier": "E-mail",
	})
	ptBR, _ := i18n.NewBundle("pt-BR", map[string]string{
		"shared.key": "Português do Brasil",
	})
	// pt-br is the default and translates exactly one key.
	r, err := i18n.NewResolver("pt-BR", en, pt, ptBR)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	cases := []struct {
		name string
		tag  i18n.Tag
		key  string
		want string
	}{
		{name: "own bundle wins", tag: "pt-BR", key: "shared.key", want: "Português do Brasil"},
		{name: "language subtag fills the gap", tag: "pt-BR", key: "login.identifier", want: "E-mail"},
		{name: "english terminates the chain", tag: "pt-BR", key: "only.english", want: "Sign in"},
		{name: "the default itself falls back", tag: "", key: "only.english", want: "Sign in"},
		{name: "unmatched tag walks the default chain", tag: "xx", key: "login.identifier", want: "E-mail"},
		{name: "explicit english is not overridden", tag: "en", key: "shared.key", want: "English"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := r.Message(tc.tag, tc.key, nil)
			if !ok || got != tc.want {
				t.Fatalf("Message(%q, %q) = (%q, %v), want (%q, true)", tc.tag, tc.key, got, ok, tc.want)
			}
		})
	}

	if got, ok := r.Message("pt-BR", "nowhere", nil); ok || got != "" {
		t.Fatalf("Message(pt-BR, nowhere) = (%q, %v), want (empty, false)", got, ok)
	}
}

func TestResolver_MessageFallsBackToDefaultAndKeepsPlaceholderRules(t *testing.T) {
	t.Parallel()

	en, err := i18n.NewBundle(i18n.English, map[string]string{
		"greeting": "Hello {name}; unresolved={missing}",
	})
	if err != nil {
		t.Fatalf("NewBundle(en): %v", err)
	}
	fr, err := i18n.NewBundle("fr", map[string]string{
		"local": "Bonjour {name}",
	})
	if err != nil {
		t.Fatalf("NewBundle(fr): %v", err)
	}
	r, err := i18n.NewResolver(i18n.English, en, fr)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	if got, ok := r.Message("fr", "local", map[string]string{"name": "Alice"}); !ok || got != "Bonjour Alice" {
		t.Errorf("Message(fr, local) = (%q, %v), want (%q, true)", got, ok, "Bonjour Alice")
	}
	if got, ok := r.Message("fr", "greeting", map[string]string{"name": "{missing}"}); !ok ||
		got != "Hello {missing}; unresolved={missing}" {
		t.Errorf("Message(fr, greeting) = (%q, %v), want default message with single-pass substitution", got, ok)
	}
	if got, ok := r.Message("fr", "unknown", nil); ok || got != "" {
		t.Errorf("Message(fr, unknown) = (%q, %v), want (empty, false)", got, ok)
	}
}

func TestResolver_DefaultAndAvailableAreStable(t *testing.T) {
	t.Parallel()

	en, _ := i18n.NewBundle(i18n.English, nil)
	ja, _ := i18n.NewBundle(i18n.Japanese, nil)
	r, err := i18n.NewResolver(i18n.Japanese, en, ja)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	if got := r.Default(); got != i18n.Japanese {
		t.Fatalf("Default() = %q, want ja", got)
	}
	got := r.Available()
	want := []i18n.Tag{i18n.English, i18n.Japanese}
	if len(got) != len(want) {
		t.Fatalf("Available() len = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Available()[%d] = %q, want %q; all=%v", i, got[i], want[i], got)
		}
	}

	got[0] = "mutated"
	again := r.Available()
	if again[0] != i18n.English {
		t.Fatalf("Available returned mutable internal slice; got %v", again)
	}
}

// An unset default is the caller declining to choose, so the resolver
// picks one. A *set* default naming a locale no bundle serves is a
// configuration error: silently redirecting it would make Default()
// report a locale the caller never asked for, and every lookup chain
// terminate somewhere unannounced.
func TestNewResolver_DefaultFallbacks(t *testing.T) {
	t.Parallel()

	en, _ := i18n.NewBundle(i18n.English, nil)
	ja, _ := i18n.NewBundle(i18n.Japanese, nil)
	if _, err := i18n.NewResolver("zz", ja, en); err == nil {
		t.Fatalf("NewResolver with an unregistered default = nil error, want rejection")
	}

	fr, _ := i18n.NewBundle("fr", nil)
	r, err := i18n.NewResolver("", fr, ja)
	if err != nil {
		t.Fatalf("NewResolver with first-bundle fallback: %v", err)
	}
	if got := r.Default(); got != "fr" {
		t.Fatalf("Default() = %q, want first registered bundle", got)
	}

	r, err = i18n.NewResolver("", ja, en)
	if err != nil {
		t.Fatalf("NewResolver with English fallback: %v", err)
	}
	if got := r.Default(); got != i18n.English {
		t.Fatalf("Default() = %q, want English fallback", got)
	}
}

func TestNewResolver_RequiresAtLeastOneBundle(t *testing.T) {
	t.Parallel()

	if _, err := i18n.NewResolver(i18n.English); err == nil {
		t.Fatalf("expected error on empty bundle list")
	}
}

func TestNewResolver_RejectsNilBundle(t *testing.T) {
	t.Parallel()

	if _, err := i18n.NewResolver(i18n.English, nil); err == nil {
		t.Fatalf("expected error on nil bundle")
	}
}

func TestNewResolver_RejectsDuplicateTag(t *testing.T) {
	t.Parallel()

	a, _ := i18n.NewBundle(i18n.English, nil)
	b, _ := i18n.NewBundle(i18n.English, nil)
	if _, err := i18n.NewResolver(i18n.English, a, b); err == nil {
		t.Fatalf("expected error on duplicate tag")
	}
}

type stubPrefs struct {
	tag i18n.Tag
	err error
}

func (s stubPrefs) PreferredLocale(_ context.Context, _ string) (i18n.Tag, error) {
	return s.tag, s.err
}

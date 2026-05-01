package i18n_test

import (
	"context"
	"errors"
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

func TestNewResolver_RequiresAtLeastOneBundle(t *testing.T) {
	t.Parallel()

	if _, err := i18n.NewResolver(i18n.English); err == nil {
		t.Fatalf("expected error on empty bundle list")
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

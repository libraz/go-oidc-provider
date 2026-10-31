package i18n_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/i18n"
)

func newMessageResolver(t *testing.T) *i18n.Resolver {
	t.Helper()
	en, _ := i18n.NewBundle(i18n.English, map[string]string{"a": "en-a", "b": "en-b"})
	pt, _ := i18n.NewBundle("pt", map[string]string{"a": "pt-a", "c": "pt-c"})
	ptBR, _ := i18n.NewBundle("pt-BR", map[string]string{"a": "ptbr-a"})
	r, err := i18n.NewResolver("pt", en, pt, ptBR)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

func TestResolver_MessageFollowsFallbackChain(t *testing.T) {
	t.Parallel()
	r := newMessageResolver(t)
	cases := []struct {
		tag  i18n.Tag
		key  string
		want string
		ok   bool
	}{
		{"pt-br", "a", "ptbr-a", true},
		{"pt-br", "c", "pt-c", true},
		{"pt-br", "b", "en-b", true},
		{"pt", "a", "pt-a", true},
		{i18n.English, "c", "pt-c", true}, // default tier serves what English lacks
		{"pt-BR", "a", "ptbr-a", true},    // unregistered spelling builds its chain per call
		{"fr", "a", "pt-a", true},
		{"pt-br", "missing", "", false},
	}
	for _, tc := range cases {
		got, ok := r.Message(tc.tag, tc.key, nil)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Message(%q, %q) = (%q, %v), want (%q, %v)", tc.tag, tc.key, got, ok, tc.want, tc.ok)
		}
	}
}

func TestResolver_MessageRegisteredTagDoesNotAllocate(t *testing.T) {
	r := newMessageResolver(t)
	if n := testing.AllocsPerRun(100, func() { _, _ = r.Message("pt-br", "b", nil) }); n != 0 {
		t.Errorf("Message allocs = %v, want 0", n)
	}
}

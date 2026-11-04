package op_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

var routeWildcard = regexp.MustCompile(`\{[^}]*\}`)

// concreteRoutePath turns a ServeMux pattern into a request path by
// substituting each wildcard with a literal segment.
func concreteRoutePath(pattern string) string {
	return routeWildcard.ReplaceAllString(pattern, "probe")
}

func TestProviderRoutes_MatchesRouter(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		spa    bool
		prefix string
		want   []string
	}{
		{name: "default", want: []string{"/oidc/token", "/oidc/interaction/{uid}", "/oidc/grant_management/{grant_id}"}},
		{name: "spa", spa: true, want: []string{"/oidc/token", "/login/state/{uid}", "/login/{uid}", "/login/assets/{path...}"}},
		{name: "prefix", prefix: "/op", want: []string{"/op/token", "/op/interaction/{uid}", "/op/grant_management/{grant_id}"}},
		{name: "spa_prefix", spa: true, prefix: "/op", want: []string{"/op/token", "/login/state/{uid}"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := append(validBaseOptsWithInmem(t),
				op.WithGrantManagement(op.GrantManagement{Actions: []op.GrantManagementAction{op.GrantActionQuery, op.GrantActionRevoke}}),
			)
			if tc.prefix != "" {
				opts = append(opts, op.WithMountPrefix(tc.prefix))
			}
			if tc.spa {
				opts = append(opts, op.WithUI(op.SPAUI{LoginMount: "/login", StaticDir: t.TempDir()}))
			}
			provider, err := op.New(opts...)
			if err != nil {
				t.Fatalf("op.New: %v", err)
			}

			routes := provider.Routes()
			if len(routes) == 0 {
				t.Fatal("Routes() is empty")
			}
			seen := make(map[string]bool, len(routes))
			for _, pat := range routes {
				if seen[pat] {
					t.Errorf("duplicate pattern %q", pat)
				}
				seen[pat] = true
			}
			for _, want := range tc.want {
				if !slices.Contains(routes, want) {
					t.Errorf("Routes() = %v, missing %q", routes, want)
				}
			}

			// Every listed pattern must be one the provider's router matches,
			// and installing each on an embedder's mux must not panic.
			outer := http.NewServeMux()
			for _, pat := range routes {
				outer.Handle(pat, provider)
				method, path, _ := strings.Cut(pat, " ")
				if path == "" {
					method, path = http.MethodGet, pat
				}
				req := httptest.NewRequestWithContext(context.Background(), method, concreteRoutePath(path), http.NoBody)
				if got := op.RoutePatternForTest(provider, req); got != pat {
					t.Errorf("pattern %q: router matched %q for %s %s", pat, got, method, req.URL.Path)
				}
			}

			// The returned slice is a copy.
			routes[0] = "/mutated"
			if got := provider.Routes()[0]; got == "/mutated" {
				t.Error("Routes() exposes internal storage")
			}
		})
	}
}

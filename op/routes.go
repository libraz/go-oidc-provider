package op

import (
	"net/http"
	"slices"
)

// routeMux wraps [http.ServeMux] so every registration is recorded; it is
// the only path to the underlying mux's Handle.
type routeMux struct {
	mux      *http.ServeMux
	patterns []string
}

func newRouteMux() *routeMux {
	return &routeMux{mux: http.NewServeMux()}
}

// Handle registers h on the mux and records pattern in registration order.
func (r *routeMux) Handle(pattern string, h http.Handler) {
	r.mux.Handle(pattern, h)
	r.patterns = append(r.patterns, pattern)
}

// Routes returns the [http.ServeMux] patterns the Provider registered, in
// registration order. The set depends on the configuration: optional
// endpoints, [WithUI] with [SPAUI], [WithMountPrefix] and [WithGrantManagement] add,
// move or drop entries. The returned slice is a copy.
//
// Mount the Provider on a router that dispatches by path, instead of
// routing "/" to it, by registering each pattern:
//
//	for _, pat := range provider.Routes() {
//		mux.Handle(pat, provider)
//	}
//
// Patterns use net/http syntax. For another router, translate "{name}"
// (one path segment, for example "/login/state/{uid}") to that router's
// single-segment parameter form, and "{path...}" (the rest of the path,
// for example "/login/assets/{path...}") to its catch-all form. Methods
// are checked by the handlers, so a pattern carries no method.
//
// Stable since v1.5.
func (p *Provider) Routes() []string {
	return slices.Clone(p.routes)
}

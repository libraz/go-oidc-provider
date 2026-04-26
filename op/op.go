package op

import (
	"net/http"
)

// Provider is the assembled OpenID Connect Provider. It implements
// [http.Handler] and is the result of a successful [New] call.
//
// A Provider is safe for concurrent use by multiple goroutines once
// constructed. It must not be mutated after construction; configuration is
// fixed via [Option] values passed to [New].
type Provider struct {
	cfg *config
}

// ServeHTTP routes incoming requests to the OIDC endpoints registered by the
// enabled grants and features. The mount path is determined by where the
// caller installs the handler in its own router.
func (p *Provider) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	// Endpoints are wired in subsequent phases. Until the router is assembled,
	// every request is rejected so an accidentally exposed Provider cannot be
	// mistaken for a working OP.
	_ = p
	http.Error(w, "go-oidc-provider: handler not yet assembled", http.StatusServiceUnavailable)
}

// New constructs a [Provider] from the supplied options. It validates that
// every required option is present and that the combination of enabled
// grants, features, and profiles is internally consistent.
//
// Stable since v0.1. New returns a non-nil error if construction fails; the
// returned Provider is nil in that case. Callers must treat construction
// failure as fatal during program start-up.
func New(opts ...Option) (*Provider, error) {
	cfg, err := newConfig(opts)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Provider{cfg: cfg}, nil
}

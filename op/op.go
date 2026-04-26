package op

import (
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/jwks"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/internal/userinfo"
	"github.com/libraz/go-oidc-provider/op/feature"
)

// defaultUserInfoLeeway is the symmetric tolerance the /userinfo
// handler applies to the access-token "exp" / "iat" comparisons. The
// value is well below the RFC 7519 §4.1.4 recommended ceiling so a
// slow / clock-skewed RP retries quickly without amplifying replay
// windows for stolen tokens.
const defaultUserInfoLeeway = 30 * time.Second

// Provider is the assembled OpenID Connect Provider. It implements
// [http.Handler] and is the result of a successful [New] call.
//
// A Provider is safe for concurrent use by multiple goroutines once
// constructed. It must not be mutated after construction; configuration is
// fixed via [Option] values passed to [New].
type Provider struct {
	cfg  *config
	keys *keys.Set
	mux  *http.ServeMux
}

// ServeHTTP routes incoming requests to the OIDC endpoints registered by the
// enabled grants and features. The mount path is determined by where the
// caller installs the handler in its own router.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mux.ServeHTTP(w, r)
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
	keySet, err := keys.NewSet(toKeyEntries(cfg.keyset))
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "keyset rejected by internal validator",
			Cause:       err,
		}
	}
	mux, err := buildRouter(cfg, keySet)
	if err != nil {
		return nil, err
	}
	return &Provider{cfg: cfg, keys: keySet, mux: mux}, nil
}

// toKeyEntries converts the public [Keyset] to the internal slice the
// internal/keys package expects. The two shapes are identical apart from
// the package boundary; the function exists to honour the rule that
// internal/* must not import op/.
func toKeyEntries(ks Keyset) []keys.Entry {
	out := make([]keys.Entry, len(ks))
	for i, k := range ks {
		out[i] = keys.Entry{KeyID: k.KeyID, Signer: k.Signer}
	}
	return out
}

// buildRouter assembles the [http.ServeMux] that backs [Provider.ServeHTTP].
// In Phase 1 it registers the discovery and JWKS endpoints; subsequent
// phases extend it with the authorization, token, and UserInfo handlers.
func buildRouter(cfg *config, keySet *keys.Set) (*http.ServeMux, error) {
	mux := http.NewServeMux()
	doc := discovery.Build(buildDiscoveryInput(cfg))
	discHandler, err := discovery.Handler(doc)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "discovery document failed to marshal",
			Cause:       err,
		}
	}
	mux.Handle(cfg.endpoints.Discovery, discHandler)
	mux.Handle(joinPath(cfg.mountPrefix, cfg.endpoints.JWKS), jwks.Handler(keySet))
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.UserInfo),
		userinfo.Handler(userinfo.HandlerDeps{
			Keys:      keySet,
			Issuer:    cfg.issuer,
			UserStore: cfg.store.Users(),
			Clock:     cfg.clock,
			Leeway:    defaultUserInfoLeeway,
		}),
	)
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.Token),
		tokenendpoint.Handler(tokenendpoint.Deps{
			Issuer:        cfg.issuer,
			Clients:       cfg.store.Clients(),
			Codes:         cfg.store.AuthorizationCodes(),
			RefreshTokens: cfg.store.RefreshTokens(),
			Grants:        cfg.store.Grants(),
			Keys:          keySet,
			Clock:         cfg.clock,
		}),
	)
	return mux, nil
}

// buildDiscoveryInput converts the public [config] to the internal
// [discovery.Input] the discovery builder consumes.
func buildDiscoveryInput(cfg *config) discovery.Input {
	grantStrings := make([]string, 0, len(cfg.grants))
	for _, g := range cfg.grants {
		grantStrings = append(grantStrings, g.String())
	}
	return discovery.Input{
		Issuer:      cfg.issuer,
		MountPrefix: cfg.mountPrefix,
		Endpoints: discovery.EndpointPaths{
			JWKS:        cfg.endpoints.JWKS,
			Authorize:   cfg.endpoints.Authorize,
			Token:       cfg.endpoints.Token,
			UserInfo:    cfg.endpoints.UserInfo,
			EndSession:  cfg.endpoints.EndSession,
			Introspect:  cfg.endpoints.Introspect,
			Revoke:      cfg.endpoints.Revoke,
			PAR:         cfg.endpoints.PAR,
			Interaction: cfg.endpoints.Interaction,
			Session:     cfg.endpoints.Session,
		},
		Features:        buildFeatures(cfg.features),
		GrantsSupported: grantStrings,
	}
}

// buildFeatures translates the configured feature flags into the
// [discovery.Features] booleans the discovery builder consumes.
func buildFeatures(flags []feature.Flag) discovery.Features {
	var out discovery.Features
	for _, f := range flags {
		switch f {
		case feature.PAR:
			out.PAR = true
		case feature.JAR:
			out.JAR = true
		case feature.JARM:
			out.JARM = true
		case feature.DPoP:
			out.DPoP = true
		case feature.MTLS:
			out.MTLS = true
		case feature.Introspect:
			out.Introspect = true
		case feature.Revoke:
			out.Revoke = true
		case feature.PKCE:
			// PKCE is always enabled in v1.0; the flag exists so the
			// caller can advertise it explicitly in discovery, which
			// is already the default. Nothing to do here.
		}
	}
	return out
}

// joinPath concatenates mountPrefix and endpoint into a full path, handling
// the slash-collapsing edge cases that http.ServeMux is strict about.
func joinPath(mountPrefix, endpoint string) string {
	if mountPrefix == "/" {
		return endpoint
	}
	return mountPrefix + endpoint
}

package op

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/jwks"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/parendpoint"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/internal/userinfo"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// defaultUserInfoLeeway is the symmetric tolerance the /userinfo
// handler applies to the access-token "exp" / "iat" comparisons. The
// value is well below the RFC 7519 §4.1.4 recommended ceiling so a
// slow / clock-skewed RP retries quickly without amplifying replay
// windows for stolen tokens.
const defaultUserInfoLeeway = 30 * time.Second

// csrfDerivationLabel is the HMAC label used to derive the CSRF signing
// key from the active cookie key. Including a domain-separation label
// prevents a key reuse attack across cookie / CSRF surfaces if either
// derivation function is ever changed independently.
const csrfDerivationLabel = "oidc-csrf-v1"

// Provider is the assembled OpenID Connect Provider. It implements
// [http.Handler] and is the result of a successful [New] call.
//
// A Provider is safe for concurrent use by multiple goroutines once
// constructed. It must not be mutated after construction; configuration is
// fixed via [Option] values passed to [New].
type Provider struct {
	cfg    *config
	keys   *keys.Set
	scopes *scoperegistry.Registry
	mux    *http.ServeMux
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
	scopes := scoperegistry.New(toScopeEntries(cfg.scopes))
	mux, err := buildRouter(cfg, keySet, scopes)
	if err != nil {
		return nil, err
	}
	return &Provider{cfg: cfg, keys: keySet, scopes: scopes, mux: mux}, nil
}

// toScopeEntries projects the public [Scope] values onto the internal
// [scoperegistry.Entry] shape. Only the protocol-relevant subset
// crosses the boundary; UI metadata (Title, Description, Icon, Claims,
// I18n) stays in op.config so internal handlers do not grow a
// dependency on UI fields.
func toScopeEntries(scopes []Scope) []scoperegistry.Entry {
	out := make([]scoperegistry.Entry, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, scoperegistry.Entry{
			Name:           s.Name,
			Public:         s.Public,
			Required:       s.Required,
			AllowedClients: append([]string(nil), s.AllowedClients...),
		})
	}
	return out
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
func buildRouter(cfg *config, keySet *keys.Set, scopes *scoperegistry.Registry) (*http.ServeMux, error) {
	mux := http.NewServeMux()
	doc := discovery.Build(buildDiscoveryInput(cfg, scopes))
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
			Scopes:        scopes,
		}),
	)
	if err := mountAuthorizeHandlers(mux, cfg, scopes); err != nil {
		return nil, err
	}
	mountPAREndpoint(mux, cfg, scopes)
	return mux, nil
}

// mountPAREndpoint registers the /par handler when the [feature.PAR] flag
// is enabled. Without the flag the route is absent — discovery already
// gates the advertisement on the same flag, so the OP cannot tell clients
// the endpoint exists while quietly serving 404.
func mountPAREndpoint(mux *http.ServeMux, cfg *config, scopes *scoperegistry.Registry) {
	if !featureEnabled(cfg.features, feature.PAR) {
		return
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.PAR),
		parendpoint.Handler(parendpoint.Deps{
			Issuer:  cfg.issuer,
			Clients: cfg.store.Clients(),
			PARs:    cfg.store.PushedAuthRequests(),
			Scopes:  scopes,
			Clock:   cfg.clock,
		}),
	)
}

// featureEnabled reports whether flag is in the configured feature list.
// Used by both /par mounting and the authorize PAR-consumption wiring so
// the two stay in lock-step.
func featureEnabled(flags []feature.Flag, flag feature.Flag) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}

// mountAuthorizeHandlers wires the /authorize and /interaction routes when
// the configuration includes a grant that needs them (currently only
// AuthorizationCode). The handler shares an internal mux so a single
// instance services both paths; see [internal/authorizeendpoint.Handler].
func mountAuthorizeHandlers(mux *http.ServeMux, cfg *config, scopes *scoperegistry.Registry) error {
	if !grantsRequireAuthorizeEndpoint(cfg.grants) {
		return nil
	}
	cookieCodec, err := cookie.NewCodec(cfg.cookieKeys[0], cfg.cookieKeys[1:]...)
	if err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "cookie codec rejected configured keys",
			Cause:       err,
		}
	}
	sessCodec, err := sessions.NewCodec(cookieCodec)
	if err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "sessions codec construction failed",
			Cause:       err,
		}
	}
	sessMgr, err := sessions.NewManager(sessions.Config{
		Codec: sessCodec,
		Store: cfg.store.Sessions(),
		Clock: cfg.clock.Now,
	})
	if err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "sessions manager construction failed",
			Cause:       err,
		}
	}
	csrfSigner, err := csrf.NewSigner(deriveCSRFKey(cfg.cookieKeys[0]))
	if err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "csrf signer construction failed",
			Cause:       err,
		}
	}
	allowOrigins := append([]string(nil), cfg.corsOrigins...)
	if origin, oerr := csrf.CanonicalOrigin(cfg.issuer); oerr == nil {
		allowOrigins = append(allowOrigins, origin)
	}
	allow, err := csrf.NewAllowlist(allowOrigins)
	if err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "csrf allowlist construction failed",
			Cause:       err,
		}
	}
	authorizePath := joinPath(cfg.mountPrefix, cfg.endpoints.Authorize)
	interactionPath := joinPath(cfg.mountPrefix, cfg.endpoints.Interaction)
	handler := authorizeendpoint.Handler(authorizeendpoint.Deps{
		Clients:         cfg.store.Clients(),
		Codes:           cfg.store.AuthorizationCodes(),
		Grants:          cfg.store.Grants(),
		Interactions:    cfg.store.Interactions(),
		PARs:            authorizePARStore(cfg),
		Sessions:        sessMgr,
		CookieCodec:     cookieCodec,
		CSRF:            csrfSigner,
		Origins:         allow,
		Driver:          cfg.interactionD,
		Scopes:          scopes,
		AuthorizePath:   authorizePath,
		InteractionPath: interactionPath,
		Clock:           cfg.clock,
	})
	mux.Handle(authorizePath, handler)
	mux.Handle(interactionPath+"/{uid}", handler)
	return nil
}

// authorizePARStore returns the substore the authorize handler should use
// to consume PAR records when the feature is enabled. When PAR is
// disabled the helper returns nil, which the handler treats as
// "request_uri is not supported".
//
// The function exists so the wiring at [mountAuthorizeHandlers] reads as
// a flat field assignment rather than a multi-line conditional.
func authorizePARStore(cfg *config) store.PushedAuthRequestStore {
	if !featureEnabled(cfg.features, feature.PAR) {
		return nil
	}
	return cfg.store.PushedAuthRequests()
}

// grantsRequireAuthorizeEndpoint reports whether any configured grant
// depends on the /authorize endpoint being mounted. Currently only the
// AuthorizationCode grant qualifies; the helper exists so future
// grants can opt in by adding themselves to the switch.
func grantsRequireAuthorizeEndpoint(grants []grant.Type) bool {
	for _, g := range grants {
		if g == grant.AuthorizationCode {
			return true
		}
	}
	return false
}

// deriveCSRFKey returns a 32-byte HMAC-SHA256 derivation of cookieKey
// labelled with [csrfDerivationLabel]. SHA-256 emits exactly 32 bytes
// which matches the [csrf.NewSigner] requirement, so no truncation is
// needed.
func deriveCSRFKey(cookieKey []byte) []byte {
	h := hmac.New(sha256.New, cookieKey)
	_, _ = h.Write([]byte(csrfDerivationLabel))
	return h.Sum(nil)
}

// buildDiscoveryInput converts the public [config] to the internal
// [discovery.Input] the discovery builder consumes.
func buildDiscoveryInput(cfg *config, scopes *scoperegistry.Registry) discovery.Input {
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
		ScopesSupported: scopes.PublicNames(),
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

package op

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/introspectendpoint"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/jarm"
	"github.com/libraz/go-oidc-provider/internal/jwks"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/parendpoint"
	"github.com/libraz/go-oidc-provider/internal/registrationendpoint"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/internal/userinfo"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
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

// stateRefDerivationLabel is the HMAC label used to derive the
// orchestrator's [authn.StateRefSigner] key from the cookie key. The
// derivation is namespaced from the CSRF key so a hypothetical key-
// disclosure on one signer cannot forge tokens on the other.
const stateRefDerivationLabel = "oidc-stateref-v1"

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
	dpopVerifier, err := buildDPoPVerifier(cfg)
	if err != nil {
		return nil, err
	}
	mtlsVerifier, err := buildMTLSVerifier(cfg)
	if err != nil {
		return nil, err
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
			DPoP:      dpopVerifier,
			MTLS:      mtlsVerifier,
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
			DPoP:          dpopVerifier,
			MTLS:          mtlsVerifier,
		}),
	)
	if err := mountAuthorizeHandlers(mux, cfg, scopes, keySet); err != nil {
		return nil, err
	}
	if err := mountPAREndpoint(mux, cfg, scopes); err != nil {
		return nil, err
	}
	mountIntrospectionEndpoint(mux, cfg, scopes, keySet)
	mountRegistrationEndpoint(mux, cfg, scopes)
	return mux, nil
}

// buildDPoPVerifier constructs the RFC 9449 verifier when the [feature.DPoP]
// flag is enabled, returning nil when the feature is off so call sites
// can use a simple non-nil check to gate DPoP enforcement. The
// (*dpop.Verifier, error) signature returns (nil, nil) on the
// "feature off" path on purpose: callers branch on the verifier's
// nilness, never on the error, so introducing a sentinel for the
// "no verifier needed" case would only obscure the wiring.
//
//nolint:nilnil // (nil, nil) is the documented "DPoP not enabled" signal.
func buildDPoPVerifier(cfg *config) (*dpop.Verifier, error) {
	if !featureEnabled(cfg.features, feature.DPoP) {
		return nil, nil
	}
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:  cfg.store.ConsumedJTIs(),
		Clock: cfg.clock,
	})
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "DPoP verifier construction failed",
			Cause:       err,
		}
	}
	return v, nil
}

// buildMTLSVerifier constructs the RFC 8705 verifier when the
// [feature.MTLS] flag is enabled. The shape mirrors
// [buildDPoPVerifier]: nil verifier means "feature off" everywhere
// downstream, and the (*mtls.Verifier, error) signature returns
// (nil, nil) on that path on purpose.
//
// v0.x ships with a zero [mtls.ProxyConfig], which restricts the
// trust path to TLS handshakes terminated at the OP. Embedders that
// need the reverse-proxy header path will land a configuration knob
// on a follow-up; the wiring here keeps the field-set narrow so that
// extension is purely additive.
//
//nolint:nilnil // (nil, nil) is the documented "mTLS not enabled" signal.
func buildMTLSVerifier(cfg *config) (*mtls.Verifier, error) {
	if !featureEnabled(cfg.features, feature.MTLS) {
		return nil, nil
	}
	v, err := mtls.NewVerifier(mtls.VerifierConfig{})
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "mTLS verifier construction failed",
			Cause:       err,
		}
	}
	return v, nil
}

// buildJARVerifier constructs the JAR verifier when the [feature.JAR]
// flag is enabled. The shape mirrors [buildDPoPVerifier] /
// [buildMTLSVerifier]: nil verifier means "feature off" everywhere
// downstream, and the (*jar.Verifier, error) signature returns
// (nil, nil) on the "feature off" path on purpose.
//
// The verifier uses the default in-process JWKS resolver, which pulls
// inline JWKs from [op/store.Client.JWKs] first and falls back to
// [op/store.Client.JWKsURI] (with hardened HTTP fetch + caching) when
// the inline value is absent.
//
//nolint:nilnil // (nil, nil) is the documented "JAR not enabled" signal.
func buildJARVerifier(cfg *config) (*jar.Verifier, error) {
	if !featureEnabled(cfg.features, feature.JAR) {
		return nil, nil
	}
	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:   cfg.issuer,
		Resolver: jar.NewDefaultResolver(cfg.clock),
		Clock:    cfg.clock,
	})
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "JAR verifier construction failed",
			Cause:       err,
		}
	}
	return v, nil
}

// buildJARMSigner constructs the JARM signer when the [feature.JARM]
// flag is enabled. The shape mirrors [buildDPoPVerifier] /
// [buildMTLSVerifier]: nil means "feature off" everywhere downstream,
// and the (*jarm.Signer, error) signature returns (nil, nil) on that
// path on purpose.
//
// The signer reuses the OP's active id_token / access_token signing
// key. v0.x ships with ES256 only; the JARM spec accepts the same
// algorithm without negotiation, so a separate keyset would only
// duplicate state without adding security.
//
//nolint:nilnil // (nil, nil) is the documented "JARM not enabled" signal.
func buildJARMSigner(cfg *config, keySet *keys.Set) (*jarm.Signer, error) {
	if !featureEnabled(cfg.features, feature.JARM) {
		return nil, nil
	}
	signer, err := jarm.NewSigner(jarm.SignerConfig{
		Key:    tokens.FromInternalEntry(keySet.Active()),
		Issuer: cfg.issuer,
		Clock:  cfg.clock,
	})
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "JARM signer construction failed",
			Cause:       err,
		}
	}
	return signer, nil
}

// mountRegistrationEndpoint registers the /register and
// /register/{client_id} handlers when [WithDynamicRegistration] is
// configured. The two paths share a single [registrationendpoint.Handler]
// instance which discriminates on the URL shape internally; mounting
// them separately here is required because [http.ServeMux] does not
// admit a single pattern that matches both the bare and parameterised
// paths.
//
// Without the option the routes are absent — discovery already gates
// the advertisement on the same condition, so the OP cannot tell
// clients the endpoint exists while quietly serving 404.
func mountRegistrationEndpoint(mux *http.ServeMux, cfg *config, scopes *scoperegistry.Registry) {
	if cfg.dcr == nil {
		return
	}
	// validateRegistration ran inside [config.validate]; the type
	// assertion here cannot fail in practice. The defensive ok-check
	// preserves the property that a misconfigured store does not panic
	// at request time.
	registry, ok := cfg.store.(store.ClientRegistry)
	if !ok {
		return
	}
	deps := registrationendpoint.Deps{
		Issuer:                   cfg.issuer,
		MountPrefix:              cfg.mountPrefix,
		RegisterPath:             cfg.endpoints.Register,
		Clock:                    cfg.clock,
		Clients:                  registry,
		InitialAccessTokens:      cfg.store.InitialAccessTokens(),
		RegistrationAccessTokens: cfg.store.RegistrationAccessTokens(),
		Scopes:                   scopes,
		Open:                     cfg.dcr.Open,
		AllowedGrantTypes:        append([]string(nil), cfg.dcr.AllowedGrantTypes...),
		AllowedResponseTypes:     append([]string(nil), cfg.dcr.AllowedResponseTypes...),
		PairwiseEnabled:          false, // WithPairwiseSubject not yet implemented; v1.0 placeholder.
		ValidateMetadata:         wrapValidateMetadata(cfg.dcr.ValidateMetadata),
		Logger:                   cfg.logger,
	}
	handler := registrationendpoint.Handler(deps)
	registerPath := joinPath(cfg.mountPrefix, cfg.endpoints.Register)
	mux.Handle(registerPath, handler)
	mux.Handle(registerPath+"/{client_id}", handler)
}

// wrapValidateMetadata adapts a caller-supplied
// [RegistrationOption.ValidateMetadata] hook (which sees the public
// op.ClientMetadata) into the internal-package signature
// (registrationendpoint.ClientMetadata). internal/* must not import
// op/, so the conversion lives here.
//
// A nil input returns nil so the internal handler can short-circuit
// the hook entirely.
func wrapValidateMetadata(fn func(ctx context.Context, m ClientMetadata) error) func(ctx context.Context, m registrationendpoint.ClientMetadata) error {
	if fn == nil {
		return nil
	}
	return func(ctx context.Context, m registrationendpoint.ClientMetadata) error {
		return fn(ctx, fromInternalMetadata(m))
	}
}

// fromInternalMetadata projects the internal-shape metadata onto the
// public [ClientMetadata]. The two structs are field-for-field
// identical; the conversion exists solely to honour the rule that
// internal/* must not import op/.
func fromInternalMetadata(m registrationendpoint.ClientMetadata) ClientMetadata {
	return ClientMetadata{
		RedirectURIs:             m.RedirectURIs,
		GrantTypes:               m.GrantTypes,
		ResponseTypes:            m.ResponseTypes,
		Scope:                    m.Scope,
		TokenEndpointAuthMethod:  m.TokenEndpointAuthMethod,
		ApplicationType:          m.ApplicationType,
		SubjectType:              m.SubjectType,
		IDTokenSignedResponseAlg: m.IDTokenSignedResponseAlg,
		SectorIdentifierURI:      m.SectorIdentifierURI,
		ClientName:               m.ClientName,
		ClientURI:                m.ClientURI,
		LogoURI:                  m.LogoURI,
		PolicyURI:                m.PolicyURI,
		TosURI:                   m.TosURI,
		JWKsURI:                  m.JWKsURI,
		JWKs:                     m.JWKs,
		Contacts:                 m.Contacts,
		DefaultMaxAge:            m.DefaultMaxAge,
		RequireAuthTime:          m.RequireAuthTime,
		DefaultACRValues:         m.DefaultACRValues,
		InitiateLoginURI:         m.InitiateLoginURI,
		RequestURIs:              m.RequestURIs,
		RequestObjectSigningAlg:  m.RequestObjectSigningAlg,
	}
}

// mountPAREndpoint registers the /par handler when the [feature.PAR] flag
// is enabled. Without the flag the route is absent — discovery already
// gates the advertisement on the same flag, so the OP cannot tell clients
// the endpoint exists while quietly serving 404.
func mountPAREndpoint(mux *http.ServeMux, cfg *config, scopes *scoperegistry.Registry) error {
	if !featureEnabled(cfg.features, feature.PAR) {
		return nil
	}
	jarVerifier, err := buildJARVerifier(cfg)
	if err != nil {
		return err
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.PAR),
		parendpoint.Handler(parendpoint.Deps{
			Issuer:  cfg.issuer,
			Clients: cfg.store.Clients(),
			PARs:    cfg.store.PushedAuthRequests(),
			Scopes:  scopes,
			Clock:   cfg.clock,
			JAR:     jarVerifier,
		}),
	)
	return nil
}

// mountIntrospectionEndpoint registers the /introspect handler when the
// [feature.Introspect] flag is enabled. Without the flag the route is
// absent — discovery already gates the advertisement on the same flag,
// so the OP cannot tell clients the endpoint exists while quietly
// serving 404. The handler reuses the OP keyset (for JWT
// access-token verification) and the refresh-token substore (for
// opaque introspection); refresh-token introspection is a no-op when
// the backend returns a nil RefreshTokenStore, which the
// introspectendpoint package documents as "opaque path always returns
// inactive".
func mountIntrospectionEndpoint(mux *http.ServeMux, cfg *config, scopes *scoperegistry.Registry, keySet *keys.Set) {
	if !featureEnabled(cfg.features, feature.Introspect) {
		return
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.Introspect),
		introspectendpoint.Handler(introspectendpoint.Deps{
			Issuer:        cfg.issuer,
			Clients:       cfg.store.Clients(),
			RefreshTokens: cfg.store.RefreshTokens(),
			Keys:          keySet,
			Scopes:        scopes,
			Clock:         cfg.clock,
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
func mountAuthorizeHandlers(mux *http.ServeMux, cfg *config, scopes *scoperegistry.Registry, keySet *keys.Set) error {
	if !grantsRequireAuthorizeEndpoint(cfg.grants) {
		return nil
	}
	jarmSigner, err := buildJARMSigner(cfg, keySet)
	if err != nil {
		return err
	}
	jarVerifier, err := buildJARVerifier(cfg)
	if err != nil {
		return err
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
	orchestrator, err := buildOrchestrator(cfg)
	if err != nil {
		return err
	}
	authorizePath := joinPath(cfg.mountPrefix, cfg.endpoints.Authorize)
	interactionPath := joinPath(cfg.mountPrefix, cfg.endpoints.Interaction)
	handler := authorizeendpoint.Handler(authorizeendpoint.Deps{
		Clients:         cfg.store.Clients(),
		Codes:           cfg.store.AuthorizationCodes(),
		Grants:          cfg.store.Grants(),
		Interactions:    cfg.store.Interactions(),
		PARs:            authorizePARStore(cfg),
		JARM:            jarmSigner,
		JAR:             jarVerifier,
		Sessions:        sessMgr,
		CookieCodec:     cookieCodec,
		CSRF:            csrfSigner,
		Origins:         allow,
		Driver:          cfg.interactionD,
		Authn:           orchestrator,
		Scopes:          scopes,
		AuthorizePath:   authorizePath,
		InteractionPath: interactionPath,
		Clock:           cfg.clock,
	})
	mux.Handle(authorizePath, handler)
	mux.Handle(interactionPath+"/{uid}", handler)
	return nil
}

// buildOrchestrator constructs the [authn.Orchestrator] the
// /interaction handler drives. The function returns nil without an
// error when no [Authenticator] has been registered: deployments
// running only non-interactive grants (client_credentials, refresh
// against an externally-issued code) do not need the chain runner,
// and the handler treats a nil orchestrator as "interaction
// disabled".
//
// The orchestrator's Interaction list is the registered
// [WithInteractions] slice prepended with the built-in consent
// interaction. Prepending preserves user-extension ordering relative
// to consent: consent always runs first at [TriggerAfterAuthn] so the
// authorize-code mint observes the approved scope subset before any
// user-extension can short-circuit the chain.
func buildOrchestrator(cfg *config) (*authn.Orchestrator, error) {
	if len(cfg.authenticators) == 0 {
		return nil, nil //nolint:nilnil // documented "no orchestrator configured" sentinel
	}
	signer, err := authn.NewStateRefSigner(deriveStateRefKey(cfg.cookieKeys[0]))
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "stateref signer construction failed",
			Cause:       err,
		}
	}
	interactions := buildBuiltInInteractions(cfg)
	orch, err := authn.New(authn.Config{
		Authenticators: cfg.authenticators,
		Interactions:   interactions,
		Risk:           cfg.risk,
		Captcha:        cfg.captcha,
		Observers:      cfg.loginObservers,
		StateRefSigner: signer,
	})
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "authn orchestrator construction failed",
			Cause:       err,
		}
	}
	return orch, nil
}

// buildBuiltInInteractions prepends the library-built-in interactions
// (today: consent only) to the user-supplied [WithInteractions] slice.
// Names already taken by user extensions win — [authn.New] de-duplicates
// by [Interaction.Name] and keeps the first occurrence — so an embedder
// who registers a custom "consent" interaction (rare but supported)
// silently overrides the built-in.
func buildBuiltInInteractions(cfg *config) []Interaction {
	out := make([]Interaction, 0, len(cfg.interactions)+1)
	out = append(out, consent.New(consentCatalog(cfg.scopes)))
	out = append(out, cfg.interactions...)
	return out
}

// consentCatalog projects the public [Scope] catalogue onto the slim
// [interaction.ConsentScope] shape the consent screen renders. UI
// metadata that the SPA owns (Title, Icon, Category, I18n, Claims,
// AllowedClients) is dropped at the boundary; the consent prompt
// surfaces only the fields the design fixes.
func consentCatalog(scopes []Scope) []interaction.ConsentScope {
	out := make([]interaction.ConsentScope, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, interaction.ConsentScope{
			Name:        s.Name,
			Description: s.Description,
			Required:    s.Required,
		})
	}
	return out
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

// deriveStateRefKey returns a 32-byte HMAC-SHA256 derivation of
// cookieKey labelled with [stateRefDerivationLabel] for use as the
// orchestrator's [authn.StateRefSigner] key.
func deriveStateRefKey(cookieKey []byte) []byte {
	h := hmac.New(sha256.New, cookieKey)
	_, _ = h.Write([]byte(stateRefDerivationLabel))
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
			Register:    cfg.endpoints.Register,
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
		case feature.DynamicRegistration:
			out.DynamicRegistration = true
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

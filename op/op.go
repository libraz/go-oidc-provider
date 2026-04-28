package op

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endsession"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/internal/introspectendpoint"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/jarm"
	"github.com/libraz/go-oidc-provider/internal/jwks"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/parendpoint"
	"github.com/libraz/go-oidc-provider/internal/registrationendpoint"
	"github.com/libraz/go-oidc-provider/internal/revokeendpoint"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/internal/userinfo"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
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
	cfg     *config
	keys    *keys.Set
	scopes  *scoperegistry.Registry
	locales *i18n.Resolver
	mux     *http.ServeMux
	handler http.Handler
}

// ServeHTTP routes incoming requests to the OIDC endpoints registered by the
// enabled grants and features. The mount path is determined by where the
// caller installs the handler in its own router.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.handler.ServeHTTP(w, r)
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
	locales, err := buildLocaleResolver(cfg)
	if err != nil {
		return nil, err
	}
	mux, err := buildRouter(cfg, keySet, scopes)
	if err != nil {
		return nil, err
	}
	handler := wrapWithProfileMiddleware(mux, cfg)
	return &Provider{
		cfg:     cfg,
		keys:    keySet,
		scopes:  scopes,
		locales: locales,
		mux:     mux,
		handler: handler,
	}, nil
}

// wrapWithProfileMiddleware decorates the [Provider]'s router with
// the cross-cutting middlewares whose enable bit comes from the
// active [profile.Profile] set. The function is composition-only;
// every middleware factory continues to live with the feature it
// implements (the FAPI x-fapi-interaction-id echo lives in
// internal/httpx, not here).
func wrapWithProfileMiddleware(mux http.Handler, cfg *config) http.Handler {
	handler := mux
	for _, p := range cfg.profiles {
		switch p {
		case profile.FAPI2Baseline, profile.FAPI2MessageSigning:
			handler = httpx.InteractionIDMiddleware(handler)
			// Once any FAPI2 profile has activated the echo we are
			// done — repeating it would stamp the header twice and
			// hide the upstream client value behind a regenerated
			// UUID. Other profiles will add their own middlewares
			// here as the constraint set grows.
			return handler
		case profile.FAPICIBA, profile.IGovHigh:
			// v1.x / v2+; no middleware contribution today.
		}
	}
	return handler
}

// buildLocaleResolver assembles the [i18n.Resolver] from the seed
// bundles plus any embedder overrides registered through [WithLocale].
// Override entries replace seeds with the same tag so an embedder
// can ship branded copy without forking the library catalogue.
func buildLocaleResolver(cfg *config) (*i18n.Resolver, error) {
	seeds, err := i18n.DefaultBundles()
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "embedded locale bundles failed to load",
			Cause:       err,
		}
	}
	bundles := make(map[i18n.Tag]*i18n.Bundle, len(seeds)+len(cfg.localeBundles))
	order := make([]i18n.Tag, 0, len(seeds)+len(cfg.localeBundles))
	for _, b := range seeds {
		bundles[b.Tag()] = b
		order = append(order, b.Tag())
	}
	for _, b := range cfg.localeBundles {
		if b.internal == nil {
			continue
		}
		if _, exists := bundles[b.internal.Tag()]; !exists {
			order = append(order, b.internal.Tag())
		}
		bundles[b.internal.Tag()] = b.internal
	}
	merged := make([]*i18n.Bundle, 0, len(order))
	for _, t := range order {
		merged = append(merged, bundles[t])
	}
	return i18n.NewResolver(i18n.Tag(cfg.defaultLocale), merged...)
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
	assertionVerifier, err := buildAssertionVerifier(cfg)
	if err != nil {
		return nil, err
	}
	mux.Handle(cfg.endpoints.Discovery, discHandler)
	mux.Handle(joinPath(cfg.mountPrefix, cfg.endpoints.JWKS), jwks.Handler(keySet))
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.UserInfo),
		userinfo.Handler(userinfo.HandlerDeps{
			Keys:       keySet,
			Issuer:     cfg.issuer,
			UserStore:  cfg.store.Users(),
			Clock:      cfg.clock,
			Leeway:     defaultUserInfoLeeway,
			DPoP:       dpopVerifier,
			DPoPNonces: cfg.dpopNonces, // nil leaves the use_dpop_nonce challenge disabled.
			MTLS:       mtlsVerifier,
		}),
	)
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.Token),
		tokenendpoint.Handler(tokenendpoint.Deps{
			Issuer:                         cfg.issuer,
			Clients:                        cfg.store.Clients(),
			Codes:                          cfg.store.AuthorizationCodes(),
			RefreshTokens:                  cfg.store.RefreshTokens(),
			Grants:                         cfg.store.Grants(),
			Keys:                           keySet,
			Clock:                          cfg.clock,
			Scopes:                         scopes,
			DPoP:                           dpopVerifier,
			DPoPNonces:                     cfg.dpopNonces, // nil leaves the use_dpop_nonce challenge disabled.
			MTLS:                           mtlsVerifier,
			AssertionVerifier:              assertionVerifier,
			AccessTokenTTL:                 cfg.accessTokenTTL,
			AllowedClientAuthMethods:       cfg.allowedClientAuthMethods(),
			RequireSenderConstrainedTokens: cfg.requireSenderConstrainedTokens(),
		}),
	)
	sessMgr, err := mountAuthorizeHandlers(mux, cfg, scopes, keySet)
	if err != nil {
		return nil, err
	}
	if err := mountPAREndpoint(mux, cfg, scopes, assertionVerifier, dpopVerifier); err != nil {
		return nil, err
	}
	mountIntrospectionEndpoint(mux, cfg, scopes, keySet, assertionVerifier)
	mountRevocationEndpoint(mux, cfg, keySet, assertionVerifier)
	mountRegistrationEndpoint(mux, cfg, scopes)
	bcc, err := buildBackchannelCoordinator(cfg, keySet)
	if err != nil {
		return nil, err
	}
	mountEndSessionEndpoint(mux, cfg, keySet, sessMgr, bcc)
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
		JTIs:   cfg.store.ConsumedJTIs(),
		Clock:  cfg.clock,
		Nonces: cfg.dpopNonces, // nil leaves the §8 / §9 gate disabled.
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
	// FAPI 2.0 Message Signing §5.6 mandates "nbf" and a request-object
	// lifetime no longer than 60 minutes after nbf. The library
	// implements that bound symmetrically: exp must not be more than
	// 60 minutes in the future, and nbf must not be more than 60
	// minutes in the past. Baseline (where JAR is rarely exercised)
	// inherits the same posture so a deployment that opts in to JAR
	// without a Message-Signing-only switch still gets the bound. Other
	// JAR-enabling profiles inherit the relaxed (back-compat) behaviour.
	var (
		requireNbf  bool
		maxLifetime time.Duration
	)
	for _, p := range cfg.profiles {
		if p == profile.FAPI2Baseline || p == profile.FAPI2MessageSigning {
			requireNbf = true
			maxLifetime = 60 * time.Minute
			break
		}
	}
	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:      cfg.issuer,
		Resolver:    jar.NewDefaultResolver(cfg.clock),
		Clock:       cfg.clock,
		RequireNbf:  requireNbf,
		MaxLifetime: maxLifetime,
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

// buildAssertionVerifier constructs the [clientauth.PrivateKeyJWTVerifier]
// the OP installs at every endpoint that authenticates clients
// (/token, /par, /introspect, /revoke). The verifier is unconditional
// — discovery advertises private_key_jwt as a supported auth method
// and the FAPI 2.0 §3.1.3 allow-list lists it as preferred — so the
// OP wiring layer does not gate it on a feature flag. Embedders that
// register a client with a different [TokenEndpointAuthMethod] are
// unaffected: the verifier is consulted only when the inbound
// request actually claims private_key_jwt.
//
// The verifier reads inline JWKs from [store.Client.JWKs] via
// [clientauth.StoreJWKSResolver]. JWKsURI fetching is documented at
// the resolver as a follow-up; until that lands an embedder whose
// clients publish their keys via URL must pre-fetch them and write
// the inline form into the client record.
//
// Audience is the absolute token endpoint URL, per OIDC Core §9 / RFC
// 7523 §3 — every assertion at /token, /par, /introspect, and /revoke
// MUST set "aud" to that URL. The library reuses the same value across
// the four endpoints so an RP that signs once can authenticate
// anywhere; spec-strict embedders who want endpoint-scoped audiences
// can swap the verifier through the public store.
func buildAssertionVerifier(cfg *config) (*clientauth.PrivateKeyJWTVerifier, error) {
	resolver, err := clientauth.NewStoreJWKSResolver(cfg.store.Clients())
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "private_key_jwt JWKS resolver construction failed",
			Cause:       err,
		}
	}
	return &clientauth.PrivateKeyJWTVerifier{
		Resolver: resolver,
		JTIStore: cfg.store.ConsumedJTIs(),
		Audience: absoluteEndpointURL(cfg, cfg.endpoints.Token),
		// FAPI 2.0 §5.2.2 mandates aud == issuer; OIDC Core §9
		// mandates aud == token endpoint URL. RFC 7523 §3 leaves the
		// choice to the AS. Accepting both lets the same OP serve
		// OIDC Core and FAPI 2.0 clients without forcing a per-
		// profile verifier swap. The PAR endpoint URL is also
		// accepted because OFCS' "par-test-pushed-authorization-url-
		// as-audience" module sets aud == PAR endpoint when the
		// client_assertion lands at /par, and RFC 7523 §3's "value
		// identifying the AS" leaves the specific URL up to the AS.
		AuxAudiences: []string{
			cfg.issuer,
			absoluteEndpointURL(cfg, cfg.endpoints.PAR),
		},
		Clock: cfg.clock.Now,
	}, nil
}

// absoluteEndpointURL composes the OP's issuer with the mount prefix
// and the named endpoint, producing the canonical absolute URL the
// JOSE assertion verifier expects in the "aud" claim. The helper
// mirrors the discovery builder's joining logic so the audience the
// verifier accepts is byte-for-byte identical to the value
// /.well-known/openid-configuration advertises.
func absoluteEndpointURL(cfg *config, endpoint string) string {
	issuer := cfg.issuer
	for len(issuer) > 0 && issuer[len(issuer)-1] == '/' {
		issuer = issuer[:len(issuer)-1]
	}
	prefix := cfg.mountPrefix
	if prefix == "/" {
		prefix = ""
	}
	for len(prefix) > 0 && prefix[len(prefix)-1] == '/' {
		prefix = prefix[:len(prefix)-1]
	}
	if len(endpoint) > 0 && endpoint[0] != '/' {
		endpoint = "/" + endpoint
	}
	return issuer + prefix + endpoint
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
		Audit:                    audit.Slog(cfg.effectiveAuditLogger()),
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
func mountPAREndpoint(
	mux *http.ServeMux,
	cfg *config,
	scopes *scoperegistry.Registry,
	assertionVerifier clientauth.AssertionVerifier,
	dpopVerifier *dpop.Verifier,
) error {
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
			Issuer:                     cfg.issuer,
			Clients:                    cfg.store.Clients(),
			PARs:                       cfg.store.PushedAuthRequests(),
			Scopes:                     scopes,
			Clock:                      cfg.clock,
			JAR:                        jarVerifier,
			DPoP:                       dpopVerifier,
			AssertionVerifier:          assertionVerifier,
			AllowedClientAuthMethods:   cfg.allowedClientAuthMethods(),
			RequirePKCE:                cfg.requirePKCE(),
			RequireNonce:               cfg.requireNonce(),
			RequireStateOrNonce:        cfg.requireStateOrNonce(),
			RequireSignedRequestObject: cfg.requireSignedRequestObject(),
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
func mountIntrospectionEndpoint(
	mux *http.ServeMux,
	cfg *config,
	scopes *scoperegistry.Registry,
	keySet *keys.Set,
	assertionVerifier clientauth.AssertionVerifier,
) {
	if !featureEnabled(cfg.features, feature.Introspect) {
		return
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.Introspect),
		introspectendpoint.Handler(introspectendpoint.Deps{
			Issuer:                     cfg.issuer,
			Clients:                    cfg.store.Clients(),
			RefreshTokens:              cfg.store.RefreshTokens(),
			Keys:                       keySet,
			Scopes:                     scopes,
			Clock:                      cfg.clock,
			SigningKey:                 tokens.FromInternalEntry(keySet.Active()),
			AssertionVerifier:          assertionVerifier,
			AllowedClientAuthMethods:   cfg.allowedClientAuthMethods(),
			RequireSignedIntrospection: cfg.requireSignedIntrospection(),
		}),
	)
}

// mountRevocationEndpoint registers the /revoke handler when the
// [feature.Revoke] flag is enabled. Without the flag the route is
// absent — discovery already gates the advertisement on the same
// flag, so the OP cannot tell clients the endpoint exists while
// quietly serving 404. The handler reuses the OP keyset (so the JWT
// branch can verify access-token signatures during the
// acknowledgement check) and the refresh-token substore (so the
// opaque branch can walk the rotation chain to its root before
// calling RevokeChain). Refresh-token revocation is a no-op when the
// backend returns a nil RefreshTokenStore, which the revokeendpoint
// package documents as "opaque path always silently 200".
func mountRevocationEndpoint(
	mux *http.ServeMux,
	cfg *config,
	keySet *keys.Set,
	assertionVerifier clientauth.AssertionVerifier,
) {
	if !featureEnabled(cfg.features, feature.Revoke) {
		return
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.Revoke),
		revokeendpoint.Handler(revokeendpoint.Deps{
			Issuer:                   cfg.issuer,
			Clients:                  cfg.store.Clients(),
			RefreshTokens:            cfg.store.RefreshTokens(),
			Keys:                     keySet,
			Clock:                    cfg.clock,
			AssertionVerifier:        assertionVerifier,
			AllowedClientAuthMethods: cfg.allowedClientAuthMethods(),
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

// allowedClientAuthMethods returns the [clientauth.Method] subset
// imposed on /token, /par, /introspect, /revoke by the active
// [profile.Profile] set, or nil when no profile constrains client
// authentication.
//
// Profile values that name authentication methods outside the
// [clientauth] enum (tls_client_auth, self_signed_tls_client_auth)
// do not appear in the returned slice because they are handled
// outside the package; the FAPI 2.0 §3.1.3 enforcement ladder for
// those methods lives in internal/mtls.
// requireSenderConstrainedTokens reports whether the active
// [profile.Profile] set forbids the issuance of bearer access
// tokens. The library's product design (§J.7.2) ties this to the
// FAPI 2.0 family; the build-time profile validator already requires
// either DPoP or mTLS feature to be enabled when a FAPI2 profile is
// active, so the runtime path returning true here means "an /token
// request must present a proof or a cert".
func (c *config) requireSenderConstrainedTokens() bool {
	for _, p := range c.profiles {
		switch p {
		case profile.FAPI2Baseline, profile.FAPI2MessageSigning:
			return true
		case profile.FAPICIBA, profile.IGovHigh:
			// Future profiles. v1.0 ships without their constraint
			// tables; FAPI-CIBA requires sender-constrained tokens
			// the same way and will land here when the profile
			// graduates from placeholder.
		}
	}
	return false
}

// requirePKCE reports whether the active [profile.Profile] set
// mandates that every authorization-code request carry a
// code_challenge. The library's overall posture is OAuth 2.1 — PKCE
// is good practice on every flow — but the OpenID Connect Basic
// certification profile drives the OP without PKCE because OIDC
// Core 1.0 predates RFC 7636. Treating PKCE as profile-conditional
// resolves the conflict: vanilla deployments accept the spec-
// compliant non-PKCE path, while every FAPI 2.0 deployment keeps
// the stronger MUST the profile mandates.
//
// Multiple profiles MAY be active simultaneously; the helper
// returns true on the first profile that requires PKCE so a
// disjunctive set ("FAPI 2.0 Baseline OR something looser") still
// resolves to "PKCE required".
func (c *config) requirePKCE() bool {
	for _, p := range c.profiles {
		if profile.RequiresPKCE(p) {
			return true
		}
	}
	return false
}

// requireNonce reports whether the active [profile.Profile] set
// mandates that every authorization request carry a nonce. OIDC
// Core 1.0 makes nonce OPTIONAL for code-flow; no shipping profile
// currently elevates this to a strict MUST (FAPI 2.0 satisfies its
// replay-mitigation rule via [config.requireStateOrNonce] instead).
// The disjunctive resolution mirrors [config.requirePKCE] so
// embedders that wire a custom profile keep the same surface.
func (c *config) requireNonce() bool {
	for _, p := range c.profiles {
		if profile.RequiresNonce(p) {
			return true
		}
	}
	return false
}

// requireStateOrNonce reports whether the active [profile.Profile]
// set mandates that every authorization request carry at least one
// of state / nonce. FAPI 2.0 §5.3.2.1.1 is the canonical source.
// The disjunctive resolution mirrors [config.requirePKCE].
func (c *config) requireStateOrNonce() bool {
	for _, p := range c.profiles {
		if profile.RequiresStateOrNonce(p) {
			return true
		}
	}
	return false
}

// requirePAR reports whether the active [profile.Profile] set
// mandates that every /authorize request reach the OP via a PAR
// request_uri. FAPI 2.0 §5.3.1 requires PAR; vanilla OIDC Core does
// not. The disjunctive resolution mirrors [config.requirePKCE].
func (c *config) requirePAR() bool {
	for _, p := range c.profiles {
		if profile.RequiresPAR(p) {
			return true
		}
	}
	return false
}

// requireSignedRequestObject reports whether the active
// [profile.Profile] set mandates that every /authorize and /par
// request carry a signed JAR request object. FAPI 2.0 Message
// Signing §5.6 (the "signed_non_repudiation" request method) is
// the only profile today that imposes this; FAPI 2.0 Baseline
// permits plain form requests. The build-time profile validator
// requires [feature.JAR] to be enabled when
// [profile.FAPI2MessageSigning] is active, so the runtime path
// returning true here means "a JAR verifier is guaranteed to be
// wired".
func (c *config) requireSignedRequestObject() bool {
	for _, p := range c.profiles {
		switch p {
		case profile.FAPI2MessageSigning:
			return true
		case profile.FAPI2Baseline, profile.FAPICIBA, profile.IGovHigh:
			// Baseline does not mandate signed_non_repudiation; the
			// two future profiles ship without their constraint
			// tables and will land here when they graduate from
			// placeholder.
		}
	}
	return false
}

// requireJARMResponseMode reports whether the active
// [profile.Profile] set mandates that every /authorize response be
// JARM-wrapped. FAPI 2.0 Message Signing §5.5 is the only profile
// today that imposes this; FAPI 2.0 Baseline leaves response_mode
// to the client (Baseline does not require response signing). The
// build-time profile validator already requires [feature.JARM] to
// be enabled when [profile.FAPI2MessageSigning] is active, so the
// runtime path returning true here means "the JARM signer is
// guaranteed to be wired".
func (c *config) requireJARMResponseMode() bool {
	for _, p := range c.profiles {
		switch p {
		case profile.FAPI2MessageSigning:
			return true
		case profile.FAPI2Baseline, profile.FAPICIBA, profile.IGovHigh:
			// Baseline does not require response signing; the two
			// future profiles ship without their constraint tables
			// and will land here when they graduate from placeholder.
		}
	}
	return false
}

// requireSignedIntrospection reports whether the active
// [profile.Profile] set forces every successful /introspect response
// onto the RFC 9701 JWT envelope. FAPI 2.0 Message Signing §5 is the
// only profile today that imposes this; FAPI 2.0 Baseline leaves
// introspection format negotiation to RFC 9701 §5 (client metadata
// plus Accept). The signing key the handler uses is the OP active key,
// which op.New requires unconditionally — so true here means a
// non-nil signer is guaranteed at request time.
func (c *config) requireSignedIntrospection() bool {
	for _, p := range c.profiles {
		switch p {
		case profile.FAPI2MessageSigning:
			return true
		case profile.FAPI2Baseline, profile.FAPICIBA, profile.IGovHigh:
			// Baseline does not require introspection signing; the
			// two future profiles ship without their constraint
			// tables and will land here when they graduate from
			// placeholder.
		}
	}
	return false
}

func (c *config) allowedClientAuthMethods() []clientauth.Method {
	allowedNames := c.profileAllowedAuthMethodNames()
	if allowedNames == nil {
		return nil
	}
	out := make([]clientauth.Method, 0, len(allowedNames))
	for _, name := range allowedNames {
		switch clientauth.Method(name) {
		case clientauth.MethodNone, clientauth.MethodSecretBasic,
			clientauth.MethodSecretPost, clientauth.MethodPrivateKeyJWT:
			out = append(out, clientauth.Method(name))
		}
	}
	return out
}

// mountAuthorizeHandlers wires the /authorize and /interaction routes when
// the configuration includes a grant that needs them (currently only
// AuthorizationCode). The handler shares an internal mux so a single
// instance services both paths; see [internal/authorizeendpoint.Handler].
//
// The returned [*sessions.Manager] is the same instance the authorize
// handler installed; [mountEndSessionEndpoint] reuses it so the two
// surfaces operate on the same chooser-group state. A nil manager is
// returned when no grant requires the authorize endpoint — the
// /end_session helper short-circuits in that case.
func mountAuthorizeHandlers(mux *http.ServeMux, cfg *config, scopes *scoperegistry.Registry, keySet *keys.Set) (*sessions.Manager, error) {
	if !grantsRequireAuthorizeEndpoint(cfg.grants) {
		return nil, nil //nolint:nilnil // documented "no manager needed" sentinel.
	}
	jarmSigner, err := buildJARMSigner(cfg, keySet)
	if err != nil {
		return nil, err
	}
	jarVerifier, err := buildJARVerifier(cfg)
	if err != nil {
		return nil, err
	}
	cookieCodec, sessMgr, err := buildSessionMachinery(cfg)
	if err != nil {
		return nil, err
	}
	csrfSigner, err := csrf.NewSigner(deriveCSRFKey(cfg.cookieKeys[0]))
	if err != nil {
		return nil, &Error{
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
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "csrf allowlist construction failed",
			Cause:       err,
		}
	}
	orchestrator, err := buildOrchestrator(cfg)
	if err != nil {
		return nil, err
	}
	authorizePath := joinPath(cfg.mountPrefix, cfg.endpoints.Authorize)
	interactionPath := joinPath(cfg.mountPrefix, cfg.endpoints.Interaction)
	handler := authorizeendpoint.Handler(authorizeendpoint.Deps{
		Clients:                 cfg.store.Clients(),
		Codes:                   cfg.store.AuthorizationCodes(),
		Grants:                  cfg.store.Grants(),
		Interactions:            cfg.store.Interactions(),
		PARs:                    authorizePARStore(cfg),
		JARM:                    jarmSigner,
		JAR:                     jarVerifier,
		Sessions:                sessMgr,
		CookieCodec:             cookieCodec,
		CSRF:                    csrfSigner,
		Origins:                 allow,
		Driver:                  cfg.interactionD,
		Authn:                   orchestrator,
		Scopes:                  scopes,
		AuthorizePath:           authorizePath,
		InteractionPath:         interactionPath,
		Clock:                   cfg.clock,
		RequireJARMResponseMode: cfg.requireJARMResponseMode(),
		RequirePKCE:             cfg.requirePKCE(),
		RequireNonce:            cfg.requireNonce(),
		RequireStateOrNonce:     cfg.requireStateOrNonce(),
		RequirePAR:              cfg.requirePAR(),
		Issuer:                  cfg.issuer,
	})
	mux.Handle(authorizePath, handler)
	mux.Handle(interactionPath+"/{uid}", handler)
	return sessMgr, nil
}

// buildSessionMachinery constructs the cookie codec and chooser-group
// session manager shared by /authorize and /end_session. Splitting the
// helper out keeps the two mount sites in lock-step: a future change
// to the cookie key derivation, the codec configuration, or the idle
// TTL applies uniformly to every endpoint that touches the session
// cookie.
func buildSessionMachinery(cfg *config) (*cookie.Codec, *sessions.Manager, error) {
	cookieCodec, err := cookie.NewCodec(cfg.cookieKeys[0], cfg.cookieKeys[1:]...)
	if err != nil {
		return nil, nil, &Error{
			Code:        codeConfiguration,
			Description: "cookie codec rejected configured keys",
			Cause:       err,
		}
	}
	sessCodec, err := sessions.NewCodec(cookieCodec)
	if err != nil {
		return nil, nil, &Error{
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
		return nil, nil, &Error{
			Code:        codeConfiguration,
			Description: "sessions manager construction failed",
			Cause:       err,
		}
	}
	return cookieCodec, sessMgr, nil
}

// mountEndSessionEndpoint registers the /end_session handler. The
// endpoint is always advertised through the discovery document
// (RP-Initiated Logout 1.0 has no feature flag in this library); the
// handler is mounted only when [grantsRequireAuthorizeEndpoint]
// reports true so a deployment running solely non-interactive grants
// (client_credentials) does not pay for a session manager it never
// uses. Discovery still advertises the URL — that's the documented
// trade-off.
//
// The handler shares the [*sessions.Manager] with /authorize so the
// two surfaces operate on the same chooser-group state and a logout
// performed at /end_session is visible to a subsequent /authorize.
//
// The handler also runs back-channel logout fan-out (OpenID Connect
// Back-Channel Logout 1.0 §2.5) when a [backchannel.Coordinator] is
// supplied; [buildBackchannelCoordinator] returns a non-nil value
// once at least one RP is registered with a backchannel_logout_uri.
func mountEndSessionEndpoint(
	mux *http.ServeMux,
	cfg *config,
	keySet *keys.Set,
	sessMgr *sessions.Manager,
	bcc *backchannel.Coordinator,
) {
	if sessMgr == nil {
		return
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.EndSession),
		endsession.Handler(endsession.Deps{
			Issuer:      cfg.issuer,
			Clients:     cfg.store.Clients(),
			Sessions:    sessMgr,
			Keys:        keySet,
			Clock:       cfg.clock,
			Backchannel: bcc,
		}),
	)
}

// buildBackchannelCoordinator constructs the [backchannel.Coordinator]
// the /end_session handler dispatches to after the session is
// terminated. The coordinator is always wired: its store traversal
// short-circuits when no RP has registered a backchannel_logout_uri,
// so the cost on a deployment that does not use back-channel logout
// is one map walk per logout.
//
// The OP signs Logout Tokens with the active OP signing key, sharing
// the rotation lifecycle with id_tokens. The HTTP transport defaults
// to an internal client with [backchannel.DefaultTimeout] applied;
// embedders that need shared instrumentation override it through
// [WithBackchannelLogoutHTTPClient].
func buildBackchannelCoordinator(cfg *config, keySet *keys.Set) (*backchannel.Coordinator, error) {
	active := keySet.Active()
	deliverer := backchannel.NewHTTPDeliverer(cfg.backchannelLogoutTimeout)
	if cfg.backchannelLogoutHTTPClient != nil {
		deliverer.Client = cfg.backchannelLogoutHTTPClient
	}
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:    cfg.issuer,
		Signing:   backchannel.SigningKey{KeyID: active.KeyID, Signer: active.Signer},
		Clients:   cfg.store.Clients(),
		Grants:    cfg.store.Grants(),
		Deliverer: deliverer,
		Emitter:   audit.Slog(cfg.effectiveAuditLogger()),
		Clock:     cfg.clock,
	})
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "back-channel logout coordinator construction failed",
			Cause:       err,
		}
	}
	return coord, nil
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
	if len(cfg.authenticators) == 0 && !cfg.loginFlowSet {
		return nil, nil //nolint:nilnil // documented "no orchestrator configured" sentinel
	}
	if cfg.loginFlowSet && len(cfg.authenticators) > 0 {
		// Defence in depth: validateLoginFlow already rejects this
		// combination, but the orchestrator constructor re-asserts
		// the invariant so a refactor that loses the option-layer
		// check still surfaces the misconfiguration here.
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "WithLoginFlow is mutually exclusive with WithAuthenticators",
		}
	}
	signer, err := authn.NewStateRefSigner(deriveStateRefKey(cfg.cookieKeys[0]))
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "stateref signer construction failed",
			Cause:       err,
		}
	}
	var compiled *authn.CompiledLoginFlow
	if cfg.loginFlowSet {
		compiled, err = compileLoginFlow(cfg.loginFlow)
		if err != nil {
			// projectStepToFlow / authn.CompileLoginFlow already
			// produce typed *Error / contextual messages; wrap only
			// non-typed errors here so the outer message stays
			// compact.
			var typed *Error
			if errors.As(err, &typed) {
				return nil, typed
			}
			return nil, &Error{
				Code:        codeConfiguration,
				Description: "WithLoginFlow: " + err.Error(),
				Cause:       err,
			}
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
		LoginFlow:      compiled,
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

// compileLoginFlow projects the public [LoginFlow] onto the internal
// [authn.LoginFlowSpec] shape and hands it to the authn-package
// compiler. The projection lives in op/ (not internal/authn/) because
// the rule "internal MUST NOT import op" forbids the inverse path.
//
// Built-in Step values (PrimaryPassword / StepTOTP / …) are not yet
// wired to internal Authenticator primitives — their construction-
// time dependencies (TOTP encryption codec, passkey RP origin, hash
// adapter) are exposed by follow-up options. Until those land the
// embedder uses [op.ExternalStep] to wrap an already-constructed
// [Authenticator] for the LoginFlow seam; calling compileLoginFlow on
// a built-in Step returns [authn.ErrBuiltinStepNotWired] with a
// pointer to that workaround.
func compileLoginFlow(flow LoginFlow) (*authn.CompiledLoginFlow, error) {
	primary, err := projectStepToFlow("Primary", flow.Primary)
	if err != nil {
		return nil, err
	}
	rules := make([]authn.LoginFlowRule, 0, len(flow.Rules))
	for i, r := range flow.Rules {
		then, perr := projectStepToFlow("Rules["+strconv.Itoa(i)+"].Then", r.Then)
		if perr != nil {
			return nil, perr
		}
		// Capture the public predicate inside a closure that adapts
		// the LoginFlowContext shape to the public LoginContext one.
		// The closure preserves nil semantics: a nil When projects to
		// a nil compiled predicate (the compiler then substitutes the
		// constant-false predicate).
		pred := r.When
		var when func(authn.LoginFlowContext) bool
		if pred != nil {
			when = func(lc authn.LoginFlowContext) bool {
				return pred(toPublicLoginContext(lc))
			}
		}
		rules = append(rules, authn.LoginFlowRule{When: when, Then: then})
	}
	spec := authn.LoginFlowSpec{
		Primary: primary,
		Rules:   rules,
		Risk:    flow.Risk,
	}
	if flow.Decider != nil {
		spec.Decider = &deciderAdapter{inner: flow.Decider}
	}
	return authn.CompileLoginFlow(spec)
}

// projectStepToFlow projects a single public [Step] onto the
// internal [authn.LoginFlowStep] shape. The dispatch handles every
// shape the public surface exposes today:
//
//   - [ExternalStep] (embedder-wrapped Authenticator): forwarded
//     verbatim, the orchestrator drives the wrapped authenticator
//     directly.
//   - Built-in Steps with construction-time wiring (PrimaryPasskey,
//     StepTOTP, StepEmailOTP, StepRecoveryCode, StepCaptcha): the
//     matching builder synthesises the internal authenticator from
//     the Step's public fields. Validation errors surface as a
//     typed *Error pointing at the offending Step.
//   - PrimaryPassword: deferred. The construction-time deps
//     (PasswordCredentialStore + verifier) are not yet exposed
//     publicly. Surface the explanation verbatim so the upgrade
//     path is obvious; embedders use [ExternalStep] today.
func projectStepToFlow(where string, s Step) (authn.LoginFlowStep, error) {
	if s == nil {
		return authn.LoginFlowStep{}, &Error{
			Code:        codeConfiguration,
			Description: "WithLoginFlow: " + where + " must not be nil",
		}
	}
	if ext, ok := s.(ExternalStep); ok {
		return projectExternalStep(where, ext)
	}
	return projectBuiltinStep(where, s)
}

// projectExternalStep is the [projectStepToFlow] arm for an
// [ExternalStep]: validate the wrapped authenticator and forward
// verbatim. The split keeps [projectStepToFlow] under the cyclop
// budget without conflating the ExternalStep contract (verbatim
// forward) with the built-in builder dispatch.
func projectExternalStep(where string, ext ExternalStep) (authn.LoginFlowStep, error) {
	if ext.Authenticator == nil {
		return authn.LoginFlowStep{}, &Error{
			Code:        codeConfiguration,
			Description: "WithLoginFlow: " + where + " ExternalStep.Authenticator must not be nil",
		}
	}
	return authn.LoginFlowStep{
		Kind:          string(ext.KindLabel),
		Authenticator: ext.Authenticator,
	}, nil
}

// projectBuiltinStep dispatches a built-in [Step] (PrimaryPasskey,
// StepTOTP, StepEmailOTP, StepRecoveryCode, StepCaptcha) to the
// matching builder in loginflow_compile.go and wraps the constructed
// authenticator in a [authn.LoginFlowStep]. PrimaryPassword and any
// unrecognised Step value surface the deferred-wiring error so the
// embedder is pointed at the ExternalStep workaround.
func projectBuiltinStep(where string, s Step) (authn.LoginFlowStep, error) {
	switch v := s.(type) {
	case PrimaryPasskey:
		auth, err := buildPrimaryPasskey(v)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		return authn.LoginFlowStep{Kind: string(StepKindPasskey), Authenticator: auth}, nil
	case StepTOTP:
		auth, err := buildStepTOTP(v)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		return authn.LoginFlowStep{Kind: string(StepKindTOTP), Authenticator: auth}, nil
	case StepEmailOTP:
		auth, err := buildStepEmailOTP(v)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		return authn.LoginFlowStep{Kind: string(StepKindEmailOTP), Authenticator: auth}, nil
	case StepRecoveryCode:
		auth, err := buildStepRecoveryCode(v)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		return authn.LoginFlowStep{Kind: string(StepKindRecoveryCode), Authenticator: auth}, nil
	case StepCaptcha:
		auth, err := buildStepCaptcha(v)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		return authn.LoginFlowStep{Kind: string(StepKindCaptcha), Authenticator: auth, IsCaptcha: true}, nil
	case PrimaryPassword:
		// PrimaryPassword wiring is deferred: the password-credential
		// store interface and the username -> subject lookup contract
		// are still being designed. Embedders compose a password
		// factor through ExternalStep today; the ExternalStep wraps
		// their own Authenticator so credential storage stays inside
		// the embedder's process.
		_ = v
		return authn.LoginFlowStep{}, &Error{
			Code:        codeConfiguration,
			Description: "WithLoginFlow: " + where + " PrimaryPassword wiring is deferred; wrap your own Authenticator in op.ExternalStep until the password-credential store contract lands",
			Cause:       authn.ErrBuiltinStepNotWired,
		}
	default:
		// An unrecognised Step shape (a future built-in we forgot to
		// wire, or an embedder-defined value type that satisfies Step
		// but is not ExternalStep). Surface the same actionable
		// message so the upgrade path stays obvious.
		return authn.LoginFlowStep{}, &Error{
			Code:        codeConfiguration,
			Description: "WithLoginFlow: " + where + " uses built-in Step " + string(s.Kind()) + " whose primitive is not yet exposed; wrap your own Authenticator in op.ExternalStep until the matching option lands",
			Cause:       authn.ErrBuiltinStepNotWired,
		}
	}
}

// projectStepError wraps a builder failure into a typed [Error] that
// names the offending Step's location ("Primary", "Rules[0].Then",
// ...). Centralising the wrapping keeps the [projectStepToFlow]
// switch arms readable.
func projectStepError(where string, err error) error {
	return &Error{
		Code:        codeConfiguration,
		Description: "WithLoginFlow: " + where + ": " + err.Error(),
		Cause:       err,
	}
}

// toPublicLoginContext projects the internal [authn.LoginFlowContext]
// onto the public [LoginContext] surface rule predicates consume. The
// numeric RiskScore field maps verbatim because the public
// [op.RiskScore] constants share the internal numeric ordering.
func toPublicLoginContext(lc authn.LoginFlowContext) LoginContext {
	scopes := make(ScopeSet, len(lc.RequestedScopes))
	for _, s := range lc.RequestedScopes {
		scopes[ScopeName(s)] = struct{}{}
	}
	completed := make([]StepKind, len(lc.CompletedKinds))
	for i, k := range lc.CompletedKinds {
		completed[i] = StepKind(k)
	}
	return LoginContext{
		Identity:        Identity{Subject: Subject(lc.Subject)},
		ClientID:        lc.ClientID,
		RequestedScopes: scopes,
		FailedAttempts:  lc.FailedAttempts,
		RiskScore:       RiskScore(lc.RiskScore),
		NewDevice:       lc.NewDevice,
		CompletedSteps:  completed,
		ACRValues:       lc.ACRValues,
		Remote: ClientHints{
			RemoteIP:       lc.RemoteIP,
			UserAgent:      lc.UserAgent,
			AcceptLanguage: lc.AcceptLanguage,
		},
	}
}

// deciderAdapter projects the public [Decider] surface onto the
// internal [authn.LoginFlowDecider]. The adapter translates each
// public [Decision] case into its internal counterpart so the
// orchestrator's switch stays closed (LoginFlowDecision is a sealed
// sum). An unrecognised public Decision projects to LoginFlowPass
// (the safe default) — Decision is itself a sealed sum so the path is
// only reachable if the op package adds a new Decision case without
// updating this adapter.
type deciderAdapter struct {
	inner Decider
}

// Decide implements [authn.LoginFlowDecider]. The adapter rebuilds the
// public LoginContext from the internal projection, calls the
// embedder's Decider, and translates the returned Decision back. A
// Require{Step} decision projects the wrapped Step back through
// projectStepToFlow so a Decider that returns an unwrapped built-in
// Step surfaces as ErrInvalidStep at the orchestrator (the
// dynamic-compile path is intentionally absent — see plan 005 H1-D §6).
func (a *deciderAdapter) Decide(ctx context.Context, lc authn.LoginFlowContext) authn.LoginFlowDecision { //nolint:ireturn // sealed-sum LoginFlowDecision is the contract.
	d := a.inner.Decide(ctx, toPublicLoginContext(lc))
	switch v := d.(type) {
	case Allow:
		return authn.LoginFlowAllow{}
	case Pass:
		return authn.LoginFlowPass{}
	case Deny:
		return authn.LoginFlowDeny{Reason: v.Reason}
	case Require:
		// Project the Decider-returned Step lazily. If the Step is
		// not registered in the compiled flow's byKind map, the
		// orchestrator surfaces ErrInvalidStep rather than
		// dynamically extending the flow.
		if v.Step == nil {
			return authn.LoginFlowPass{}
		}
		return authn.LoginFlowRequire{
			Step: authn.LoginFlowStep{Kind: string(v.Step.Kind())},
		}
	default:
		return authn.LoginFlowPass{}
	}
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
		Features:                  buildFeatures(cfg.features),
		GrantsSupported:           grantStrings,
		ScopesSupported:           scopes.PublicNames(),
		ProfileAllowedAuthMethods: cfg.profileAllowedAuthMethodNames(),
	}
}

// profileAllowedAuthMethodNames returns the intersection of every
// active [profile.Profile]'s [profile.AllowedClientAuthMethods] as
// raw method names, suitable for [discovery.Input]. Returns nil
// when no profile constrains client authentication.
//
// When multiple profiles are active the result is the intersection
// of every profile's allowed list — the most restrictive policy
// wins, matching the "stricter MAY override looser" posture used
// elsewhere in the configuration. The wire list keeps mTLS methods
// (tls_client_auth / self_signed_tls_client_auth) because they are
// advertised in discovery even though the [clientauth] package
// does not enforce them directly.
func (c *config) profileAllowedAuthMethodNames() []string {
	if len(c.profiles) == 0 {
		return nil
	}
	var allowed []string
	first := true
	for _, p := range c.profiles {
		methods := profile.AllowedClientAuthMethods(p)
		if methods == nil {
			continue
		}
		if first {
			allowed = methods
			first = false
			continue
		}
		allowed = intersectStrings(allowed, methods)
	}
	if first {
		return nil
	}
	return allowed
}

// intersectStrings returns the elements of a that also appear in b,
// preserving a's order. It exists as a free function so
// [config.profileAllowedAuthMethodNames] stays under the gocognit
// budget while remaining readable.
func intersectStrings(a, b []string) []string {
	out := make([]string, 0, len(a))
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
				break
			}
		}
	}
	return out
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

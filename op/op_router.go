package op

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/cors"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endsession"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/internal/introspectendpoint"
	"github.com/libraz/go-oidc-provider/internal/jwks"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/parendpoint"
	"github.com/libraz/go-oidc-provider/internal/registrationendpoint"
	"github.com/libraz/go-oidc-provider/internal/revokeendpoint"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/sector"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/internal/userinfo"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
)

// buildRouter assembles the [http.ServeMux] that backs [Provider.ServeHTTP].
// It registers the discovery, JWKS, authorize, token, and UserInfo
// handlers, plus the optional endpoints (PAR, introspect, revoke,
// /register, /end_session) gated on the configured features and
// grants.
func buildRouter(cfg *config, keySet *keys.Set, scopes *scoperegistry.Registry, locales *i18n.Resolver) (*http.ServeMux, error) {
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
	originAllow, err := buildOriginAllowlist(cfg)
	if err != nil {
		return nil, err
	}
	publicCORS := cors.NewPublic()
	strictCORS := cors.NewStrict(originAllow)
	mux.Handle(cfg.endpoints.Discovery, publicCORS.Handler(discHandler))
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.JWKS),
		publicCORS.Handler(jwks.HandlerWithOptions(keySet, jwks.HandlerOptions{
			RotationActive: cfg.jwksRotationActive,
		})),
	)
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.UserInfo),
		strictCORS.Handler(userinfo.Handler(userinfo.HandlerDeps{
			Keys:               keySet,
			Issuer:             cfg.issuer,
			UserStore:          cfg.store.Users(),
			Grants:             cfg.store.Grants(),
			Clock:              cfg.clock,
			Leeway:             defaultUserInfoLeeway,
			DPoP:               dpopVerifier,
			DPoPNonces:         cfg.dpopNonces, // nil leaves the use_dpop_nonce challenge disabled.
			MTLS:               mtlsVerifier,
			AccessTokens:       cfg.store.AccessTokens(),
			OpaqueAccessTokens: cfg.store.OpaqueAccessTokens(),
			GrantRevocations:   cfg.store.GrantRevocations(),
			RevocationStrategy: cfg.atRevocation,
		})),
	)
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.Token),
		strictCORS.Handler(tokenendpoint.Handler(tokenendpoint.Deps{
			Issuer:                         cfg.issuer,
			Clients:                        cfg.store.Clients(),
			Codes:                          cfg.store.AuthorizationCodes(),
			RefreshTokens:                  cfg.store.RefreshTokens(),
			Grants:                         cfg.store.Grants(),
			UserStore:                      cfg.store.Users(),
			Keys:                           keySet,
			Clock:                          cfg.clock,
			Scopes:                         scopes,
			DPoP:                           dpopVerifier,
			DPoPNonces:                     cfg.dpopNonces, // nil leaves the use_dpop_nonce challenge disabled.
			MTLS:                           mtlsVerifier,
			AssertionVerifier:              assertionVerifier,
			AccessTokenTTL:                 cfg.accessTokenTTL,
			RefreshTokenTTL:                cfg.refreshTokenTTL,
			RefreshTokenOfflineTTL:         cfg.refreshTokenOfflineTTL,
			RefreshTokenGraceTTL:           cfg.effectiveRefreshGrace(),
			StrictOfflineAccess:            cfg.strictOfflineAccess,
			AllowedClientAuthMethods:       cfg.allowedClientAuthMethods(),
			RequireSenderConstrainedTokens: cfg.requireSenderConstrainedTokens(),
			AccessTokens:                   cfg.store.AccessTokens(),
			OpaqueAccessTokens:             cfg.store.OpaqueAccessTokens(),
			AccessTokenFormatFor:           cfg.formatForAudience,
			GrantRevocations:               cfg.store.GrantRevocations(),
			RevocationStrategy:             cfg.atRevocation,
			Audit:                          cfg.effectiveAuditEmitter(),
		})),
	)
	sessMgr, err := mountAuthorizeHandlers(mux, cfg, scopes, keySet, originAllow, strictCORS, locales)
	if err != nil {
		return nil, err
	}
	if err := mountPAREndpoint(mux, cfg, scopes, assertionVerifier, dpopVerifier, strictCORS); err != nil {
		return nil, err
	}
	mountIntrospectionEndpoint(mux, cfg, scopes, keySet, assertionVerifier, strictCORS)
	mountRevocationEndpoint(mux, cfg, keySet, assertionVerifier, strictCORS)
	mountRegistrationEndpoint(mux, cfg, scopes, strictCORS)
	bcc, err := buildBackchannelCoordinator(cfg, keySet)
	if err != nil {
		return nil, err
	}
	mountEndSessionEndpoint(mux, cfg, keySet, sessMgr, bcc, strictCORS)
	return mux, nil
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
func mountRegistrationEndpoint(mux *http.ServeMux, cfg *config, scopes *scoperegistry.Registry, strictCORS *cors.Strict) {
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
		PairwiseEnabled:          cfg.pairwiseEnabled(),
		AllowLocalhostLoopback:   cfg.allowLocalhostLoopback,
		SectorResolver:           buildSectorResolver(cfg),
		ValidateMetadata:         wrapValidateMetadata(cfg.dcr.ValidateMetadata),
		Logger:                   cfg.logger,
		Audit:                    cfg.effectiveAuditEmitter(),
		OnClientDeleted:          cfg.dcr.OnClientDeleted,
	}
	handler := strictCORS.Handler(registrationendpoint.Handler(deps))
	registerPath := joinPath(cfg.mountPrefix, cfg.endpoints.Register)
	mux.Handle(registerPath, handler)
	mux.Handle(registerPath+"/{client_id}", handler)
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
	strictCORS *cors.Strict,
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
		strictCORS.Handler(parendpoint.Handler(parendpoint.Deps{
			Issuer:                     cfg.issuer,
			Clients:                    cfg.store.Clients(),
			PARs:                       cfg.store.PushedAuthRequests(),
			Scopes:                     scopes,
			Clock:                      cfg.clock,
			JAR:                        jarVerifier,
			DPoP:                       dpopVerifier,
			DPoPNonces:                 cfg.dpopNonces, // nil leaves the use_dpop_nonce challenge disabled.
			AssertionVerifier:          assertionVerifier,
			AllowedClientAuthMethods:   cfg.allowedClientAuthMethods(),
			RequirePKCE:                cfg.requirePKCE(),
			RequireNonce:               cfg.requireNonce(),
			RequireStateOrNonce:        cfg.requireStateOrNonce(),
			RequireSignedRequestObject: cfg.requireSignedRequestObject(),
			OpenIDScopeOptional:        cfg.openIDScopeOptional,
			ClaimsParameterEnabled:     cfg.claimsParameterSupported(),
			Audit:                      cfg.effectiveAuditEmitter(),
		})),
	)
	return nil
}

// mountIntrospectionEndpoint registers the /introspect handler when the
// [feature.Introspect] flag is enabled.
func mountIntrospectionEndpoint(
	mux *http.ServeMux,
	cfg *config,
	scopes *scoperegistry.Registry,
	keySet *keys.Set,
	assertionVerifier clientauth.AssertionVerifier,
	strictCORS *cors.Strict,
) {
	if !featureEnabled(cfg.features, feature.Introspect) {
		return
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.Introspect),
		strictCORS.Handler(introspectendpoint.Handler(introspectendpoint.Deps{
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
			AccessTokens:               cfg.store.AccessTokens(),
			OpaqueAccessTokens:         cfg.store.OpaqueAccessTokens(),
			GrantRevocations:           cfg.store.GrantRevocations(),
			RevocationStrategy:         cfg.atRevocation,
			Audit:                      cfg.effectiveAuditEmitter(),
		})),
	)
}

// mountRevocationEndpoint registers the /revoke handler when the
// [feature.Revoke] flag is enabled.
func mountRevocationEndpoint(
	mux *http.ServeMux,
	cfg *config,
	keySet *keys.Set,
	assertionVerifier clientauth.AssertionVerifier,
	strictCORS *cors.Strict,
) {
	if !featureEnabled(cfg.features, feature.Revoke) {
		return
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.Revoke),
		strictCORS.Handler(revokeendpoint.Handler(revokeendpoint.Deps{
			Issuer:                   cfg.issuer,
			Clients:                  cfg.store.Clients(),
			RefreshTokens:            cfg.store.RefreshTokens(),
			Keys:                     keySet,
			Clock:                    cfg.clock,
			AssertionVerifier:        assertionVerifier,
			AllowedClientAuthMethods: cfg.allowedClientAuthMethods(),
			AccessTokens:             cfg.store.AccessTokens(),
			OpaqueAccessTokens:       cfg.store.OpaqueAccessTokens(),
			GrantRevocations:         cfg.store.GrantRevocations(),
			RevocationStrategy:       cfg.atRevocation,
			Audit:                    cfg.effectiveAuditEmitter(),
		})),
	)
}

// mountAuthorizeHandlers wires the /authorize and /interaction routes.
// Returns a [*sessions.Manager] reused by [mountEndSessionEndpoint], or
// nil when the configured grants do not require the authorize endpoint.
func mountAuthorizeHandlers(
	mux *http.ServeMux,
	cfg *config,
	scopes *scoperegistry.Registry,
	keySet *keys.Set,
	allow *csrf.Allowlist,
	strictCORS *cors.Strict,
	locales *i18n.Resolver,
) (*sessions.Manager, error) {
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
	orchestrator, err := buildOrchestrator(cfg, sessMgr)
	if err != nil {
		return nil, err
	}
	authorizePath := joinPath(cfg.mountPrefix, cfg.endpoints.Authorize)
	interactionPath := joinPath(cfg.mountPrefix, cfg.endpoints.Interaction)
	spaLoginMount, spaStaticDir := spaWiringFor(cfg)
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
		SPALoginMount:           spaLoginMount,
		SPAStaticDir:            spaStaticDir,
		Clock:                   cfg.clock,
		RequireJARMResponseMode: cfg.requireJARMResponseMode(),
		RequirePKCE:             cfg.requirePKCE(),
		RequireNonce:            cfg.requireNonce(),
		RequireStateOrNonce:     cfg.requireStateOrNonce(),
		RequirePAR:              cfg.requirePAR(),
		Issuer:                  cfg.issuer,
		AllowPrivateNetworkJAR:  cfg.allowPrivateNetworkJAR,
		OpenIDScopeOptional:     cfg.openIDScopeOptional,
		ClaimsParameterEnabled:  cfg.claimsParameterSupported(),
		ACRResolver:             newACRResolver(cfg),
		LocaleResolver:          locales,
		SubjectProjector:        buildSubjectProjector(cfg),
	})
	mux.Handle(authorizePath, handler)
	if spaLoginMount == "" {
		mux.Handle(interactionPath+"/{uid}", strictCORS.Handler(handler))
	} else {
		mux.Handle(spaLoginMount+"/state/{uid}", strictCORS.Handler(handler))
		mux.Handle(spaLoginMount+"/{uid}", handler)
		if spaStaticDir != "" {
			mux.Handle(spaLoginMount+"/assets/{path...}", handler)
		}
	}
	return sessMgr, nil
}

// mountEndSessionEndpoint registers the /end_session handler.
func mountEndSessionEndpoint(
	mux *http.ServeMux,
	cfg *config,
	keySet *keys.Set,
	sessMgr *sessions.Manager,
	bcc *backchannel.Coordinator,
	strictCORS *cors.Strict,
) {
	if sessMgr == nil {
		return
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.EndSession),
		strictCORS.Handler(endsession.Handler(endsession.Deps{
			Issuer:             cfg.issuer,
			Clients:            cfg.store.Clients(),
			Sessions:           sessMgr,
			Keys:               keySet,
			Clock:              cfg.clock,
			Backchannel:        bcc,
			Grants:             cfg.store.Grants(),
			AccessTokens:       cfg.store.AccessTokens(),
			OpaqueAccessTokens: cfg.store.OpaqueAccessTokens(),
			AccessTokenTTL:     cfg.accessTokenTTL,
			GrantRevocations:   cfg.store.GrantRevocations(),
			RevocationStrategy: cfg.atRevocation,
		})),
	)
}

// joinPath concatenates mountPrefix and endpoint into a full path, handling
// the slash-collapsing edge cases that http.ServeMux is strict about.
func joinPath(mountPrefix, endpoint string) string {
	if mountPrefix == "/" {
		return endpoint
	}
	return mountPrefix + endpoint
}

// buildSectorResolver constructs the [sector.Resolver] the DCR
// validator drives at registration time. The resolver inherits the
// embedder clock so a frozen-clock test fixture sees deterministic
// cache TTL bookkeeping, and honours the
// [WithAllowPrivateNetworkSector] opt-in for embedders that host
// their RPs on a private network. Construction is unconditional —
// even DCR registrations that omit sector_identifier_uri pay only
// the resolver allocation, and the validator short-circuits on the
// empty value.
func buildSectorResolver(cfg *config) *sector.Resolver {
	opts := []sector.Option{sector.WithClock(cfg.clock)}
	if cfg.allowPrivateNetworkSector {
		opts = append(opts, sector.AllowPrivateNetwork())
	}
	return sector.New(opts...)
}

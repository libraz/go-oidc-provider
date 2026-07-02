package op

import (
	"context"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/cibaendpoint"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/cors"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/devicecodeendpoint"
	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endsession"
	"github.com/libraz/go-oidc-provider/internal/grantmgmtendpoint"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/internal/introspectendpoint"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/jwks"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/parendpoint"
	"github.com/libraz/go-oidc-provider/internal/protectedresource"
	"github.com/libraz/go-oidc-provider/internal/proxy"
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
func buildRouter(cfg *config, keySet *keys.Set, encSet *keys.EncryptionSet, scopes *scoperegistry.Registry, locales *i18n.Resolver, proxyTrust *proxy.Trust) (*http.ServeMux, error) {
	mux := http.NewServeMux()
	doc := discovery.Build(buildDiscoveryInput(cfg, scopes, locales))
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
	assertionVerifiers, err := buildAssertionVerifiers(cfg)
	if err != nil {
		return nil, err
	}
	jarVerifier, err := buildJARVerifier(cfg, encSet)
	if err != nil {
		return nil, err
	}
	originAllow, err := buildOriginAllowlist(cfg)
	if err != nil {
		return nil, err
	}
	publicCORS := cors.NewPublic()
	strictCORS := cors.NewStrict(originAllow, cfg.effectiveAuditEmitter())
	encResolver := buildClientEncryptionResolver(cfg)
	var subjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error)
	if cfg.subjectGeneratorSource != "" {
		subjectProjector = buildSubjectProjector(cfg)
	}
	mux.Handle(cfg.endpoints.Discovery, publicCORS.Handler(discHandler))
	if err := mountProtectedResourceMetadata(mux, cfg, publicCORS); err != nil {
		return nil, err
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.JWKS),
		publicCORS.Handler(jwks.HandlerWithOptions(keySet, jwks.HandlerOptions{
			RotationActive: cfg.jwksRotationActive,
			EncryptionSet:  encSet,
		})),
	)
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.UserInfo),
		strictCORS.Handler(userinfo.Handler(userinfo.HandlerDeps{
			Keys:               keySet,
			Issuer:             cfg.issuer,
			Clients:            cfg.store.Clients(),
			UserStore:          cfg.store.Users(),
			Grants:             cfg.store.Grants(),
			SubjectProjector:   subjectProjector,
			Clock:              cfg.clock,
			Leeway:             defaultUserInfoLeeway,
			CustomScopeClaims:  customScopeClaims(cfg.scopes),
			DPoP:               dpopVerifier,
			DPoPNonces:         cfg.dpopNonces, // nil leaves the use_dpop_nonce challenge disabled.
			MTLS:               mtlsVerifier,
			AccessTokens:       cfg.store.AccessTokens(),
			OpaqueAccessTokens: cfg.store.OpaqueAccessTokens(),
			GrantRevocations:   cfg.store.GrantRevocations(),
			RevocationStrategy: cfg.atRevocation,
			ClientEncJWKs:      encResolver,
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
			SubjectProjector:               subjectProjector,
			Keys:                           keySet,
			Clock:                          cfg.clock,
			Scopes:                         scopes,
			AuthorizationDetailTypes:       authorizationDetailRegistry(cfg),
			DPoP:                           dpopVerifier,
			DPoPNonces:                     cfg.dpopNonces, // nil leaves the use_dpop_nonce challenge disabled.
			MTLS:                           mtlsVerifier,
			AssertionVerifier:              assertionVerifiers.Token,
			AccessTokenTTL:                 cfg.accessTokenTTL,
			RefreshTokenTTL:                cfg.refreshTokenTTL,
			RefreshTokenOfflineTTL:         cfg.refreshTokenOfflineTTL,
			RefreshTokenGraceTTL:           cfg.effectiveRefreshGrace(),
			StrictOfflineAccess:            cfg.strictOfflineAccess,
			GrantManagementEnabled:         cfg.grantManagementEnabled,
			AllowedClientAuthMethods:       cfg.allowedClientAuthMethods(),
			RequireSenderConstrainedTokens: cfg.requireSenderConstrainedTokens(),
			AccessTokens:                   cfg.store.AccessTokens(),
			OpaqueAccessTokens:             cfg.store.OpaqueAccessTokens(),
			AccessTokenFormatFor:           cfg.formatForAudience,
			GrantRevocations:               cfg.store.GrantRevocations(),
			RevocationStrategy:             cfg.atRevocation,
			Audit:                          cfg.effectiveAuditEmitter(),
			CustomGrants:                   buildExtensionDispatcher(cfg, keySet),
			DeviceCodes:                    deviceCodesFor(cfg),
			CIBARequests:                   cibaRequestsFor(cfg),
			CIBAMaxPollViolations:          cfg.cibaMaxPollViolations,
			ClientEncJWKs:                  encResolver,
		})),
	)
	mountDeviceAuthorizationEndpoint(mux, cfg, scopes, dpopVerifier, mtlsVerifier, assertionVerifiers.Device, strictCORS)
	mountBackchannelAuthenticationEndpoint(mux, cfg, scopes, dpopVerifier, mtlsVerifier, assertionVerifiers.Backchannel, jarVerifier, strictCORS)
	sessMgr, err := mountAuthorizeHandlers(mux, cfg, scopes, keySet, encResolver, jarVerifier, originAllow, strictCORS, locales, proxyTrust)
	if err != nil {
		return nil, err
	}
	if err := mountPAREndpoint(mux, cfg, scopes, jarVerifier, assertionVerifiers.PAR, dpopVerifier, strictCORS); err != nil {
		return nil, err
	}
	mountIntrospectionEndpoint(mux, cfg, scopes, keySet, encResolver, assertionVerifiers.Introspect, subjectProjector, strictCORS)
	mountRevocationEndpoint(mux, cfg, keySet, assertionVerifiers.Revoke, strictCORS)
	mountGrantManagementEndpoint(mux, cfg, assertionVerifiers.Revoke, strictCORS)
	mountRegistrationEndpoint(mux, cfg, scopes, strictCORS)
	bcc, err := buildBackchannelCoordinator(cfg, keySet)
	if err != nil {
		return nil, err
	}
	mountEndSessionEndpoint(mux, cfg, keySet, sessMgr, bcc, strictCORS)
	return mux, nil
}

// mountProtectedResourceMetadata registers one read-only RFC 9728
// /.well-known/oauth-protected-resource handler per resource server
// configured through [WithProtectedResources]. Without the option no
// route is added. The well-known documents live at the OP root (not
// behind [WithMountPrefix]) because RFC 9728 §3 fixes their location, so
// the path is used verbatim rather than via [joinPath]. The OP issuer is
// stamped into authorization_servers for every document.
func mountProtectedResourceMetadata(mux *http.ServeMux, cfg *config, publicCORS *cors.Public) error {
	for i := range cfg.protectedResources {
		pr := cfg.protectedResources[i]
		doc := protectedresource.Build(protectedresource.Input{
			Resource:                          pr.Resource,
			Issuer:                            cfg.issuer,
			ScopesSupported:                   pr.ScopesSupported,
			BearerMethodsSupported:            pr.BearerMethodsSupported,
			ResourceSigningAlgValuesSupported: pr.ResourceSigningAlgValuesSupported,
			JWKSURI:                           pr.JWKSURI,
			ResourceDocumentation:             pr.ResourceDocumentation,
		})
		handler, err := protectedresource.Handler(doc)
		if err != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "protected-resource metadata failed to marshal for " + pr.Resource,
				Cause:       err,
			}
		}
		mux.Handle(protectedresource.WellKnownPath(pr.Resource), publicCORS.Handler(handler))
	}
	return nil
}

// mountGrantManagementEndpoint registers the OAuth 2.0 Grant Management
// draft endpoint (GET / DELETE {endpoint}/{grant_id}) when the feature is
// enabled via [WithGrantManagement]. Without the option no route is added;
// discovery gates the advertisement on the same condition.
func mountGrantManagementEndpoint(mux *http.ServeMux, cfg *config, assertionVerifier clientauth.AssertionVerifier, strictCORS *cors.Strict) {
	if !cfg.grantManagementEnabled {
		return
	}
	handler := strictCORS.Handler(grantmgmtendpoint.Handler(grantmgmtendpoint.Deps{
		Clients:                  cfg.store.Clients(),
		Grants:                   cfg.store.Grants(),
		RefreshTokens:            cfg.store.RefreshTokens(),
		OpaqueAccessTokens:       cfg.store.OpaqueAccessTokens(),
		AccessTokens:             cfg.store.AccessTokens(),
		GrantRevocations:         cfg.store.GrantRevocations(),
		RevocationStrategy:       cfg.atRevocation,
		AccessTokenTTL:           cfg.accessTokenTTL,
		Audit:                    cfg.effectiveAuditEmitter(),
		SecretVerifier:           nil, // handler installs the Argon2id default.
		AssertionVerifier:        assertionVerifier,
		AllowedClientAuthMethods: cfg.allowedClientAuthMethods(),
		QueryEnabled:             cfg.grantManagementActionEnabled(GrantActionQuery),
		RevokeEnabled:            cfg.grantManagementActionEnabled(GrantActionRevoke),
		Clock:                    cfg.clock,
	}))
	base := joinPath(cfg.mountPrefix, cfg.endpoints.GrantManagement)
	mux.Handle(base+"/{grant_id}", handler)
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
		Issuer:                               cfg.issuer,
		MountPrefix:                          cfg.mountPrefix,
		RegisterPath:                         cfg.endpoints.Register,
		Clock:                                cfg.clock,
		Clients:                              registry,
		InitialAccessTokens:                  cfg.store.InitialAccessTokens(),
		RegistrationAccessTokens:             cfg.store.RegistrationAccessTokens(),
		Scopes:                               scopes,
		Open:                                 cfg.dcr.Open,
		OpenRegistrationDefaultScopes:        append([]string(nil), cfg.dcr.OpenRegistrationDefaultScopes...),
		AllowedGrantTypes:                    append([]string(nil), cfg.dcr.AllowedGrantTypes...),
		AllowedResponseTypes:                 append([]string(nil), cfg.dcr.AllowedResponseTypes...),
		PairwiseEnabled:                      cfg.pairwiseEnabled(),
		AllowLocalhostLoopback:               cfg.allowLocalhostLoopback,
		AllowInsecureBackchannelLogoutForDev: cfg.allowInsecureBackchannelLogoutForDev,
		SectorResolver:                       buildSectorResolver(cfg),
		ValidateMetadata:                     wrapValidateMetadata(cfg.dcr.ValidateMetadata),
		Logger:                               cfg.logger,
		Audit:                                cfg.effectiveAuditEmitter(),
		OnClientDeleted:                      cfg.dcr.OnClientDeleted,
		RefreshTokens:                        cfg.store.RefreshTokens(),
		Grants:                               cfg.store.Grants(),
		AccessTokens:                         cfg.store.AccessTokens(),
		OpaqueAccessTokens:                   cfg.store.OpaqueAccessTokens(),
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
//
// The JAR verifier is built once at the router scope so /par,
// /authorize, and /bc-authorize share the same instance (one JTI
// replay-defence pool, one HTTP-fetch client, one resolver cache).
// A nil verifier signals that [feature.JAR] is off; the PAR handler
// surfaces invalid_request_object for any inbound request that
// carries a "request" parameter.
func mountPAREndpoint(
	mux *http.ServeMux,
	cfg *config,
	scopes *scoperegistry.Registry,
	jarVerifier *jar.Verifier,
	assertionVerifier clientauth.AssertionVerifier,
	dpopVerifier *dpop.Verifier,
	strictCORS *cors.Strict,
) error {
	if !featureEnabled(cfg.features, feature.PAR) {
		return nil
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.PAR),
		strictCORS.Handler(parendpoint.Handler(parendpoint.Deps{
			Issuer:                        cfg.issuer,
			Clients:                       cfg.store.Clients(),
			PARs:                          cfg.store.PushedAuthRequests(),
			Scopes:                        scopes,
			AuthorizationDetailTypes:      authorizationDetailRegistry(cfg),
			Clock:                         cfg.clock,
			JAR:                           jarVerifier,
			DPoP:                          dpopVerifier,
			DPoPNonces:                    cfg.dpopNonces, // nil leaves the use_dpop_nonce challenge disabled.
			AssertionVerifier:             assertionVerifier,
			AllowedClientAuthMethods:      cfg.allowedClientAuthMethods(),
			RequirePKCE:                   cfg.requirePKCE(),
			RequireNonce:                  cfg.requireNonce(),
			RequireStateOrNonce:           cfg.requireStateOrNonce(),
			RequireSignedRequestObject:    cfg.requireSignedRequestObject(),
			OpenIDScopeOptional:           cfg.openIDScopeOptional,
			ClaimsParameterEnabled:        cfg.claimsParameterSupported(),
			Audit:                         cfg.effectiveAuditEmitter(),
			GrantManagementEnabled:        cfg.grantManagementEnabled,
			GrantManagementActions:        grantManagementActionSet(cfg),
			GrantManagementActionRequired: cfg.grantManagementActionRequired,
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
	encResolver *clientencjwks.Resolver,
	assertionVerifier clientauth.AssertionVerifier,
	subjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error),
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
			Grants:                     cfg.store.Grants(),
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
			ClientEncJWKs:              encResolver,
			SubjectProjector:           subjectProjector,
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
//
// The JAR verifier is built once at the router scope (see
// [buildRouter]) so /par, /authorize, and /bc-authorize share the
// same instance. A nil verifier signals that [feature.JAR] is off;
// the authorize handler treats it as "request_uri / request not
// supported" rather than panicking.
func mountAuthorizeHandlers(
	mux *http.ServeMux,
	cfg *config,
	scopes *scoperegistry.Registry,
	keySet *keys.Set,
	encResolver *clientencjwks.Resolver,
	jarVerifier *jar.Verifier,
	allow *csrf.Allowlist,
	strictCORS *cors.Strict,
	locales *i18n.Resolver,
	proxyTrust *proxy.Trust,
) (*sessions.Manager, error) {
	if !grantsRequireAuthorizeEndpoint(cfg.grants) {
		return nil, nil //nolint:nilnil // documented "no manager needed" sentinel.
	}
	jarmSigner, err := buildJARMSigner(cfg, keySet)
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
		Clients:                       cfg.store.Clients(),
		Codes:                         cfg.store.AuthorizationCodes(),
		Grants:                        cfg.store.Grants(),
		AuthorizationDetailTypes:      authorizationDetailRegistry(cfg),
		GrantManagementEnabled:        cfg.grantManagementEnabled,
		GrantManagementActions:        grantManagementActionSet(cfg),
		GrantManagementActionRequired: cfg.grantManagementActionRequired,
		Interactions:                  cfg.store.Interactions(),
		PARs:                          authorizePARStore(cfg),
		JARM:                          jarmSigner,
		JAR:                           jarVerifier,
		Sessions:                      sessMgr,
		CookieCodec:                   cookieCodec,
		CSRF:                          csrfSigner,
		Origins:                       allow,
		Driver:                        cfg.interactionD,
		Authn:                         orchestrator,
		Scopes:                        scopes,
		AuthorizePath:                 authorizePath,
		InteractionPath:               interactionPath,
		SPALoginMount:                 spaLoginMount,
		SPAStaticDir:                  spaStaticDir,
		Clock:                         cfg.clock,
		RequireJARMResponseMode:       cfg.requireJARMResponseMode(),
		RequirePKCE:                   cfg.requirePKCE(),
		RequireNonce:                  cfg.requireNonce(),
		RequireStateOrNonce:           cfg.requireStateOrNonce(),
		RequirePAR:                    cfg.requirePAR(),
		Issuer:                        cfg.issuer,
		AllowPrivateNetworkJAR:        cfg.allowPrivateNetworkJAR,
		OpenIDScopeOptional:           cfg.openIDScopeOptional,
		ClaimsParameterEnabled:        cfg.claimsParameterSupported(),
		ACRResolver:                   newACRResolver(cfg),
		LocaleResolver:                locales,
		ProxyTrust:                    proxyTrust,
		ClientEncJWKs:                 encResolver,
		FirstPartyClients:             firstPartyClientSet(cfg),
		Audit:                         cfg.effectiveAuditEmitter(),
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
			Audit:              cfg.effectiveAuditEmitter(),
		})),
	)
}

// mountDeviceAuthorizationEndpoint registers the
// /device_authorization handler when the device_code grant is
// configured (via [WithDeviceCodeGrant] or by including
// [grant.DeviceCode] in [WithGrants]). The mount is gated on the
// resolved grant configuration so a deployment that does not enable
// the grant keeps the route absent — the discovery document advertises
// the endpoint with the same gating, so the OP cannot tell clients the
// endpoint exists while quietly serving 404.
//
// The substore is reached through [deviceCodesFor];
// [validateDeviceCodeGrant] runs ahead of the router so a
// configured grant without a wired substore is rejected at
// construction time. The handler retains a defensive nil guard so
// any residual misconfiguration surfaces as 500 server_error
// rather than a nil-interface panic.
func mountDeviceAuthorizationEndpoint(
	mux *http.ServeMux,
	cfg *config,
	scopes *scoperegistry.Registry,
	dpopVerifier *dpop.Verifier,
	mtlsVerifier *mtls.Verifier,
	assertionVerifier clientauth.AssertionVerifier,
	strictCORS *cors.Strict,
) {
	if !cfg.deviceCodeGrantConfigured() {
		return
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.DeviceAuthorization),
		strictCORS.Handler(devicecodeendpoint.Handler(devicecodeendpoint.Deps{
			Issuer:                   cfg.issuer,
			VerificationURI:          cfg.effectiveDeviceVerificationURI(),
			Clients:                  cfg.store.Clients(),
			DeviceCodes:              deviceCodesFor(cfg),
			Scopes:                   scopes,
			Clock:                    cfg.clock,
			AssertionVerifier:        assertionVerifier,
			AllowedClientAuthMethods: cfg.allowedClientAuthMethods(),
			DPoP:                     dpopVerifier,
			DPoPNonces:               cfg.dpopNonces,
			MTLS:                     mtlsVerifier,
			RequireSenderConstraint:  cfg.requireSenderConstrainedTokens(),
			DeviceCodeTTL:            cfg.effectiveDeviceCodeExpiry(),
			PollInterval:             cfg.effectiveDeviceCodePollInterval(),
			Audit:                    cfg.effectiveAuditEmitter(),
		})),
	)
}

// deviceCodesFor returns the [store.DeviceCodeStore] the device-flow
// surfaces consume. The function exists so the token-endpoint mount
// and the device-authorization mount share an identical resolution
// path. [validateDeviceCodeGrant] guarantees the substore is non-nil
// whenever the grant is configured, but the helper still tolerates
// a nil Store so the no-grant boot path (where the dispatch never
// reaches the device-flow branch) does not require a fully-wired
// store.
func deviceCodesFor(cfg *config) store.DeviceCodeStore {
	if cfg.store == nil {
		return nil
	}
	return cfg.store.DeviceCodes()
}

// cibaRequestsFor returns the [store.CIBARequestStore] the CIBA
// surfaces consume. The function mirrors [deviceCodesFor]:
// [validateCIBAGrant] guarantees the substore is non-nil whenever
// the CIBA grant is configured, but the helper still tolerates a
// nil Store so the no-grant boot path is unaffected.
func cibaRequestsFor(cfg *config) store.CIBARequestStore {
	if cfg.store == nil {
		return nil
	}
	return cfg.store.CIBARequests()
}

// cibaHintResolverAdapter bridges the public [HintResolver] surface
// onto the internal [cibaendpoint.HintResolver] interface. The two
// have identical method signatures (HintKind is a type alias) but
// the wrapper preserves the public/internal split so a future
// internal-only refactor cannot leak through the public option.
type cibaHintResolverAdapter struct {
	r HintResolver
}

// Resolve forwards to the wrapped public resolver.
func (a cibaHintResolverAdapter) Resolve(ctx context.Context, kind ciba.HintKind, value string) (string, error) {
	return a.r.Resolve(ctx, kind, value)
}

// mountBackchannelAuthenticationEndpoint registers the /bc-authorize
// handler when the CIBA grant is configured (via [WithCIBA] or by
// including [grant.CIBA] in [WithGrants]). The mount is gated on
// the resolved grant configuration so a deployment that does not
// enable the grant keeps the route absent — the discovery document
// advertises the endpoint with the same gating, so the OP cannot
// tell clients the endpoint exists while quietly serving 404.
//
// The substore is reached through [cibaRequestsFor];
// [validateCIBAGrant] runs ahead of the router so a configured
// grant without a wired substore (or HintResolver) is rejected at
// construction time. The handler retains a defensive nil guard so
// any residual misconfiguration surfaces as 500 server_error rather
// than a nil-interface panic.
//
// The JAR verifier is built once at the router scope so /par,
// /authorize, and /bc-authorize share the same instance. A nil
// verifier signals that [feature.JAR] is off; the cibaendpoint
// handler surfaces invalid_request_object for any inbound request
// that carries a "request" parameter, and rejects requests under
// FAPI-CIBA (which mandates the parameter) with invalid_request.
func mountBackchannelAuthenticationEndpoint(
	mux *http.ServeMux,
	cfg *config,
	scopes *scoperegistry.Registry,
	dpopVerifier *dpop.Verifier,
	mtlsVerifier *mtls.Verifier,
	assertionVerifier clientauth.AssertionVerifier,
	jarVerifier *jar.Verifier,
	strictCORS *cors.Strict,
) {
	if !cfg.cibaGrantConfigured() {
		return
	}
	var resolver cibaendpoint.HintResolver
	if cfg.cibaHintResolver != nil {
		resolver = cibaHintResolverAdapter{r: cfg.cibaHintResolver}
	}
	mux.Handle(
		joinPath(cfg.mountPrefix, cfg.endpoints.Backchannel),
		strictCORS.Handler(cibaendpoint.Handler(cibaendpoint.Deps{
			Issuer:                   cfg.issuer,
			Clients:                  cfg.store.Clients(),
			CIBARequests:             cibaRequestsFor(cfg),
			Scopes:                   scopes,
			Clock:                    cfg.clock,
			AssertionVerifier:        assertionVerifier,
			AllowedClientAuthMethods: cfg.allowedClientAuthMethods(),
			DPoP:                     dpopVerifier,
			DPoPNonces:               cfg.dpopNonces,
			MTLS:                     mtlsVerifier,
			RequireSenderConstraint:  cfg.requireSenderConstrainedTokens(),
			JAR:                      jarVerifier,
			RequireSignedAuthRequest: cfg.requireSignedBackchannelRequest(),
			FAPICIBAProfileActive:    cfg.fapiCIBAProfileActive(),
			ACRValuesSupported:       cfg.acrValuesSupportedCopy(),
			HintResolver:             resolver,
			DefaultExpiresIn:         cfg.effectiveCIBADefaultExpiresIn(),
			MaxExpiresIn:             cfg.cibaMaxExpiresIn,
			PollInterval:             cfg.effectiveCIBAPollInterval(),
			Audit:                    cfg.effectiveAuditEmitter(),
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

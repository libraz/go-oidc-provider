package op

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/chooser"
	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/jarm"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/metrics"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/proxy"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
)

// buildMetricsCollector populates [config.metricsCollector] when
// [WithPrometheus] supplied a registry. The function builds the
// static-client allowlist and the endpoint-name reverse map up front
// so the bridge and the middleware see the same closed sets — adding
// an endpoint to the router without listing it here causes that
// endpoint's histogram observations to land in the "other" bucket
// rather than leaking the literal path as a label value.
//
// The collector is registered on the embedder-supplied registry; any
// AlreadyRegisteredError is surfaced as a configuration error so a
// double-construction in tests fails fast instead of corrupting the
// metric names.
func buildMetricsCollector(cfg *config) error {
	if cfg.promRegistry == nil {
		return nil
	}
	staticIDs := make(map[string]struct{}, len(cfg.staticClients))
	for i := range cfg.staticClients {
		staticIDs[cfg.staticClients[i].ID] = struct{}{}
	}
	collector, err := metrics.New(cfg.promRegistry, metrics.Options{
		StaticClientIDs: staticIDs,
	})
	if err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithPrometheus collector registration failed",
			Cause:       err,
		}
	}
	cfg.metricsCollector = collector
	return nil
}

// buildLocaleResolver assembles the [i18n.Resolver] from the seed
// bundles plus any embedder overrides registered through [WithLocale].
// Override entries are merged on top of the existing bundle for the
// same tag at key granularity: the embedder's keys win on collision,
// keys present only on the existing bundle are preserved. This means
// embedders override only the strings they care about without having
// to re-supply the entire seed catalogue. Layered [WithLocale] calls
// for the same tag compose by repeated merge, so the last call wins
// per key.
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
		tag := b.internal.Tag()
		if existing, exists := bundles[tag]; exists {
			merged, mergeErr := existing.Merge(b.internal)
			if mergeErr != nil {
				return nil, &Error{
					Code:        codeConfiguration,
					Description: "WithLocale: " + mergeErr.Error(),
					Cause:       mergeErr,
				}
			}
			bundles[tag] = merged
			continue
		}
		order = append(order, tag)
		bundles[tag] = b.internal
	}
	merged := make([]*i18n.Bundle, 0, len(order))
	for _, t := range order {
		merged = append(merged, bundles[t])
	}
	resolver, err := i18n.NewResolver(i18n.Tag(cfg.defaultLocale), merged...)
	if err != nil {
		return nil, err
	}
	if cfg.preferredLocaleStore != nil {
		resolver.WithPreferredLocaleStore(preferredLocaleStoreAdapter{store: cfg.preferredLocaleStore})
	}
	return resolver, nil
}

// buildProxyTrust constructs the runtime [proxy.Trust] consumed by the
// authorize endpoint to resolve the client IP / scheme / host through
// X-Forwarded-* headers when the request arrives from a trusted CIDR.
//
// The X-Forwarded-Host allowlist is the union of:
//
//   - the canonical issuer host derived from [WithIssuer] (auto-
//     included so the typical single-hostname deployment requires no
//     further configuration);
//   - explicit entries from [WithTrustedProxyHosts] (multi-hostname
//     deployments).
//
// When [WithTrustedProxies] is configured but the issuer is empty AND
// no explicit hosts were supplied, the function emits a startup WARN
// through the operational logger so the operator notices the gap. The
// returned trust still rejects every XFH in that case (the empty
// allowlist behaviour is preserved on the runtime side: [proxy.Trust]
// honours XFH only when the supplied host appears in the allowlist).
//
// A nil return is the documented "no proxy trusted" signal — the
// authorize endpoint passes a nil trust to [proxy.Resolve] which falls
// back to [http.Request.RemoteAddr] without consulting forwarded
// headers.
func buildProxyTrust(cfg *config) (*proxy.Trust, error) {
	if len(cfg.trustedProxies) == 0 {
		return nil, nil //nolint:nilnil // documented "no proxy trusted" sentinel.
	}
	hosts := append([]string(nil), cfg.trustedProxyHosts...)
	if h := issuerHost(cfg.issuer); h != "" {
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 && cfg.logger != nil {
		cfg.logger.Warn(
			"proxy: WithTrustedProxies configured without a host allowlist; X-Forwarded-Host will be ignored",
		)
	}
	t, err := proxy.NewTrustWithHosts(cfg.trustedProxies, hosts)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "proxy trust construction failed",
			Cause:       err,
		}
	}
	return t, nil
}

// issuerHost returns the lowercase host of the canonical issuer URL
// or "" when issuer is empty / malformed. The helper is split so the
// proxy-trust builder and any future runtime check (e.g., a future
// XFH-aware redirect validator) read the same canonical value.
func issuerHost(issuer string) string {
	if issuer == "" {
		return ""
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// buildOriginAllowlist composes the cross-origin allowlist consumed by both
// the strict CORS layer and the /authorize CSRF Origin gate. The list is the
// union of:
//
//   - explicit entries from [WithCORSOrigins] (cfg.corsOrigins);
//   - the OP's own canonical origin derived from cfg.issuer, so same-origin
//     fetches from the OP's hosted login UI never need to be enumerated;
//   - the canonical origin of every redirect_uri attached to a
//     [WithStaticClients] entry. SPAs commonly post to /token and /userinfo
//     from the same origin that hosts their `redirect_uri` callback page,
//     so admitting that origin keeps the CORS allowlist in lock-step with
//     the registered redirect URIs without forcing the embedder to repeat
//     them in [WithCORSOrigins]. Dynamically-registered clients are not
//     covered here; their origins must be enumerated through
//     [WithCORSOrigins] (or a future per-request CORS hook).
//
// The helper is idempotent: it tolerates a nil/empty list (= "deny all
// cross-origin", the safe default) and silently skips an issuer that fails
// canonicalisation (a malformed issuer is rejected earlier by config.validate,
// so the skip path is defensive only). Redirect URIs that fail canonicalisation
// (custom schemes such as `com.example.app:/cb`, opaque URIs, …) are skipped
// silently — the option layer already validated them at registration time and
// the allowlist only cares about web-style http(s) origins anyway.
func buildOriginAllowlist(cfg *config) (*csrf.Allowlist, error) {
	allowOrigins := append([]string(nil), cfg.corsOrigins...)
	if origin, oerr := csrf.CanonicalOrigin(cfg.issuer); oerr == nil {
		allowOrigins = append(allowOrigins, origin)
	}
	for i := range cfg.staticClients {
		for _, ru := range cfg.staticClients[i].RedirectURIs {
			origin, oerr := csrf.CanonicalOrigin(ru)
			if oerr != nil {
				// Non-web schemes (e.g. native-app custom schemes) are
				// fine on the redirect path but have no origin in the
				// CORS sense; skip them silently.
				continue
			}
			allowOrigins = append(allowOrigins, origin)
		}
	}
	allow, err := csrf.NewAllowlist(allowOrigins)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "csrf allowlist construction failed",
			Cause:       err,
		}
	}
	return allow, nil
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
		// Emitter is threaded so a future opt-in to the
		// AllowLooseMethodCase bridge surfaces the
		// dpop.loose_method_case_admitted audit signal through
		// the OP's normal emission chain. Today the verifier
		// runs in strict mode unless the embedder rebuilds it
		// directly, so the event is only observable when a
		// future option flips the flag — wiring the emitter
		// up-front avoids a partial wiring at that point.
		Emitter: cfg.effectiveAuditEmitter(),
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
// When the embedder configured [WithMTLSProxy] the recorded
// [mtls.ProxyConfig] is threaded into the verifier so the
// reverse-proxy header path is honoured. Embedders that did not call
// [WithMTLSProxy] get a zero [mtls.ProxyConfig], which restricts the
// trust path to TLS handshakes terminated at the OP.
//
//nolint:nilnil // (nil, nil) is the documented "mTLS not enabled" signal.
func buildMTLSVerifier(cfg *config) (*mtls.Verifier, error) {
	if !featureEnabled(cfg.features, feature.MTLS) {
		return nil, nil
	}
	v, err := mtls.NewVerifier(mtls.VerifierConfig{Proxy: loadMTLSProxyConfig(cfg)})
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
func buildJARVerifier(cfg *config, encSet *keys.EncryptionSet) (*jar.Verifier, error) {
	if !featureEnabled(cfg.features, feature.JAR) {
		return nil, nil
	}
	// FAPI 2.0 Message Signing §5.6 mandates "nbf" and a request-object
	// lifetime no longer than 60 minutes. The library implements that
	// bound symmetrically: exp must not be more than 60 minutes in the
	// future, and nbf must not be more than 60 minutes in the past. The
	// OFCS conformance modules
	// "ensure-request-object-with-exp-over-60-fails" and
	// "-with-nbf-over-60-fails" push the claim 70 minutes out and expect
	// rejection, while the happy-flow shape (nbf=now, exp=now+5min) sits
	// well within the cap. Baseline (where JAR is rarely exercised)
	// inherits the same posture so a deployment that opts in to JAR
	// without a Message-Signing-only switch still gets the bound. Other
	// JAR-enabling profiles inherit the relaxed (back-compat) behaviour.
	//
	// AllowMissingJTI stays true for OIDC Core / FAPI 2.0 baseline /
	// FAPI 2.0 Message Signing: RFC 9101 §6.1 marks "jti" as OPTIONAL on
	// the wire, RFC 9101 §10.8 uses SHOULD (not MUST) for AS-side jti
	// tracking, and the FAPI 2.0 Security Profile / FAPI 2.0 Message
	// Signing do not promote it to MUST either. Rejecting jti-less
	// request objects refuses spec-conformant clients (the OpenID
	// Foundation Conformance Suite emits jti-less request objects for
	// fapi2-message-signing); the §10.8 replay-defence floor is
	// preserved through the JTIs store, which the verifier still
	// consumes for every jti it does see.
	//
	// FAPI-CIBA flips the default: §5.2.2 of the FAPI-CIBA Profile
	// promotes jti from OPTIONAL to MUST on the backchannel
	// authentication request object, and OFCS' CIBA-13 row drives the
	// negative test "ensure-request-object-missing-jti-fails" against
	// it. The flag below tracks that requirement and applies only when
	// no other profile loosened the constraint.
	var (
		requireNbf      bool
		requireIAT      bool
		maxLifetime     time.Duration
		allowMissingJTI = true
	)
	for _, p := range cfg.profiles {
		if p == profile.FAPI2Baseline || p == profile.FAPI2MessageSigning || p == profile.FAPICIBA {
			requireNbf = true
			maxLifetime = 60 * time.Minute
		}
		if p == profile.FAPICIBA {
			allowMissingJTI = false
			requireIAT = true
		}
	}
	resolverOpts := []jar.ResolverOption{}
	if cfg.allowPrivateNetworkJWKS {
		resolverOpts = append(resolverOpts, jar.AllowPrivateNetwork())
	}
	if cfg.jwksHTTPTransport != nil {
		resolverOpts = append(resolverOpts, jar.WithBaseTransport(cfg.jwksHTTPTransport))
	}
	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:             cfg.issuer,
		Resolver:           jar.NewDefaultResolver(cfg.clock, resolverOpts...),
		Clock:              cfg.clock,
		RequireNbf:         requireNbf,
		RequireIAT:         requireIAT,
		JTIs:               cfg.store.ConsumedJTIs(),
		EncryptionResolver: jarEncryptionResolver(encSet),
		AllowMissingJTI:    allowMissingJTI,
		MaxLifetime:        maxLifetime,
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

// jarEncryptionResolver returns the [jar.EncryptionResolver] backing
// the verifier's JWE seam. A nil [keys.EncryptionSet] yields a nil
// resolver — the documented "JWE off" signal in
// [jar.VerifierConfig.EncryptionResolver]; without
// [WithEncryptionKeyset] no encrypted request object can be honoured
// and the verifier surfaces [jar.ErrEncryptionUnsupported] uniformly.
//
// Returning the typed-nil interface from a typed-nil concrete value
// would defeat the nil-check at the consumer (the verifier inspects
// the interface against nil), so the wrapper compares the concrete
// pointer first.
//
//nolint:ireturn // adapter that maps a typed-nil pointer to an untyped-nil interface for the verifier nil-check.
func jarEncryptionResolver(encSet *keys.EncryptionSet) jar.EncryptionResolver {
	if encSet == nil {
		return nil
	}
	return encSet
}

// buildClientEncryptionResolver constructs the [clientencjwks.Resolver]
// that the four outbound-encryption response paths (id_token /
// userinfo / JARM / introspection) consult to translate a client's
// registered (alg, enc) pair into a [jose.EncryptionRecipient]. The
// resolver shares its SSRF posture with the JAR JWKS fetcher: the
// [WithAllowPrivateNetworkJWKS] opt-in suppresses the deny-list for
// embedders fronting their RPs with private DNS. Construction is
// unconditional — a client that did not register encryption metadata
// surfaces [clientencjwks.ErrNoEncryptionConfigured] at request time
// and the consumer skips the JWE wrap, so the resolver only adds a
// constant-time sentinel check on the non-encryption path.
func buildClientEncryptionResolver(cfg *config) *clientencjwks.Resolver {
	return clientencjwks.New(clientencjwks.Config{
		Clock:               cfg.clock,
		AllowPrivateNetwork: cfg.allowPrivateNetworkJWKS,
	})
}

type assertionVerifiers struct {
	Token       *clientauth.PrivateKeyJWTVerifier
	PAR         *clientauth.PrivateKeyJWTVerifier
	Introspect  *clientauth.PrivateKeyJWTVerifier
	Revoke      *clientauth.PrivateKeyJWTVerifier
	Device      *clientauth.PrivateKeyJWTVerifier
	Backchannel *clientauth.PrivateKeyJWTVerifier
}

// buildAssertionVerifiers constructs endpoint-scoped
// [clientauth.PrivateKeyJWTVerifier] instances for every endpoint that
// authenticates clients. All instances share the same JWKS resolver and
// consumed-JTI store, but each endpoint gets its own expected audience
// set so an assertion minted for PAR cannot be replayed at revoke,
// introspection, device authorization, or token.
//
// The AS issuer remains accepted as an alias on every endpoint for FAPI
// 2.0 / RFC 7523bis compatibility. PAR additionally accepts the token
// endpoint URL: RFC 9126 §2 authenticates the PAR request as a token-
// endpoint client, so the token endpoint URL — the canonical
// client_assertion audience per RFC 7523 §3 / OIDC Core §9 — is a valid
// aud there. The directional protection is preserved: the token endpoint
// still does not accept the PAR-specific URL, and the shared consumed-JTI
// store blocks replay of a single assertion across endpoints. CIBA
// likewise accepts the token endpoint URL because CIBA Core 1.0 §7.1
// explicitly permits issuer, token endpoint URL, and backchannel
// authentication endpoint URL.
func buildAssertionVerifiers(cfg *config) (assertionVerifiers, error) {
	resolver, err := clientauth.NewStoreJWKSResolver(cfg.store.Clients())
	if err != nil {
		return assertionVerifiers{}, &Error{
			Code:        codeConfiguration,
			Description: "private_key_jwt JWKS resolver construction failed",
			Cause:       err,
		}
	}
	jwksFetcher := jar.NewFetcher(cfg.clock)
	if cfg.allowPrivateNetworkJWKS {
		jwksFetcher.SetAllowPrivate(true)
	}
	if cfg.jwksHTTPTransport != nil {
		jwksFetcher.SetBaseTransport(cfg.jwksHTTPTransport)
	}
	resolver.SetURLFetcher(jwksFetcher)
	tokenAud := absoluteEndpointURL(cfg, cfg.endpoints.Token)
	parAud := absoluteEndpointURL(cfg, cfg.endpoints.PAR)
	backchannelAud := absoluteEndpointURL(cfg, cfg.endpoints.Backchannel)
	return assertionVerifiers{
		Token:       buildAssertionVerifier(cfg, resolver, tokenAud, []string{cfg.issuer}),
		PAR:         buildAssertionVerifier(cfg, resolver, parAud, []string{cfg.issuer, tokenAud}),
		Introspect:  buildAssertionVerifier(cfg, resolver, tokenAud, []string{cfg.issuer}),
		Revoke:      buildAssertionVerifier(cfg, resolver, tokenAud, []string{cfg.issuer}),
		Device:      buildAssertionVerifier(cfg, resolver, tokenAud, []string{cfg.issuer}),
		Backchannel: buildAssertionVerifier(cfg, resolver, backchannelAud, []string{cfg.issuer, tokenAud}),
	}, nil
}

func buildAssertionVerifier(
	cfg *config,
	resolver clientauth.JWKSResolver,
	audience string,
	auxAudiences []string,
) *clientauth.PrivateKeyJWTVerifier {
	return &clientauth.PrivateKeyJWTVerifier{
		Resolver:     resolver,
		JTIStore:     cfg.store.ConsumedJTIs(),
		Audience:     audience,
		AuxAudiences: append([]string(nil), auxAudiences...),
		Clock:        cfg.clock.Now,
	}
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
	// The deliverer's SSRF gate refuses loopback / private-network
	// destinations by default. The dev opt-in suppresses the gate so
	// the in-process examples and CI fixtures can POST a logout token
	// at a stub RP bound to 127.0.0.1; the
	// [WithBackchannelAllowPrivateNetwork] knob retains its existing
	// service-mesh meaning. Either flag widens the gate, mirroring the
	// validator's accept-set.
	if cfg.allowInsecureBackchannelLogoutForDev || cfg.BackchannelAllowsPrivateNetwork() {
		deliverer.AllowPrivateNetwork = true
	}
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:                   cfg.issuer,
		Signing:                  backchannel.SigningKey{KeyID: active.KeyID, Signer: active.Signer},
		Clients:                  cfg.store.Clients(),
		Grants:                   cfg.store.Grants(),
		SubjectProjector:         backchannelSubjectProjector(cfg),
		Deliverer:                deliverer,
		Emitter:                  cfg.effectiveAuditEmitter(),
		Clock:                    cfg.clock,
		SessionDurabilityPosture: backchannelPostureFor(cfg.sessionDurabilityPosture),
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

func backchannelSubjectProjector(cfg *config) func(ctx context.Context, raw string, client *store.Client) (string, error) {
	if cfg.subjectGeneratorSource == "" {
		return nil
	}
	return buildSubjectProjector(cfg)
}

// backchannelPostureFor projects the public
// [SessionDurabilityPosture] enum onto the internal
// [backchannel.SessionDurabilityPosture] enum. The two carry the
// same semantics; the type duplication exists only because the
// internal package cannot import op (one-way import graph) and the
// public type must live alongside the option that records it.
func backchannelPostureFor(p SessionDurabilityPosture) backchannel.SessionDurabilityPosture {
	if p == SessionDurabilityDurable {
		return backchannel.PostureDurable
	}
	return backchannel.PostureVolatile
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
//
// sessMgr is the chooser-group session manager. When non-nil, the
// built-in account chooser is registered alongside consent and
// runs at [TriggerBeforeAuthn] for /authorize requests whose hint
// matrix routed to the chooser. A nil sessMgr (e.g., chains that
// do not reach the authorize endpoint) suppresses the chooser
// registration; the orchestrator continues to run consent and any
// user-extension interactions.
func buildOrchestrator(cfg *config, sessMgr *sessions.Manager) (*authn.Orchestrator, error) {
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
		compiled, err = compileLoginFlow(cfg.loginFlow, cfg)
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
	interactions := buildBuiltInInteractions(cfg, sessMgr)
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

// buildBuiltInInteractions prepends the library-built-in interactions
// to the user-supplied [WithInteractions] slice. Today the built-ins
// are the consent screen and (when sessMgr is non-nil) the account
// chooser. Names already taken by user extensions win —
// [authn.New] de-duplicates by [Interaction.Name] and keeps the first
// occurrence — so an embedder who registers a custom "consent" or
// "chooser" interaction (rare but supported) silently overrides the
// built-in.
func buildBuiltInInteractions(cfg *config, sessMgr *sessions.Manager) []Interaction {
	out := make([]Interaction, 0, len(cfg.interactions)+2)
	out = append(out, consent.New(consentCatalog(cfg.scopes)))
	if sessMgr != nil {
		out = append(out, chooser.New(sessMgr))
	}
	out = append(out, cfg.interactions...)
	return out
}

// buildDiscoveryInput converts the public [config] to the internal
// [discovery.Input] the discovery builder consumes.
func buildDiscoveryInput(cfg *config, scopes *scoperegistry.Registry, locales *i18n.Resolver) discovery.Input {
	customNames := customGrantNamesFor(cfg)
	grantStrings := make([]string, 0, len(cfg.grants)+len(customNames))
	for _, g := range cfg.grants {
		grantStrings = append(grantStrings, g.String())
	}
	// Custom grant_types follow the built-ins so RFC 8414 §2 ordering
	// preserves the spec-defined wires at the head of the list. The
	// dispatcher rejected built-in collisions at registration time so
	// the append cannot create a duplicate entry.
	grantStrings = append(grantStrings, customNames...)
	uiLocales := cfg.discoveryMetadata.UILocalesSupported
	if len(uiLocales) == 0 && locales != nil {
		// Fall back to the registered locale set so the resolver and
		// the discovery surface stay in lock-step: the OP advertises
		// every tag for which a bundle has been registered (seed +
		// [WithLocale]). Embedders that need an explicit list — e.g.
		// hiding a locale they ship internally but do not expose to
		// RPs — keep the override path through [WithDiscoveryMetadata].
		available := locales.Available()
		if len(available) > 0 {
			uiLocales = make([]string, len(available))
			for i, t := range available {
				uiLocales[i] = string(t)
			}
		}
	}
	return discovery.Input{
		Issuer:      cfg.issuer,
		MountPrefix: cfg.mountPrefix,
		Endpoints: discovery.EndpointPaths{
			JWKS:                cfg.endpoints.JWKS,
			Authorize:           cfg.endpoints.Authorize,
			Token:               cfg.endpoints.Token,
			UserInfo:            cfg.endpoints.UserInfo,
			EndSession:          cfg.endpoints.EndSession,
			Introspect:          cfg.endpoints.Introspect,
			Revoke:              cfg.endpoints.Revoke,
			PAR:                 cfg.endpoints.PAR,
			Interaction:         cfg.endpoints.Interaction,
			Session:             cfg.endpoints.Session,
			Register:            cfg.endpoints.Register,
			DeviceAuthorization: cfg.endpoints.DeviceAuthorization,
			Backchannel:         cfg.endpoints.Backchannel,
			GrantManagement:     cfg.endpoints.GrantManagement,
		},
		Features:                           buildDiscoveryFeatures(cfg),
		GrantsSupported:                    grantStrings,
		ScopesSupported:                    scopes.PublicNames(),
		ProfileAllowedAuthMethods:          cfg.profileAllowedAuthMethodNames(),
		ClaimsParameterSupported:           cfg.claimsParameterSupported(),
		ClaimsSupported:                    cfg.claimsSupported,
		ACRValuesSupported:                 cfg.acrValuesSupportedCopy(),
		AuthorizationDetailsTypesSupported: cfg.authorizationDetailTypeNames(),
		RequirePAR:                         cfg.requirePAR(),
		GrantManagementEnabled:             cfg.grantManagementEnabled,
		GrantManagementActions:             cfg.grantManagementActionStrings(),
		GrantManagementActionRequired:      cfg.grantManagementActionRequired,
		PairwiseEnabled:                    cfg.pairwiseEnabled(),
		EncryptionAlgsSupported:            cfg.effectiveEncryptionAlgs(),
		EncryptionEncsSupported:            cfg.effectiveEncryptionEncs(),
		Metadata: discovery.Metadata{
			ServiceDocumentation: cfg.discoveryMetadata.ServiceDocumentation,
			OPPolicyURI:          cfg.discoveryMetadata.OPPolicyURI,
			OPTermsOfServiceURI:  cfg.discoveryMetadata.OPTermsOfServiceURI,
			UILocalesSupported:   uiLocales,
			MTLSEndpointAliases:  cfg.discoveryMetadata.MTLSEndpointAliases,
			Extra:                cfg.discoveryMetadata.Extra,
		},
	}
}

// buildSubjectProjector returns the closure the authorize handler
// invokes at code emission to convert the post-authentication subject
// into the value persisted onto [store.Grant.Subject] /
// [store.AuthorizationCode.Subject]. The closure adapts the
// [SubjectGenerator] surface to the function-typed callback the
// handler receives so the internal package does not import op.
//
// # Per-client dispatch (built-in pairwise)
//
// When [WithPairwiseSubject] is active, OIDC Core 1.0 §8 mandates that
// the OP MUST compute pairwise sub values only for clients that
// requested subject_type=pairwise; clients registered with
// subject_type=public (or with the field empty, which the registration
// endpoint defaults to "public") MUST receive a non-pairwise sub. The
// projector implements that dispatch: it consults
// [store.Client.SubjectType] (RFC 7591 §2 makes subject_type per-
// client metadata) and routes pairwise clients to the configured
// pairwise generator while routing every other client to the
// package-default UUIDv7 passthrough. This is what allows a single OP
// to serve a mixed tenant base where some clients want sector-scoped
// subjects and others want a stable global identifier.
//
// # Custom-generator passthrough
//
// When [WithSubjectGenerator] supplies a fully custom generator
// (anything other than the built-in pairwise wiring), the projector
// hands every client to that generator without per-client routing.
// Embedders that need bespoke dispatch (attribute-derived sub values,
// federated-identifier hashing, multi-strategy mixes) own the routing
// inside their own [SubjectGenerator] so they can read whatever client
// metadata their strategy requires.
//
// # Default install
//
// Without any subject option the projector hands every client to the
// UUIDv7 passthrough, preserving the legacy v0.x wire shape where the
// OP-internal subject flows verbatim into the "sub" claim.
func buildSubjectProjector(cfg *config) func(ctx context.Context, raw string, client *store.Client) (string, error) {
	if cfg.pairwiseEnabled() {
		// Built-in pairwise wiring: dispatch on the per-client
		// subject_type. The pairwise generator is the one the option
		// recorded; the non-pairwise arm collapses onto the package
		// default (UUIDv7 passthrough), which preserves the v0.x wire
		// shape for any client that did not opt into pairwise.
		pairwiseGen := cfg.subjectGenerator
		fallbackGen := defaultSubjectGenerator()
		return func(ctx context.Context, raw string, client *store.Client) (string, error) {
			gen := fallbackGen
			if client != nil && client.SubjectType == "pairwise" {
				gen = pairwiseGen
			}
			sub, err := gen.Generate(ctx, SubjectGeneratorInput{
				InternalUserID: raw,
				Client:         client,
			})
			if err != nil {
				return "", err
			}
			return string(sub), nil
		}
	}
	gen := cfg.effectiveSubjectGenerator()
	return func(ctx context.Context, raw string, client *store.Client) (string, error) {
		sub, err := gen.Generate(ctx, SubjectGeneratorInput{
			InternalUserID: raw,
			Client:         client,
		})
		if err != nil {
			return "", err
		}
		return string(sub), nil
	}
}

// firstPartyClientSet materialises the [WithFirstPartyClients] slice
// into the O(1) lookup map the authorize endpoint consults on every
// request. The validator already rejects unknown ids and combinations
// with FAPI 2.0 profiles, so the returned set is safe to consult
// without further filtering. An empty slice yields a nil map so the
// downstream lookup short-circuits without allocating.
func firstPartyClientSet(cfg *config) map[string]struct{} {
	if len(cfg.firstPartyClients) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(cfg.firstPartyClients))
	for _, id := range cfg.firstPartyClients {
		out[id] = struct{}{}
	}
	return out
}

// buildDiscoveryFeatures composes the discovery feature flags from
// the configured [feature.Flag] set AND the cross-cutting fields that
// do not flow through [feature.Flag] (e.g. the device_code grant,
// gated on grant_types_supported and substore presence rather than a
// dedicated feature flag). The function is the single source of
// truth for "which optional surfaces does the OP advertise" so the
// discovery builder, the router, and the option-layer validators stay
// aligned.
func buildDiscoveryFeatures(cfg *config) discovery.Features {
	out := buildFeatures(cfg.features)
	out.DeviceCodeGrant = cfg.deviceCodeGrantConfigured()
	out.CIBAGrant = cfg.cibaGrantConfigured()
	out.Encryption = cfg.encryptionEnabled()
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
		case feature.RAR:
			// RAR advertises through authorization_details_types_supported
			// (set from the registered types), not a boolean discovery
			// flag, so there is nothing to toggle on [discovery.Features].
		case feature.GrantManagement:
			// Grant Management advertises through the dedicated
			// grant_management_* Input fields, not a boolean
			// [discovery.Features] flag, so there is nothing to toggle.
		}
	}
	return out
}

package op

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"strconv"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clone"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/proxy"
	"github.com/libraz/go-oidc-provider/internal/registrationendpoint"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
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

// SubjectGenerator returns the [SubjectGenerator] the Provider was
// constructed with. The returned value is the embedder-supplied
// generator from [WithSubjectGenerator] or [WithPairwiseSubject], or
// the package default UUIDv7 passthrough when neither option was
// supplied. Embedders calling this from out-of-band code paths
// (admin tooling, audit reports) drive the same generator instance
// the issuance pipeline consults — but note that under
// [WithPairwiseSubject] the issuance pipeline also performs per-
// client dispatch on [store.Client.SubjectType] (OIDC Core 1.0 §8 /
// RFC 7591 §2): only clients registered with subject_type=pairwise
// receive pairwise sub values; clients with subject_type=public (or
// the field empty) receive the package-default UUIDv7 passthrough.
// Out-of-band callers that want to reproduce the issuance value MUST
// either inspect [store.Client.SubjectType] themselves or invoke the
// per-client projector through a /authorize round-trip.
//
// Stable since v0.9.1.
func (p *Provider) SubjectGenerator() SubjectGenerator { //nolint:ireturn,nolintlint // sealed-sum interface return is the contract.
	if p == nil || p.cfg == nil {
		return nil
	}
	return p.cfg.effectiveSubjectGenerator()
}

// LocaleResolver returns the locale [Resolver] the Provider built
// from [WithLocale] / [WithDefaultLocale] / [WithPreferredLocaleStore].
// Embedders use it to render emails, server-rendered admin pages, or
// other out-of-band surfaces in the same locale the OP picks for
// /authorize prompts. The resolver is safe for concurrent use.
//
// Stable since v0.1.
func (p *Provider) LocaleResolver() *Resolver {
	if p == nil || p.locales == nil {
		return nil
	}
	return &Resolver{inner: p.locales}
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
	cfg.emitPartialWiringWarnings()
	trust, err := proxy.NewTrust(cfg.trustedProxies)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "WithTrustedProxies rejected by parser",
			Cause:       err,
		}
	}
	if err := seedStaticClients(cfg); err != nil {
		return nil, err
	}
	if err := cfg.enforceSubjectModeGate(context.Background()); err != nil {
		return nil, err
	}
	if err := buildMetricsCollector(cfg); err != nil {
		return nil, err
	}
	keySet, err := keys.NewSet(
		toKeyEntries(cfg.keyset),
		keys.WithClock(keysetClock(cfg)),
		keys.WithRetiredKidObserver(retiredKidObserver(cfg)),
	)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "keyset rejected by internal validator",
			Cause:       err,
		}
	}
	encSet, err := buildEncryptionSet(cfg)
	if err != nil {
		return nil, err
	}
	scopes := scoperegistry.New(toScopeEntries(cfg.scopes))
	locales, err := buildLocaleResolver(cfg)
	if err != nil {
		return nil, err
	}
	mux, err := buildRouter(cfg, keySet, encSet, scopes, locales)
	if err != nil {
		return nil, err
	}
	handler := wrapWithProfileMiddleware(mux, cfg)
	handler = wrapWithTrustedProxy(handler, trust)
	return &Provider{
		cfg:     cfg,
		keys:    keySet,
		scopes:  scopes,
		locales: locales,
		mux:     mux,
		handler: handler,
	}, nil
}

// wrapWithTrustedProxy decorates h with a middleware that resolves
// X-Forwarded-* headers per [proxy.Resolve] when the request arrives
// from a CIDR registered through [WithTrustedProxies]. The middleware
// rewrites a clone of the request so downstream handlers (issuer
// matching, redirect_uri scheme checks, DPoP htu canonicalisation,
// cookie Secure decisions) observe the externally-visible scheme and
// host instead of the in-cluster values reported by the standard
// library on the inbound listener. Untrusted requests pass through
// unchanged so a hostile client cannot forge headers.
//
// When [WithTrustedProxies] is empty the trust rejects every CIDR and
// the middleware is functionally a no-op; the wrap is still applied
// unconditionally so the request flow stays uniform across deployments.
func wrapWithTrustedProxy(h http.Handler, t *proxy.Trust) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolved := proxy.Resolve(r, t)
		if !resolved.Trusted {
			h.ServeHTTP(w, r)
			return
		}
		clone := r.Clone(r.Context())
		if clone.URL != nil && resolved.Scheme != "" {
			clone.URL.Scheme = resolved.Scheme
		}
		if resolved.Host != "" {
			clone.Host = resolved.Host
		}
		h.ServeHTTP(w, clone)
	})
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
		case profile.FAPI2Baseline, profile.FAPI2MessageSigning, profile.FAPICIBA:
			// FAPI-CIBA-ID1 §6 inherits the FAPI 1.0 Advanced
			// requirement that every response carry a stable
			// x-fapi-interaction-id; the OFCS fapi-ciba modules
			// EnsureMatchingFAPIInteractionId / CheckForFAPIInteractionId
			// pin both the presence and the round-trip echo.
			handler = httpx.InteractionIDMiddleware(handler)
			// Once any FAPI profile has activated the echo we are
			// done — repeating it would stamp the header twice and
			// hide the upstream client value behind a regenerated
			// UUID. Other profiles will add their own middlewares
			// here as the constraint set grows.
			return handler
		case profile.IGovHigh:
			// v2+; no middleware contribution today.
		}
	}
	return handler
}

// preferredLocaleStoreAdapter bridges the public [PreferredLocaleStore]
// (which speaks [Locale]) to the internal contract (which speaks
// [i18n.Tag]). The adapter is internal-only; the public interface
// stays free of the internal type so embedders never import it.
type preferredLocaleStoreAdapter struct {
	store PreferredLocaleStore
}

func (a preferredLocaleStoreAdapter) PreferredLocale(ctx context.Context, sub string) (i18n.Tag, error) {
	loc, err := a.store.PreferredLocale(ctx, sub)
	if err != nil {
		return "", err
	}
	return i18n.Tag(loc), nil
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
		out[i] = keys.Entry{KeyID: k.KeyID, Signer: k.Signer, NotAfter: k.NotAfter}
	}
	return out
}

// toEncryptionEntries mirrors [toKeyEntries] for the JWE encryption
// keyset. The conversion is a one-to-one field map; type checking on
// the supplied PrivateKey runs inside [keys.NewEncryptionSet].
func toEncryptionEntries(ks EncryptionKeyset) []keys.EncryptionEntry {
	out := make([]keys.EncryptionEntry, len(ks))
	for i, k := range ks {
		out[i] = keys.EncryptionEntry{
			KeyID:      k.KeyID,
			PrivateKey: k.PrivateKey,
			Algorithm:  k.Algorithm,
			NotAfter:   k.NotAfter,
		}
	}
	return out
}

// buildEncryptionSet constructs the runtime [keys.EncryptionSet] from
// the embedder-supplied [EncryptionKeyset]. Returns (nil, nil) when
// no encryption keyset was registered — that is the documented "JWE
// off" posture, not an error. A non-empty keyset that fails internal
// validation is wrapped in a configuration error so the misconfigured
// boot surfaces at op.New, not on first /authorize fetch.
func buildEncryptionSet(cfg *config) (*keys.EncryptionSet, error) {
	if len(cfg.encryptionKeyset) == 0 {
		return nil, nil //nolint:nilnil // optional feature; nil is the off state, not a missing value.
	}
	set, err := keys.NewEncryptionSet(
		toEncryptionEntries(cfg.encryptionKeyset),
		keys.WithClock(keysetClock(cfg)),
		keys.WithRetiredKidObserver(retiredKidObserver(cfg)),
	)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "WithEncryptionKeyset rejected by internal validator",
			Cause:       err,
		}
	}
	return set, nil
}

// keysetClock returns the wall-clock seam the [keys.Set] retirement
// gate consults. The embedder-supplied [op.Clock] (from [WithClock]) is
// preferred so the gate observes the same instant as token TTLs and
// audit timestamps; a nil [config.clock] collapses onto the package
// default (system wall clock) inside [keys.NewSet].
func keysetClock(cfg *config) func() time.Time {
	if cfg == nil || cfg.clock == nil {
		return nil
	}
	clock := cfg.clock
	return func() time.Time { return clock.Now() }
}

// retiredKidObserver builds the [keys.RetiredKidObserver] that fires
// [AuditKeyRetiredKidPresented] when the verifier rejects a kid whose
// retirement deadline has elapsed (H-F1). The observer rides on the
// configured [audit.Emitter] chain so the event lands on every sink
// (slog audit logger + the Prometheus bridge when [WithPrometheus] is
// active). [config.effectiveAuditEmitter] never returns nil — an
// embedder that did not wire any logger collapses onto [audit.Discard]
// — so the observer always emits, even when the operator has no sink
// configured (the discard sink is a no-op but keeps the gate uniform).
func retiredKidObserver(cfg *config) keys.RetiredKidObserver {
	emitter := cfg.effectiveAuditEmitter()
	return func(kid string) {
		emitter.Emit(context.Background(), audit.Event{
			Name:    string(AuditKeyRetiredKidPresented),
			Level:   audit.LevelWarn,
			Message: "verification rejected: presented kid is retired",
			Extras: map[string]any{
				"kid": kid,
			},
		})
	}
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
		RedirectURIs:                      m.RedirectURIs,
		GrantTypes:                        m.GrantTypes,
		ResponseTypes:                     m.ResponseTypes,
		Scope:                             m.Scope,
		TokenEndpointAuthMethod:           m.TokenEndpointAuthMethod,
		ApplicationType:                   m.ApplicationType,
		SubjectType:                       m.SubjectType,
		IDTokenSignedResponseAlg:          m.IDTokenSignedResponseAlg,
		SectorIdentifierURI:               m.SectorIdentifierURI,
		ClientName:                        m.ClientName,
		ClientURI:                         m.ClientURI,
		LogoURI:                           m.LogoURI,
		PolicyURI:                         m.PolicyURI,
		TosURI:                            m.TosURI,
		JWKsURI:                           m.JWKsURI,
		JWKs:                              m.JWKs,
		Contacts:                          m.Contacts,
		DefaultMaxAge:                     clone.Int64Ptr(m.DefaultMaxAge),
		RequireAuthTime:                   m.RequireAuthTime,
		DefaultACRValues:                  m.DefaultACRValues,
		InitiateLoginURI:                  m.InitiateLoginURI,
		RequestURIs:                       m.RequestURIs,
		RequestObjectSigningAlg:           m.RequestObjectSigningAlg,
		RequestObjectEncryptionAlg:        m.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc:        m.RequestObjectEncryptionEnc,
		IDTokenEncryptedResponseAlg:       m.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:       m.IDTokenEncryptedResponseEnc,
		UserInfoEncryptedResponseAlg:      m.UserInfoEncryptedResponseAlg,
		UserInfoEncryptedResponseEnc:      m.UserInfoEncryptedResponseEnc,
		AuthorizationEncryptedResponseAlg: m.AuthorizationEncryptedResponseAlg,
		AuthorizationEncryptedResponseEnc: m.AuthorizationEncryptedResponseEnc,
		IntrospectionEncryptedResponseAlg: m.IntrospectionEncryptedResponseAlg,
		IntrospectionEncryptedResponseEnc: m.IntrospectionEncryptedResponseEnc,
		PostLogoutRedirectURIs:            m.PostLogoutRedirectURIs,
		BackchannelLogoutURI:              m.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  m.BackchannelLogoutSessionRequired,
	}
}

// seedStaticClients persists the [WithStaticClients] entries in
// [config.staticClients] through [store.ClientRegistry.RegisterClient].
// The function is a no-op when no static clients were configured. It
// fails [New] when:
//
//   - the configured store does not satisfy [store.ClientRegistry] and
//     does not vend one through [clientRegistryProvider] (the embedder
//     asked for static seeding but supplied a read-only store);
//   - any [store.ClientRegistry.RegisterClient] call fails (e.g. the
//     same id is registered twice).
//
// Calling this once at construction matches the OAuth 2.0 §2 expectation
// that the OP knows about every static client before serving requests.
func seedStaticClients(cfg *config) error {
	if len(cfg.staticClients) == 0 {
		return nil
	}
	registry, err := resolveClientRegistry(cfg.store)
	if err != nil {
		return err
	}
	ctx := context.Background()
	for i := range cfg.staticClients {
		c := cfg.staticClients[i]
		if err := registry.RegisterClient(ctx, &c); err != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithStaticClients: registering client " + c.ID,
				Cause:       err,
			}
		}
	}
	return nil
}

// clientRegistryProvider is the optional capability stores expose when
// they cannot satisfy [store.ClientRegistry] directly but can vend one.
// The composite adapter (op/storeadapter/composite) is the canonical
// implementer: its godoc explains why it deliberately does NOT implement
// [store.ClientRegistry] via a type assertion (a read-only Clients
// backend would otherwise be silently coerced into a registry). The
// interface is duck-typed because composite cannot import this package.
type clientRegistryProvider interface {
	ClientRegistry() (store.ClientRegistry, bool)
}

// resolveClientRegistry returns the [store.ClientRegistry] view of s.
// It first tries a direct interface assertion (every storeadapter that
// can register clients satisfies [store.ClientRegistry]); when that
// fails it probes [clientRegistryProvider] so composite stores opt in
// without re-implementing the registry surface. A store that does
// neither is rejected with [codeConfiguration] so [WithStaticClients]
// fails fast at [New].
func resolveClientRegistry(s store.Store) (store.ClientRegistry, error) {
	if registry, ok := s.(store.ClientRegistry); ok {
		return registry, nil
	}
	if provider, ok := s.(clientRegistryProvider); ok {
		if registry, has := provider.ClientRegistry(); has {
			return registry, nil
		}
	}
	return nil, &Error{
		Code: codeConfiguration,
		Description: "WithStaticClients requires a Store that implements " +
			"store.ClientRegistry; got a read-only store",
	}
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
// FAPI 2.0 family and FAPI-CIBA (which inherits the FAPI 2.0
// §3.1.4 mandate verbatim per FAPI-CIBA-ID1 §5); the build-time
// profile validator already requires either DPoP or mTLS feature
// to be enabled when one of those profiles is active, so the
// runtime path returning true here means "an /token (or
// /bc-authorize) request must present a proof or a cert".
func (c *config) requireSenderConstrainedTokens() bool {
	for _, p := range c.profiles {
		switch p {
		case profile.FAPI2Baseline, profile.FAPI2MessageSigning, profile.FAPICIBA:
			return true
		case profile.IGovHigh:
			// IGovHigh is a placeholder today; it will land here
			// when its constraint table graduates.
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
			// Baseline does not mandate signed_non_repudiation;
			// FAPI-CIBA mandates signed authentication requests
			// at /bc-authorize but not at /authorize / /par
			// (CIBA does not exercise either endpoint), so its
			// gate lives on [config.requireSignedBackchannelRequest].
			// IGovHigh is a placeholder today and will land here
			// when its constraint table graduates.
		}
	}
	return false
}

// requireSignedBackchannelRequest reports whether the active
// [profile.Profile] set mandates that every /bc-authorize request
// carry a signed JAR request object. FAPI-CIBA-ID1 §5.2.2 ("the
// authentication request MUST be a signed authentication request")
// is the canonical source. The build-time profile validator
// requires [feature.JAR] to be enabled when [profile.FAPICIBA] is
// active, so the runtime path returning true here means "a JAR
// verifier is guaranteed to be wired" at /bc-authorize. The
// helper mirrors the disjunctive shape of [config.requirePKCE]:
// any one active profile that mandates signed backchannel
// requests resolves the answer to true.
func (c *config) requireSignedBackchannelRequest() bool {
	for _, p := range c.profiles {
		switch p {
		case profile.FAPICIBA:
			return true
		case profile.FAPI2Baseline, profile.FAPI2MessageSigning, profile.IGovHigh:
			// FAPI 2.0 Baseline / Message Signing do not mount a
			// backchannel-authentication endpoint; the signed-
			// request mandate is specific to FAPI-CIBA. IGovHigh
			// is a placeholder today and will land here when its
			// constraint table graduates.
		}
	}
	return false
}

// fapiCIBAProfileActive reports whether [profile.FAPICIBA] is in the
// active profile set. The /bc-authorize handler consults the flag to
// flip the requested_expiry gate from the legacy "clamp silently"
// posture to the FAPI-CIBA-ID1 §5 / FAPI 2.0 §3.1.9 hard-reject
// posture (any value above ten minutes surfaces as invalid_request
// rather than being clamped down without notice). The helper mirrors
// the disjunctive shape of [config.requirePKCE]; the inner switch
// names every other profile so an exhaustive linter flags a future
// addition that needs to revisit the FAPI-CIBA distinction.
func (c *config) fapiCIBAProfileActive() bool {
	for _, p := range c.profiles {
		switch p {
		case profile.FAPICIBA:
			return true
		case profile.FAPI2Baseline, profile.FAPI2MessageSigning, profile.IGovHigh:
			// FAPI 2.0 Baseline / Message Signing do not mount the
			// backchannel-authentication endpoint; IGovHigh is a
			// placeholder today.
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
			// Baseline does not require response signing;
			// FAPI-CIBA does not exercise /authorize so JARM does
			// not apply. IGovHigh is a placeholder today and will
			// land here when its constraint table graduates.
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
			// Baseline does not require introspection signing;
			// FAPI-CIBA inherits the FAPI 2.0 Baseline posture for
			// /introspect (the profile only adds backchannel-
			// authentication mandates). IGovHigh is a placeholder
			// today and will land here when its constraint table
			// graduates.
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

// spaWiringFor projects the [config.spaUI] state onto the
// authorizeendpoint deps fields. An unset SPAUI returns the empty
// pair; the consumer treats it as "legacy /interaction wiring".
func spaWiringFor(cfg *config) (loginMount, staticDir string) {
	if !cfg.spaUISet {
		return "", ""
	}
	return cfg.spaUI.LoginMount, cfg.spaUI.StaticDir
}

// compileLoginFlow projects the public [LoginFlow] onto the internal
// [authn.LoginFlowSpec] shape and hands it to the authn-package
// compiler. The projection lives in op/ (not internal/authn/) because
// the rule "internal MUST NOT import op" forbids the inverse path.
//
// Built-in Steps (PrimaryPassword / PrimaryPasskey / StepTOTP /
// StepEmailOTP / StepRecoveryCode / StepCaptcha) are wired to their
// internal Authenticator primitives through the matching builders in
// loginflow_compile.go. ExternalStep continues to forward an
// already-constructed [Authenticator] verbatim for embedders with
// proprietary factors.
//
// cfg supplies the Provider-level fallbacks the per-step builders
// consult when the Step omits its own field (e.g. StepTOTP defers to
// [WithMFAEncryptionKeys] when [StepTOTP.EncryptionKey] is empty).
func compileLoginFlow(flow LoginFlow, cfg *config) (*authn.CompiledLoginFlow, error) {
	primary, err := projectStepToFlow("Primary", flow.Primary, cfg)
	if err != nil {
		return nil, err
	}
	rules := make([]authn.LoginFlowRule, 0, len(flow.Rules))
	for i, r := range flow.Rules {
		then, perr := projectStepToFlow("Rules["+strconv.Itoa(i)+"].Then", r.Then, cfg)
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
//   - Built-in Steps with construction-time wiring (PrimaryPassword,
//     PrimaryPasskey, StepTOTP, StepEmailOTP, StepRecoveryCode,
//     StepCaptcha): the matching builder synthesises the internal
//     authenticator from the Step's public fields. Validation errors
//     surface as a typed *Error pointing at the offending Step.
//   - Unrecognised Step values: surface a configuration_error pointing
//     at the offending Step so the upgrade path is obvious; embedders
//     use [ExternalStep] until a missing built-in lands.
//
// cfg threads the Provider-level fallbacks (e.g. MFA encryption keys)
// through to the built-in builders.
func projectStepToFlow(where string, s Step, cfg *config) (authn.LoginFlowStep, error) {
	if s == nil {
		return authn.LoginFlowStep{}, &Error{
			Code:        codeConfiguration,
			Description: "WithLoginFlow: " + where + " must not be nil",
		}
	}
	if ext, ok := s.(ExternalStep); ok {
		return projectExternalStep(where, ext)
	}
	return projectBuiltinStep(where, s, cfg)
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

// projectBuiltinStep dispatches a built-in [Step] (PrimaryPassword,
// PrimaryPasskey, StepTOTP, StepEmailOTP, StepRecoveryCode,
// StepCaptcha) to the matching builder in loginflow_compile.go and
// wraps the constructed authenticator in a [authn.LoginFlowStep]. An
// unrecognised Step value surfaces a configuration_error pointing the
// embedder at [ExternalStep].
//
// cfg supplies the Provider-level fallbacks the per-step builders
// consult when the Step omits its own field.
func projectBuiltinStep(where string, s Step, cfg *config) (authn.LoginFlowStep, error) {
	switch v := s.(type) {
	case PrimaryPasskey:
		auth, err := buildPrimaryPasskey(v)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		return authn.LoginFlowStep{Kind: string(StepKindPasskey), Authenticator: auth}, nil
	case StepTOTP:
		fallbackCurrent, fallbackPrev := totpFallbackKeys(cfg)
		auth, err := buildStepTOTP(v, fallbackCurrent, fallbackPrev)
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
		auth, err := buildPrimaryPassword(v)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		return authn.LoginFlowStep{Kind: string(StepKindPassword), Authenticator: auth}, nil
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

// totpFallbackKeys returns the Provider-level TOTP encryption keys
// configured through [WithMFAEncryptionKeys].
// The first return value is the active key (or nil when the option is
// unset), the second is the rotation history (nil when absent or when
// only the active key was supplied). Splitting the slice this way lets
// [buildStepTOTP] feed [selectTOTPKeys] without re-parsing the layout.
func totpFallbackKeys(cfg *config) ([]byte, [][]byte) {
	if len(cfg.mfaEncryptionKeys) == 0 {
		return nil, nil
	}
	current := cfg.mfaEncryptionKeys[0]
	if len(cfg.mfaEncryptionKeys) == 1 {
		return current, nil
	}
	return current, cfg.mfaEncryptionKeys[1:]
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
// onto the public [LoginContext] surface rule predicates consume.
// [op.RiskScore] is a type alias for [authn.RiskScore], so the field
// flows through without a conversion.
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
		RiskScore:       lc.RiskScore,
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
// dynamic-compile path is intentionally absent: a Decider that needs
// to introduce a previously-unregistered Step must register it on the
// LoginFlow up front).
func (a *deciderAdapter) Decide(ctx context.Context, lc authn.LoginFlowContext) authn.LoginFlowDecision { //nolint:ireturn,nolintlint // sealed-sum LoginFlowDecision is the contract.
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

// newACRResolver builds the [authorizeendpoint.ACRResolver] closure the
// authorize endpoint consults before stamping acr / amr onto the
// persisted grant. The closure adapts the public [ACRPolicy] surface
// to the wire-layer input bundle: the input's CompletedKinds (raw
// strings carried by [authn.State]) project onto the public
// [StepKind] slice that [ACRPolicy.Resolve] / [ACRPolicy.Satisfies]
// consume, and the input's request-scoped fields fold into a fresh
// [LoginContext]. The function never returns nil so the wire layer
// always sees a configured resolver: a nil [config.acrPolicy] triggers
// the [DefaultACRPolicy] fallback.
func newACRResolver(cfg *config) authorizeendpoint.ACRResolver {
	policy := cfg.effectiveACRPolicy()
	return func(ctx context.Context, in authorizeendpoint.ACRResolveInput) authorizeendpoint.ACRResolveOutput {
		scopes := make(ScopeSet, len(in.RequestedScopes))
		for _, s := range in.RequestedScopes {
			scopes[ScopeName(s)] = struct{}{}
		}
		completed := make([]StepKind, len(in.CompletedKinds))
		for i, k := range in.CompletedKinds {
			completed[i] = StepKind(k)
		}
		lc := LoginContext{
			Identity:        Identity{Subject: Subject(in.Subject)},
			ClientID:        in.ClientID,
			RequestedScopes: scopes,
			CompletedSteps:  completed,
			ACRValues:       append([]string(nil), in.RequestedACRValues...),
			Remote: ClientHints{
				RemoteIP:       in.RemoteIP,
				UserAgent:      in.UserAgent,
				AcceptLanguage: in.AcceptLanguage,
			},
		}
		acr, amr, ok := policy.Resolve(ctx, lc, in.InternalAAL)
		return authorizeendpoint.ACRResolveOutput{
			ACR: acr,
			AMR: append([]string(nil), amr...),
			OK:  ok,
		}
	}
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

// customScopeClaims projects the public scope catalogue onto the
// runtime-only scope -> claim-name mapping consumed by /userinfo.
// Scopes with no claim mapping are omitted entirely so downstream code
// can treat absence and "no custom claims" identically.
func customScopeClaims(scopes []Scope) map[string][]string {
	out := make(map[string][]string)
	for _, s := range scopes {
		if len(s.Claims) == 0 {
			continue
		}
		out[s.Name] = append([]string(nil), s.Claims...)
	}
	if len(out) == 0 {
		return nil
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

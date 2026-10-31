package op

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/proxy"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// defaultUserInfoLeeway is the symmetric tolerance the /userinfo
// handler applies to the access-token "exp" / "iat" comparisons. It is
// an alias for [tokens.DefaultLeeway], which is the one value every
// access-token verification surface resolves to: /userinfo answers the
// same "is this token valid?" question as /introspect, /revoke and the
// token-exchange subject-token lookup, and a deployment with clock skew
// gets contradictory answers the moment those tolerances differ.
const defaultUserInfoLeeway = tokens.DefaultLeeway

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
	routes  []string
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
// Failures of the built-in generators are reported as the catalog
// entries that document them ([ErrSubjectInputEmpty],
// [ErrPairwiseSectorUnresolved]), matchable with [errors.Is] and
// classified by [IsServerError]. A generator supplied through
// [WithSubjectGenerator] is returned verbatim, errors included.
//
// Stable since v1.0.
func (p *Provider) SubjectGenerator() SubjectGenerator { //nolint:ireturn,nolintlint // sealed-sum interface return is the contract.
	if p == nil || p.cfg == nil {
		return nil
	}
	return p.cfg.catalogSubjectGenerator()
}

// LocaleResolver returns the locale [Resolver] the Provider built
// from [WithLocale] / [WithDefaultLocale] / [WithPreferredLocaleStore].
// Embedders use it to render emails, server-rendered admin pages, or
// other out-of-band surfaces in the same locale the OP picks for
// /authorize prompts. The resolver is safe for concurrent use.
//
// Stable since v1.0.
func (p *Provider) LocaleResolver() *Resolver {
	if p == nil || p.locales == nil {
		return nil
	}
	return &Resolver{inner: p.locales}
}

// Shutdown blocks until every back-channel logout fan-out already in
// flight has finished, or until ctx expires. It returns nil on a
// complete drain and ctx's error otherwise, so a caller can
// distinguish the two with [errors.Is] against
// [context.DeadlineExceeded] / [context.Canceled].
//
// The seam exists because /end_session answers the browser as soon as
// the OP-side session is gone and notifies the relying parties on a
// detached context. Nothing on the request path waits for that work,
// so without a drain a SIGTERM during a rolling deploy would end the
// process while signed Logout Tokens were still queued, and the RPs
// would never learn the session ended.
//
// Three behaviours embedders wire this into a signal handler need to
// be able to rely on:
//
//   - Shutdown is a no-op returning nil on a Provider with no
//     back-channel logout coordinator — a machine-to-machine
//     configuration that never mounts /end_session, or a nil
//     receiver. Call it unconditionally.
//   - Shutdown may be called any number of times, from any number of
//     goroutines. It holds no closed state: each call waits for
//     whatever is in flight when it runs, and a second call on a
//     quiet Provider returns nil immediately.
//   - Shutdown does not seal the Provider. [Provider.ServeHTTP] keeps
//     serving afterwards, and a /end_session request that arrives
//     after the drain starts its own fan-out, which that call will
//     not wait for. Stop accepting requests first — typically
//     [net/http.Server.Shutdown] — and drain second, so the set of
//     in-flight fan-outs can only shrink.
//
// Each fan-out is independently bounded by
// [WithBackchannelFanOutBudget], so a Provider left unattended still
// converges; Shutdown makes the convergence something the embedder
// can wait for.
//
// Stable since v1.1.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.cfg == nil || p.cfg.backchannelCoordinator == nil {
		return nil
	}
	return p.cfg.backchannelCoordinator.Drain(ctx)
}

// New constructs a [Provider] from the supplied options. It validates that
// every required option is present and that the combination of enabled
// grants, features, and profiles is internally consistent.
//
// Stable since v1.0. New returns a non-nil error if construction fails; the
// returned Provider is nil in that case. Callers must treat construction
// failure as fatal during program start-up.
func New(opts ...Option) (*Provider, error) {
	cfg, err := newConfig(opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		clear(cfg.staticClientSecrets)
		cfg.staticClientSecrets = nil
	}()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.emitPartialWiringWarnings()
	trust, err := buildProxyTrust(cfg)
	if err != nil {
		return nil, err
	}
	commitSubjectMode, err := cfg.checkSubjectModeGate(context.Background())
	if err != nil {
		return nil, err
	}
	if err := buildMetricsCollector(cfg); err != nil {
		return nil, err
	}
	// Collector registration mutates the embedder-owned registry before later
	// fallible constructor stages (keys, locales, router, and static-client
	// reconciliation). Keep that mutation transactional with New: a failed
	// construction must not strand descriptors that make a corrected retry on
	// the same registry fail as an apparent duplicate registration.
	metricsCommitted := false
	if cfg.metricsCollector != nil {
		defer func() {
			if !metricsCommitted {
				cfg.metricsCollector.Unregister()
			}
		}()
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
	cfg.interactionD = wireHTMLDriverTranslator(cfg.interactionD, locales)
	router, err := buildRouter(cfg, keySet, encSet, scopes, locales, trust)
	if err != nil {
		return nil, err
	}
	mux := router.mux
	handler := wrapWithProfileMiddleware(mux, cfg)
	handler = wrapWithTrustedProxy(handler, trust, cfg.logger)
	provider := &Provider{
		cfg:     cfg,
		keys:    keySet,
		scopes:  scopes,
		locales: locales,
		mux:     mux,
		routes:  router.patterns,
		handler: handler,
	}
	if err := seedStaticClients(cfg); err != nil {
		return nil, err
	}
	if err := commitSubjectMode(context.Background()); err != nil {
		return nil, err
	}
	// Emitted last so the record only describes a Provider the caller
	// actually receives: an audit stream that announced a security
	// posture for a construction that then failed would be worse than
	// no record at all.
	cfg.emitStartupProfile(context.Background())
	metricsCommitted = true
	return provider, nil
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
// In that state the first request carrying X-Forwarded-For,
// X-Forwarded-Proto or X-Forwarded-Host logs one WARN per wrapped
// handler (a Provider) on logger; a nil logger disables the warning.
func wrapWithTrustedProxy(h http.Handler, t *proxy.Trust, logger *slog.Logger) http.Handler {
	var warnOnce sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if logger != nil && !t.IsConfigured() && hasForwardedHeader(r) {
			warnOnce.Do(func() {
				logger.Warn("forwarded headers received but WithTrustedProxies is not configured; the OP ignores X-Forwarded-* and uses the peer address for audit, risk and rate decisions")
			})
		}
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

// hasForwardedHeader reports whether r carries any of the X-Forwarded-*
// headers [proxy.Resolve] would honour.
func hasForwardedHeader(r *http.Request) bool {
	for _, k := range []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"} {
		if len(r.Header.Values(k)) > 0 {
			return true
		}
	}
	return false
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
		case profile.Baseline:
			// The OAuth 2.1 posture adds no cross-cutting response
			// header; x-fapi-interaction-id is a FAPI construct and
			// stamping it on a non-FAPI deployment would advertise a
			// profile the OP is not running.
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
	return i18n.ParseTag(string(loc)), nil
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
// no encryption keyset was registered — that is the documented
// "inbound JWE off" posture, not an error. A non-empty keyset that
// fails internal validation is wrapped in a configuration error so the
// misconfigured boot surfaces at op.New, not on first /authorize fetch.
//
// The set also carries the deployment's [config.jwePolicy], which is
// how a [WithSupportedEncryptionAlgs] narrowing reaches inbound
// decryption: the JOSE layer reads it off the resolver rather than
// having it threaded through every verifier that owns one.
func buildEncryptionSet(cfg *config) (*keys.EncryptionSet, error) {
	if len(cfg.encryptionKeyset) == 0 {
		return nil, nil //nolint:nilnil // optional feature; nil is the off state, not a missing value.
	}
	set, err := keys.NewEncryptionSet(
		toEncryptionEntries(cfg.encryptionKeyset),
		keys.WithClock(keysetClock(cfg)),
		keys.WithRetiredKidObserver(retiredKidObserver(cfg)),
		keys.WithJWEPolicy(cfg.jwePolicy()),
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
// retirement deadline has elapsed. The observer rides on the
// configured [audit.Emitter] chain so the event lands on every sink
// (slog audit logger + the Prometheus bridge when [WithPrometheus] is
// active). [config.effectiveAuditEmitter] never returns nil — an
// embedder that did not wire any logger collapses onto [audit.Discard]
// — so the observer always emits, even when the operator has no sink
// configured (the discard sink is a no-op but keeps the gate uniform).
//
// The event carries the context of the request that presented the
// retired kid, so the sink can attach the embedder's request id and the
// active trace span. Without it the operator sees that a retired kid was
// presented but cannot tell by whom or on which request — and a token
// signed by a key the OP has stopped trusting is precisely the event
// worth tracing back to its caller.
func retiredKidObserver(cfg *config) keys.RetiredKidObserver {
	emitter := cfg.effectiveAuditEmitter()
	return func(ctx context.Context, kid string) {
		emitter.Emit(ctx, audit.Event{
			Name:    string(AuditKeyRetiredKidPresented),
			Level:   audit.LevelWarn,
			Message: "verification rejected: presented kid is retired",
			Extras: map[string]any{
				"kid": kid,
			},
		})
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

// grantsRequireAuthorizeEndpoint reports whether any configured grant
// depends on the /authorize endpoint being mounted. Currently only the
// AuthorizationCode grant qualifies; the helper exists so future
// grants can opt in by adding themselves to the switch.
//
// This is the single predicate behind three decisions that MUST agree:
// [mountAuthorizeHandlers] registering /authorize (and, through the
// session manager it returns, /end_session), the store-capability
// validation those handlers depend on, and the discovery advertisement
// of authorization_endpoint / end_session_endpoint /
// response_types_supported / backchannel_logout_supported
// ([buildDiscoveryFeatures]). A grant added to the switch therefore
// gains the routes and the metadata in one step, and a grant set that
// stays out of it can never advertise an endpoint that answers 404.
func grantsRequireAuthorizeEndpoint(grants []grant.Type) bool {
	for _, g := range grants {
		if g == grant.AuthorizationCode {
			return true
		}
	}
	return false
}

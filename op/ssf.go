package op

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/cors"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/ssf"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// buildSharedSignals validates the [WithSharedSignals] contract, then
// constructs the SSF sealer, transmitter and push worker, records them
// on cfg and registers the receiver scopes. It runs after the keyset and
// before the scope registry and the router, so every audit emitter the
// router takes is already wrapped by the SSF decorator. The worker is
// started separately, once [New] can no longer fail.
func buildSharedSignals(cfg *config, keySet *keys.Set) error {
	if err := cfg.validateSharedSignals(); err != nil {
		return err
	}
	if !cfg.sharedSignals {
		return nil
	}
	ss, err := cfg.sharedSignalsStore()
	if err != nil {
		return err
	}
	grants, err := cfg.sharedSignalsGrants()
	if err != nil {
		return err
	}
	current, previous := deriveSSFSealKeys(cfg.cookieKeys)
	sealer, err := ssf.NewSealer(current, previous...)
	if err != nil {
		return newConfigurationError("WithSharedSignals: seal key derivation failed", err)
	}
	// The transmitter reports to the undecorated chain: its own ssf.*
	// events must not re-enter the decorator.
	base := cfg.baseAuditEmitter()
	tx, err := ssf.New(ssf.Deps{
		Issuer:           cfg.issuer,
		Streams:          ss.SSFStreams(),
		Events:           ss.SSFEvents(),
		Grants:           grants,
		Clients:          cfg.clientStore(),
		SubjectProjector: subjectProjectorFor(cfg),
		Audit:            base,
		Clock:            cfg.clock,
	})
	if err != nil {
		return newConfigurationError("WithSharedSignals: transmitter construction failed", err)
	}
	worker, err := ssf.NewWorker(ssf.WorkerDeps{
		Events:              ss.SSFEvents(),
		Streams:             ss.SSFStreams(),
		Sealer:              sealer,
		SigningKey:          ssfActiveKey(keySet),
		AllowPrivateNetwork: cfg.sharedSignalsAllowPrivateNetwork,
		OptIn:               optInSharedSignals,
		AllowInsecureForDev: cfg.allowInsecureSharedSignalsPushForDev,
		Audit:               base,
		Clock:               cfg.clock,
		Logger:              cfg.logger,
	})
	if err != nil {
		return newConfigurationError("WithSharedSignals: push worker construction failed", err)
	}
	cfg.ssfSealer = sealer
	cfg.ssfTransmitter = tx
	cfg.ssfWorker = worker
	cfg.registerSharedSignalsScopes()
	return nil
}

// ssfActiveKey returns the key a SET is signed with at dispatch time, so
// a queued SET never outlives its kid.
func ssfActiveKey(keySet *keys.Set) func() (ssf.SigningKey, error) {
	return func() (ssf.SigningKey, error) {
		return tokens.FromInternalEntry(keySet.Active()), nil
	}
}

// mountSharedSignals registers the transmitter metadata at the host root
// (outside the mount prefix, like RFC 9728's) and the management, status,
// verification and poll endpoints inside it. Without [WithSharedSignals]
// no route is added.
func mountSharedSignals(
	mux *routeMux,
	cfg *config,
	keySet *keys.Set,
	dpopVerifier *dpop.Verifier,
	mtlsVerifier *mtls.Verifier,
	subjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error),
	publicCORS *cors.Public,
	strictCORS *cors.Strict,
) error {
	if cfg.ssfTransmitter == nil {
		return nil
	}
	ss, err := cfg.sharedSignalsStore()
	if err != nil {
		return err
	}
	wellKnown, err := ssf.WellKnownPath(cfg.issuer)
	if err != nil {
		return newConfigurationError("WithSharedSignals: metadata path", err)
	}
	metadata, err := ssf.NewMetadataHandler(ssf.MetadataDeps{
		Issuer:                cfg.issuer,
		JWKSURI:               absoluteEndpointURL(cfg, cfg.endpoints.JWKS),
		ConfigurationEndpoint: absoluteEndpointURL(cfg, cfg.endpoints.SSFConfiguration),
		StatusEndpoint:        absoluteEndpointURL(cfg, cfg.endpoints.SSFStatus),
		VerificationEndpoint:  absoluteEndpointURL(cfg, cfg.endpoints.SSFVerify),
	})
	if err != nil {
		return newConfigurationError("WithSharedSignals: metadata handler", err)
	}
	// The bearer rules are userinfo's, field for field, so a token is
	// accepted (format, revocation, sender constraint) by both or neither.
	handlers, err := ssf.NewHandlers(ssf.HandlerDeps{
		Issuer: cfg.issuer,
		Bearer: endpointsupport.BearerDeps{
			Keys:               keySet,
			Issuer:             cfg.issuer,
			Clock:              cfg.clock,
			Clients:            cfg.clientStore(),
			Grants:             cfg.store.Grants(),
			SubjectProjector:   subjectProjector,
			OpaqueAccessTokens: cfg.store.OpaqueAccessTokens(),
			AccessTokens:       cfg.store.AccessTokens(),
			GrantRevocations:   cfg.store.GrantRevocations(),
			RevocationStrategy: cfg.atRevocation,
			DPoP:               dpopVerifier,
			DPoPNonces:         cfg.dpopNonces,
			MTLS:               mtlsVerifier,
		},
		Streams:             ss.SSFStreams(),
		Events:              ss.SSFEvents(),
		Transmitter:         cfg.ssfTransmitter,
		Sealer:              cfg.ssfSealer,
		PollEndpoint:        absoluteEndpointURL(cfg, cfg.endpoints.SSFPoll),
		ActiveKey:           ssfActiveKey(keySet),
		AllowInsecureForDev: cfg.allowInsecureSharedSignalsPushForDev,
		AllowPrivateNetwork: cfg.sharedSignalsAllowPrivateNetwork,
		Audit:               cfg.effectiveAuditEmitter(),
		Clock:               cfg.clock,
	})
	if err != nil {
		return newConfigurationError("WithSharedSignals: endpoint construction failed", err)
	}
	mux.Handle(wellKnown, publicCORS.Handler(metadata))
	mux.Handle(protocolEndpointPath(cfg, cfg.endpoints.SSFConfiguration), strictCORS.Handler(handlers.Streams()))
	mux.Handle(protocolEndpointPath(cfg, cfg.endpoints.SSFStatus), strictCORS.Handler(handlers.Status()))
	mux.Handle(protocolEndpointPath(cfg, cfg.endpoints.SSFVerify), strictCORS.Handler(handlers.Verify()))
	mux.Handle(protocolEndpointPath(cfg, cfg.endpoints.SSFPoll)+"/{"+ssf.PollPathValue+"}", strictCORS.Handler(handlers.Poll()))
	return nil
}

// wrapSharedSignals wraps next with the SSF decorator when the
// transmitter is built; otherwise it returns next unchanged.
func (c *config) wrapSharedSignals(next audit.Emitter) audit.Emitter {
	if c.ssfTransmitter == nil {
		return next
	}
	return ssfAuditDecorator{next: next, tx: c.ssfTransmitter}
}

// ssfAuditDecorator turns the OP's own session.destroyed record (one
// per session row an RP-Initiated Logout ends) into a CAEP
// session-revoked SET. It looks at nothing else, ssf.* included, so it
// cannot re-enter itself. Publish is synchronous but makes no outbound
// HTTP call; its failures are audited by the transmitter on the
// undecorated chain and never fail the logout.
type ssfAuditDecorator struct {
	next audit.Emitter
	tx   *ssf.Transmitter
}

func (d ssfAuditDecorator) Emit(ctx context.Context, ev audit.Event) {
	d.next.Emit(ctx, ev)
	if ev.Name != string(auditevent.AuditSessionDestroyed) || ev.ActorID == "" {
		return
	}
	_, _ = d.tx.Publish(ctx, ssf.EventSessionRevoked, ev.ActorID, ssf.Fields{
		InitiatingEntity: ssf.InitiatingEntityUser,
	})
}

// startSharedSignals starts the push worker. [New] calls it last, once
// construction can no longer fail, so a failed New leaves no goroutine.
func startSharedSignals(cfg *config) {
	if cfg.ssfWorker == nil {
		return
	}
	cfg.ssfWorker.Start(context.Background())
}

// compile-time check that the decorator stays an [audit.Emitter].
var _ audit.Emitter = ssfAuditDecorator{}

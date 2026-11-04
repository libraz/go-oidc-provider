package op

import (
	"context"
	"errors"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/customgrant/tokenexchange"
	"github.com/libraz/go-oidc-provider/internal/keys"
)

// buildExtensionDispatcher wires the customgrant dispatcher with both
// embedder-supplied custom-grant handlers and the in-tree token-
// exchange handler when [WithTokenExchangeGrant] or [WithIDJAGIssuance]
// was invoked. The
// helper is the single seam through which the token endpoint reaches
// the extension grants so a future addition (CIBA / device-code / ...)
// keeps the wiring local to one file.
func buildExtensionDispatcher(cfg *config, keySet *keys.Set, auditEmitter audit.Emitter) (*customgrant.Dispatcher, error) {
	var extras []customgrant.Handler
	if cfg.tokenExchangePolicy != nil || cfg.idjagIssuancePolicy != nil {
		h, err := tokenexchange.New(tokenexchange.Config{
			Policy:             tokenExchangeAdapter(cfg.tokenExchangePolicy),
			IDJAGPolicy:        idjagIssuanceAdapter(cfg.idjagIssuancePolicy),
			Issuer:             cfg.issuer,
			Keys:               keySet,
			AccessTokens:       cfg.store.AccessTokens(),
			GrantRevocations:   cfg.store.GrantRevocations(),
			RevocationStrategy: cfg.atRevocation,
			OpaqueAccessTokens: cfg.store.OpaqueAccessTokens(),
			Grants:             cfg.store.Grants(),
			Clients:            cfg.clientStore(),
			// An opaque subject_token records the OP-internal subject;
			// the exchanged token must carry the per-client public one a
			// JWT subject_token already does.
			SubjectProjector: subjectProjectorFor(cfg),
			Audit:            auditEmitter,
			Clock:            cfg.clock,
			MaxAccessTTL:     cfg.accessTokenTTL,
		})
		if err != nil {
			return nil, newConfigurationError("token-exchange handler construction failed", err)
		}
		extras = append(extras, h)
	}
	return cfg.buildCustomGrantDispatcher(auditEmitter, extras...), nil
}

// tokenExchangeAdapter projects the public [TokenExchangePolicy] onto
// the internal [tokenexchange.PolicyFunc] shape so the handler stays
// inside internal/. The adapter copies request slices defensively
// before invoking the embedder so a policy mutating its input cannot
// disturb the OP's own bookkeeping.
func tokenExchangeAdapter(policy TokenExchangePolicy) tokenexchange.PolicyFunc {
	if policy == nil {
		return nil
	}
	return func(ctx context.Context, req tokenexchange.RequestView) (*tokenexchange.Decision, error) {
		publicReq := TokenExchangeRequest{
			Client:            req.Client,
			Subject:           Subject(req.Subject),
			SubjectToken:      toPublicTokenView(req.SubjectToken),
			RequestedAudience: append([]string(nil), req.RequestedAudience...),
			RequestedScope:    append([]string(nil), req.RequestedScope...),
			MTLSCert:          req.MTLSCert,
		}
		if req.Actor != "" {
			actor := Subject(req.Actor)
			publicReq.Actor = &actor
		}
		if req.ActorToken != nil {
			view := toPublicTokenView(*req.ActorToken)
			publicReq.ActorToken = &view
		}
		if req.DPoPJKT != "" {
			publicReq.DPoP = &DPoPProof{JKT: req.DPoPJKT, JTI: req.DPoPJTI}
		}
		decision, err := policy.Allow(ctx, publicReq)
		if err != nil {
			return nil, err
		}
		if decision == nil {
			return nil, nil
		}
		return toInternalDecision(decision), nil
	}
}

// toPublicTokenView projects an internal token view onto the public
// [SubjectTokenView] shape.
func toPublicTokenView(view tokenexchange.TokenView) SubjectTokenView {
	out := SubjectTokenView{
		Type:          view.Type,
		ClientID:      view.ClientID,
		Scope:         append([]string(nil), view.Scope...),
		Audience:      append([]string(nil), view.Audience...),
		ExpiresAt:     view.ExpiresAt,
		ActChainDepth: view.ActChainDepth,
	}
	if view.Confirmation != nil {
		out.Confirmation = &ConfirmationProof{
			JKT:     view.Confirmation.JKT,
			X5tS256: view.Confirmation.X5tS256,
		}
	}
	return out
}

// toInternalDecision converts a public TokenExchangeDecision onto the
// internal Decision shape.
func toInternalDecision(d *TokenExchangeDecision) *tokenexchange.Decision {
	return &tokenexchange.Decision{
		GrantedScope:      slices.Clone(d.GrantedScope),
		GrantedAudience:   slices.Clone(d.GrantedAudience),
		GrantedTTL:        d.GrantedTTL,
		IssueIDToken:      d.IssueIDToken,
		IssueRefreshToken: d.IssueRefreshToken,
		ExtraClaims:       cloneClaims(d.ExtraClaims),
	}
}

// idjagIssuanceAdapter projects the public [IDJAGIssuancePolicy] onto
// the internal [tokenexchange.IDJAGPolicyFunc] shape, mapping the public
// sentinels onto the internal ones the handler classifies.
func idjagIssuanceAdapter(policy IDJAGIssuancePolicy) tokenexchange.IDJAGPolicyFunc {
	if policy == nil {
		return nil
	}
	return func(ctx context.Context, req tokenexchange.IDJAGRequest) (*tokenexchange.IDJAGDecision, error) {
		decision, err := policy.Allow(ctx, IDJAGRequest{
			Client:   req.Client,
			Subject:  Subject(req.Subject),
			Audience: req.Audience,
			Resource: slices.Clone(req.Resource),
			Scope:    slices.Clone(req.Scope),
		})
		switch {
		case errors.Is(err, ErrIDJAGUnknownAudience):
			return nil, tokenexchange.ErrIDJAGUnknownAudience
		case errors.Is(err, ErrIDJAGDenied):
			return nil, tokenexchange.ErrIDJAGDenied
		case err != nil:
			return nil, err
		case decision == nil:
			return nil, nil
		}
		return &tokenexchange.IDJAGDecision{
			ClientID: decision.ClientID,
			Scope:    slices.Clone(decision.Scope),
			Resource: slices.Clone(decision.Resource),
			Email:    decision.Email,
			TTL:      decision.TTL,
		}, nil
	}
}

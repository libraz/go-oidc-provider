package op

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/customgrant/tokenexchange"
	"github.com/libraz/go-oidc-provider/internal/keys"
)

// buildExtensionDispatcher wires the customgrant dispatcher with both
// embedder-supplied custom-grant handlers and the in-tree token-
// exchange handler when [RegisterTokenExchange] was invoked. The
// helper is the single seam through which the token endpoint reaches
// the extension grants so a future addition (CIBA / device-code / ...)
// keeps the wiring local to one file.
func buildExtensionDispatcher(cfg *config, keySet *keys.Set) *customgrant.Dispatcher {
	var extras []customgrant.Handler
	if cfg.tokenExchangePolicy != nil {
		var clock interface{ Now() time.Time }
		if cfg.clock != nil {
			clock = cfg.clock
		}
		h, err := tokenexchange.New(tokenexchange.Config{
			Policy:             tokenExchangeAdapter(cfg.tokenExchangePolicy),
			Issuer:             cfg.issuer,
			Keys:               keySet,
			AccessTokens:       cfg.store.AccessTokens(),
			GrantRevocations:   cfg.store.GrantRevocations(),
			RevocationStrategy: cfg.atRevocation,
			OpaqueAccessTokens: cfg.store.OpaqueAccessTokens(),
			Audit:              cfg.effectiveAuditEmitter(),
			Clock:              clock,
			MaxAccessTTL:       cfg.accessTokenTTL,
		})
		if err == nil {
			extras = append(extras, h)
		}
		// A construction-time error here is unreachable: cfg.validate
		// gated nil policy, the keyset is non-nil by op.New invariants,
		// and the issuer is non-empty. The defensive nil check on
		// extras keeps the dispatcher correct under future changes.
	}
	return cfg.buildCustomGrantDispatcher(extras...)
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
	out := &tokenexchange.Decision{
		GrantedScope:      append([]string(nil), d.GrantedScope...),
		GrantedAudience:   append([]string(nil), d.GrantedAudience...),
		GrantedTTL:        d.GrantedTTL,
		IssueIDToken:      d.IssueIDToken,
		IssueRefreshToken: d.IssueRefreshToken,
	}
	if len(d.ExtraClaims) > 0 {
		out.ExtraClaims = make(map[string]any, len(d.ExtraClaims))
		for k, v := range d.ExtraClaims {
			out.ExtraClaims[k] = v
		}
	}
	return out
}

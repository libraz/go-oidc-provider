package tokenexchange

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/audit"
)

// Audit event names emitted by the token-exchange handler. The
// strings agree byte-for-byte with the corresponding entries in
// op.AuditEvent and an op-side guard pins the two lists together.
const (
	auditRequested             = "token_exchange.requested"
	auditGranted               = "token_exchange.granted"
	auditPolicyDenied          = "token_exchange.policy_denied"
	auditPolicyError           = "token_exchange.policy_error"
	auditScopeInflationBlocked = "token_exchange.scope_inflation_blocked"
	auditAudienceBlocked       = "token_exchange.audience_blocked"
	auditTTLCapped             = "token_exchange.ttl_capped"
	auditActChainTooDeep       = "token_exchange.act_chain_too_deep"
	auditEmptyScopeRejected    = "token_exchange.empty_scope_rejected"
	auditActorEqualsSubject    = "token_exchange.actor_equals_subject"
	auditSubjectTokenExternal  = "token_exchange.subject_token_external"
	auditActorTokenExternal    = "token_exchange.actor_token_external"
	auditSubjectTokenInvalid   = "token_exchange.subject_token_invalid"
	auditRefreshIssued         = "token_exchange.refresh_issued"
	auditSelfExchange          = "token_exchange.self_exchange"
)

// emit writes an audit event through the configured emitter, using
// audit.Discard when no emitter was supplied so callers do not need
// to nil-check at every emission site.
func (h *Handler) emit(ctx context.Context, name string, level audit.Level, msg, clientID, actor string, extras map[string]any) {
	em := h.audit
	if em == nil {
		em = audit.Discard()
	}
	em.Emit(ctx, audit.Event{
		Name:     name,
		Level:    level,
		Message:  msg,
		ClientID: clientID,
		ActorID:  actor,
		Extras:   extras,
	})
}

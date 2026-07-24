package tokenexchange

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
)

// Audit event names emitted by the token-exchange handler. Values come from
// the same registry as the public op.AuditTokenExchange* constants.
const (
	auditRequested             = string(auditevent.AuditTokenExchangeRequested)
	auditGranted               = string(auditevent.AuditTokenExchangeGranted)
	auditPolicyDenied          = string(auditevent.AuditTokenExchangePolicyDenied)
	auditPolicyError           = string(auditevent.AuditTokenExchangePolicyError)
	auditScopeInflationBlocked = string(auditevent.AuditTokenExchangeScopeInflationBlocked)
	auditAudienceBlocked       = string(auditevent.AuditTokenExchangeAudienceBlocked)
	auditTTLCapped             = string(auditevent.AuditTokenExchangeTTLCapped)
	auditActChainTooDeep       = string(auditevent.AuditTokenExchangeActChainTooDeep)
	auditEmptyScopeRejected    = string(auditevent.AuditTokenExchangeEmptyScopeRejected)
	auditActorEqualsSubject    = string(auditevent.AuditTokenExchangeActorEqualsSubject)
	auditSubjectTokenExternal  = string(auditevent.AuditTokenExchangeSubjectTokenExternal)
	auditActorTokenExternal    = string(auditevent.AuditTokenExchangeActorTokenExternal)
	auditSubjectTokenInvalid   = string(auditevent.AuditTokenExchangeSubjectTokenInvalid)
	auditRefreshIssued         = string(auditevent.AuditTokenExchangeRefreshIssued)
	auditSelfExchange          = string(auditevent.AuditTokenExchangeSelfExchange)

	// auditSubjectTokenRegistryError fires when the access-token
	// registry returned a non-ErrNotFound error during subject_token
	// (or actor_token) lookup. The wire shape is unchanged — the
	// request still collapses to invalid_grant — but operators need
	// a separate observation channel so a transient registry outage
	// (DB blip, network partition) is distinguishable from an actual
	// revocation. The event is warn-level: a healthy deployment
	// should never emit it.
	auditSubjectTokenRegistryError = string(auditevent.AuditTokenExchangeSubjectTokenRegistryError)
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

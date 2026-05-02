package authn

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/authn/audit"
)

// auditObserverAdapter wraps a [LoginAttemptObserver] so it can be
// dispatched through the audit sub-package's typed fan-out. The
// adapter translates the audit.Event back into the public-API
// LoginAttempt shape on every call so the observer contract stays
// stable.
type auditObserverAdapter struct {
	wrapped LoginAttemptObserver
}

// Observe converts evt to a [LoginAttempt] and forwards it. Foreign
// audit.Outcome values fall through to AttemptFailure as a defensive
// default; the orchestrator only emits the three known values.
func (a auditObserverAdapter) Observe(ctx context.Context, evt audit.Event) {
	a.wrapped.Observe(ctx, LoginAttempt{
		Subject:   evt.Subject,
		ClientID:  evt.ClientID,
		RemoteIP:  evt.RemoteIP,
		UserAgent: evt.UserAgent,
		Outcome:   auditOutcomeToAttempt(evt.Outcome),
		Factor:    FactorType(evt.Factor),
		Reason:    evt.Reason,
		At:        evt.At,
	})
}

// wrapAuditObservers converts the public-API observer slice into the
// audit package's slice once at orchestrator construction time so the
// per-event fan-out stays free of allocation.
func wrapAuditObservers(in []LoginAttemptObserver) []audit.Observer {
	if len(in) == 0 {
		return nil
	}
	out := make([]audit.Observer, 0, len(in))
	for _, obs := range in {
		if obs == nil {
			continue
		}
		out = append(out, auditObserverAdapter{wrapped: obs})
	}
	return out
}

// auditOutcomeToAttempt maps audit.Outcome onto AttemptOutcome. The
// mapping is one-to-one; the helper exists so the conversion stays
// centralised.
func auditOutcomeToAttempt(o audit.Outcome) AttemptOutcome {
	switch o {
	case audit.Success:
		return AttemptSuccess
	case audit.Failure:
		return AttemptFailure
	case audit.Locked:
		return AttemptLocked
	}
	return AttemptFailure
}

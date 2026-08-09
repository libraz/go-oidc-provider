package authn

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/audit"
)

// This file is the orchestrator's "audit" responsibility seam: the
// per-attempt success / failure event emitters that build an
// audit.Event from the orchestrator State and dispatch via
// [audit.FanOut] to the wrapped observer slice.
//
// Captcha events deliberately bypass these helpers — captcha is
// out-of-band from the brute-force / amr-history feed. Hard
// authenticator errors (store outage, codec misconfiguration) also
// bypass them; observers see only the soft credential-failure path
// through observeFailure.

// observeSuccess fans out an [AttemptSuccess] event to every
// observer. The orchestrator does not retry on observer panics; the
// public-API contract is "non-blocking".
func (o *Orchestrator) observeSuccess(ctx context.Context, st State, now time.Time, factor FactorType) {
	audit.FanOut(ctx, o.logger, o.auditObservers, audit.Event{
		Subject:   st.Subject,
		ClientID:  st.ClientID,
		RemoteIP:  st.RemoteIP,
		UserAgent: st.UserAgent,
		Outcome:   audit.Success,
		Factor:    string(factor),
		At:        now,
	})
}

// observeFailure fans out an [AttemptFailure] event. Subject is
// intentionally blanked on the failure path to avoid enumeration via
// the observer feed.
func (o *Orchestrator) observeFailure(ctx context.Context, st State, now time.Time, factor FactorType) {
	audit.FanOut(ctx, o.logger, o.auditObservers, audit.Event{
		ClientID:  st.ClientID,
		RemoteIP:  st.RemoteIP,
		UserAgent: st.UserAgent,
		Outcome:   audit.Failure,
		Factor:    string(factor),
		Reason:    "attempt.invalid_credentials",
		At:        now,
	})
}

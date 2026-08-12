package authn

import (
	"context"
	"time"

	opaudit "github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
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
	o.emitAttempt(ctx, st, factor, true)
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
	o.emitAttempt(ctx, st, factor, false)
}

// emitAttempt reports the same outcome to the OP-wide audit stream
// under the shared catalogue's login.* / mfa.* vocabulary.
//
// Both observe helpers funnel through here rather than emitting at
// their five call sites, because "one event per resolved factor" is
// the invariant that makes the login_attempts metric mean anything —
// spreading the emission across the legacy-chain and LoginFlow paths
// is how one of them ends up double-counting a retry.
//
// # Which name a factor gets
//
// The distinction between a primary factor and an additional one is
// read off [State.Factors] rather than from a configured position,
// because the LoginFlow path chooses factors at runtime and has no
// fixed ordering to consult. The count is authoritative at both call
// sites, but for opposite reasons: observeSuccess runs after the
// factor has been appended, so the first success sees exactly one
// entry, while observeFailure runs before any append, so a primary
// failure sees none. Nothing else in the orchestrator may reorder
// those two operations without changing what these events mean.
//
// # Subject on the failure path
//
// The observer feed blanks Subject on failure so an embedder policy
// hook cannot be turned into a user-enumeration oracle. This stream
// carries it. The two are not in tension: the observer feed runs
// inside the attempt and its output can steer the response, whereas
// the audit stream reaches the embedder's own sink and nothing on the
// wire. Withholding the subject here would leave the record unable to
// answer the one question a failed-login audit exists for — which
// account was being guessed at.
func (o *Orchestrator) emitAttempt(ctx context.Context, st State, factor FactorType, success bool) {
	name, level, message := auditevent.AuditLoginSuccess, opaudit.LevelInfo, "primary authentication factor succeeded"
	switch {
	case success && len(st.Factors) > 1:
		name, message = auditevent.AuditMFASuccess, "additional authentication factor succeeded"
	case !success && len(st.Factors) > 0:
		name, level, message = auditevent.AuditMFAFailed, opaudit.LevelWarn, "additional authentication factor failed"
	case !success:
		name, level, message = auditevent.AuditLoginFailed, opaudit.LevelWarn, "primary authentication factor failed"
	}
	o.auditEmitter.Emit(ctx, opaudit.Event{
		Name:      string(name),
		Level:     level,
		Message:   message,
		ActorID:   st.Subject,
		ClientID:  st.ClientID,
		IP:        st.RemoteIP.String(),
		UserAgent: st.UserAgent,
		Extras:    map[string]any{"factor": string(factor)},
	})
}

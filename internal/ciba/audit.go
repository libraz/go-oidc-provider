package ciba

import "github.com/libraz/go-oidc-provider/internal/auditevent"

// Audit event names emitted across the CIBA flow. Values come from the shared
// typed registry that also backs op.AuditCIBA*.
//
// The names group by surface:
//
//   - ciba.authorization.* — events from POST /bc-authorize (the
//     backchannel-authentication endpoint).
//   - ciba.auth_device.* — events from the embedder's authentication
//     device interaction (Approve / Deny callbacks into the
//     CIBARequestStore substore).
//   - ciba.poll_abuse.* — events from the poll-violation counter
//     when the strike cap is reached and the record is locked.
//   - ciba.token.* — events from the token-endpoint CIBA grant
//     (POST /token with the CIBA grant_type URN).
const (
	// AuditAuthorizationIssued is emitted when /bc-authorize
	// successfully mints an auth_req_id. Extras carry: client_id,
	// scope, resource, expires_in, interval, binding ("dpop",
	// "mtls", or "bearer"), hint_kind ("login_hint",
	// "id_token_hint", or "login_hint_token").
	AuditAuthorizationIssued = string(auditevent.AuditCIBAAuthorizationIssued)

	// AuditAuthorizationRejected is emitted when /bc-authorize
	// rejects the request before issuing an auth_req_id. Extras
	// carry: client_id (when resolved), reason (a stable code
	// string mirroring the wire error).
	AuditAuthorizationRejected = string(auditevent.AuditCIBAAuthorizationRejected)

	// AuditAuthorizationUnboundRejected is emitted when
	// /bc-authorize rejects an unbound request under the FAPI 2.0
	// baseline profile (sender-constraint required). Extras carry:
	// client_id, profile, reason="unbound_request".
	AuditAuthorizationUnboundRejected = string(auditevent.AuditCIBAAuthorizationUnboundRejected)

	// AuditAuthDeviceApproved is emitted when the embedder's
	// authentication device transitions a Pending record to
	// Approved. Extras carry: client_id, subject, scope, resource.
	AuditAuthDeviceApproved = string(auditevent.AuditCIBAAuthDeviceApproved)

	// AuditAuthDeviceDenied is emitted when the embedder's
	// authentication device transitions a Pending record to Denied.
	// Extras carry: client_id, reason ("user_denied",
	// "auth_device_timeout", "poll_abuse", or an embedder-supplied
	// value).
	AuditAuthDeviceDenied = string(auditevent.AuditCIBAAuthDeviceDenied)

	// AuditPollAbuseLockout is emitted when the poll-violation
	// counter reaches [MaxPollViolations] and the token endpoint
	// locks the record to access_denied. Extras carry: client_id,
	// strikes (the post-increment counter), max_strikes
	// ([MaxPollViolations]).
	AuditPollAbuseLockout = string(auditevent.AuditCIBAPollAbuseLockout)

	// AuditTokenIssued is emitted when the token endpoint
	// successfully redeems an auth_req_id. Extras carry: client_id,
	// subject, scope, audience, sender_constraint ("dpop", "mtls",
	// or "bearer").
	AuditTokenIssued = string(auditevent.AuditCIBATokenIssued)

	// AuditTokenRejected is emitted when the token-endpoint CIBA
	// grant rejects a poll. Extras carry: client_id, reason (the
	// wire error: authorization_pending, slow_down, access_denied,
	// expired_token, invalid_grant).
	AuditTokenRejected = string(auditevent.AuditCIBATokenRejected)

	// AuditTokenSlowDown is emitted alongside AuditTokenRejected
	// when the rejection cause is slow_down. Extras carry:
	// client_id, observed_interval (the gap the client polled at),
	// effective_interval (the value before doubling),
	// next_interval (the value after doubling).
	AuditTokenSlowDown = string(auditevent.AuditCIBATokenSlowDown)

	// AuditPollObservationFailed is emitted when the token-endpoint
	// CIBA grant observed a non-nil error from
	// [CIBARequestStore.RecordPoll]. The wire response is unchanged
	// — the poll decision still proceeds because the stamp is
	// best-effort observability rather than a single-use gate — but
	// the slow_down ladder reads a stale LastPolledAt on the next
	// poll, which may skip violations. The event is warn-level so
	// a transient substore outage that quietly defeats the ladder
	// is still visible. Extras carry: client_id, error (the
	// stringified store error).
	AuditPollObservationFailed = string(auditevent.AuditCIBAPollObservationFailed)
)

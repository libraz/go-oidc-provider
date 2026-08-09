package devicecode

import "github.com/libraz/go-oidc-provider/internal/auditevent"

// Audit event names emitted across the device flow. Values come from the
// shared typed registry that also backs op.AuditDeviceCode*.
//
// The names group by surface:
//
//   - device_authorization.* — events from POST /device_authorization
//     (the device-issuing endpoint).
//   - device_code.verification.* — events from the verification
//     ceremony (the user-facing /device page).
//   - device_code.token.* — events from the token-endpoint
//     device_code grant (POST /token with the device_code URN).
const (
	// AuditAuthorizationIssued is emitted when /device_authorization
	// successfully mints a device_code / user_code pair. Extras
	// carry: client_id, scope, resource, dpop_jkt or
	// mtls_cert_s256 (when bound), expires_in, interval.
	AuditAuthorizationIssued = string(auditevent.AuditDeviceAuthorizationIssued)

	// AuditAuthorizationRejected is emitted when
	// /device_authorization rejects the request before issuing a
	// pair. Extras carry: client_id (when resolved), reason
	// (a stable code string mirroring the wire error), profile
	// (when a profile gate fired).
	AuditAuthorizationRejected = string(auditevent.AuditDeviceAuthorizationRejected)

	// AuditAuthorizationUnboundRejected is emitted when
	// /device_authorization rejects an unbound request under the
	// FAPI 2.0 baseline profile (Q5 sender-constraint). Extras
	// carry: client_id, profile, reason="unbound_request".
	AuditAuthorizationUnboundRejected = string(auditevent.AuditDeviceAuthorizationUnboundRejected)

	// AuditVerificationApproved is emitted when the verification
	// page transitions a Pending record to Approved. Extras carry:
	// client_id, subject, scope, resource.
	AuditVerificationApproved = string(auditevent.AuditDeviceCodeVerificationApproved)

	// AuditVerificationDenied is emitted when the verification page
	// transitions a Pending record to Denied. Extras carry:
	// client_id, reason ("user_denied" or
	// "user_code_lockout" or an embedder-supplied value).
	AuditVerificationDenied = string(auditevent.AuditDeviceCodeVerificationDenied)

	// AuditUserCodeBruteForce is emitted on each failed user_code
	// submission against an active record. Extras carry:
	// strikes (the post-increment counter), max_strikes
	// ([MaxUserCodeStrikes]). The verification page calls
	// AuditVerificationDenied with reason="user_code_lockout"
	// when strikes reaches max.
	AuditUserCodeBruteForce = string(auditevent.AuditDeviceCodeUserCodeBruteForce)

	// AuditTokenIssued is emitted when the token endpoint
	// successfully redeems a device_code. Extras carry: client_id,
	// subject, scope, audience, ttl_bucket, sender_constraint
	// ("dpop", "mtls", or "bearer").
	AuditTokenIssued = string(auditevent.AuditDeviceCodeTokenIssued)

	// AuditTokenRejected is emitted when the token-endpoint
	// device_code grant rejects a poll. Extras carry: client_id,
	// reason (the wire error: authorization_pending, slow_down,
	// access_denied, expired_token, invalid_grant).
	AuditTokenRejected = string(auditevent.AuditDeviceCodeTokenRejected)

	// AuditTokenSlowDown is emitted alongside AuditTokenRejected
	// when the rejection cause is slow_down. Extras carry:
	// client_id, observed_interval (the gap the device polled at),
	// effective_interval (the bar before the ladder advanced),
	// next_interval (the bar after it advanced).
	AuditTokenSlowDown = string(auditevent.AuditDeviceCodeTokenSlowDown)

	// AuditRevoked is emitted by the public revoke helper that wraps
	// [store.DeviceCodeStore.Deny] with an audit signal so SOC tooling
	// and embedder cascade-revoke subscribers can react to a denied
	// device authorization in one place. Extras carry: client_id,
	// reason (the embedder-supplied or library-default value, e.g.
	// "user_denied", "user_code_lockout", "user_revoked_device"), and,
	// when the revoke helper was given an [store.AccessTokenRegistry],
	// the revoked_access_tokens count. The helper cascade-revokes every
	// access token whose grant_id matches the device_code so the
	// per-grant cascade fires inside the library.
	AuditRevoked = string(auditevent.AuditDeviceCodeRevoked)

	// AuditPollObservationFailed is emitted when the token-endpoint
	// device_code grant observed a non-nil error from
	// [store.DeviceCodeStore.RecordPoll]. The wire response is
	// unchanged — the poll decision still proceeds because the
	// stamp is best-effort observability rather than a single-use
	// gate — but the slow_down ladder reads a stale LastPolledAt on
	// the next poll, which may skip violations. The event is
	// warn-level so a transient substore outage that quietly
	// defeats the ladder is still visible. Extras carry: client_id,
	// error (the stringified store error). Mirrors
	// [github.com/libraz/go-oidc-provider/internal/ciba.AuditPollObservationFailed]
	// for the CIBA surface.
	AuditPollObservationFailed = string(auditevent.AuditDeviceCodePollObservationFailed)
)

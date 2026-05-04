package op

// AuditEvent identifies a structured audit event the OP emits. The
// constants below are the closed catalogue handler code selects from;
// new event names are added here once the handler that emits them
// lands.
//
// The naming convention is "<area>.<verb>" (or
// "<area>.<verb>.<qualifier>") so dashboards can pre-aggregate by
// area without parsing a free-form message.
//
// When [WithPrometheus] is configured, a curated subset of these
// events is mirrored onto Prometheus counters by the package-internal
// metrics bridge — a single emission updates both the slog audit
// stream and the matching counter.
//
// Stable since v0.1. New events MAY be added in a minor release;
// existing event names are part of the API surface and only renamed
// in a major release with a deprecation notice.
type AuditEvent string

// Account-management events. Most fire from out-of-band admin paths
// the OP does not host directly; they are listed here so a single
// catalogue exists for SOC dashboards to subscribe to.
const (
	AuditAccountCreated             = AuditEvent("account.created")
	AuditAccountDeleted             = AuditEvent("account.deleted")
	AuditAccountEmailAdded          = AuditEvent("account.email.added")
	AuditAccountEmailVerified       = AuditEvent("account.email.verified")
	AuditAccountEmailRemoved        = AuditEvent("account.email.removed")
	AuditAccountEmailSetPrimary     = AuditEvent("account.email.set_primary")
	AuditAccountPasskeyRegistered   = AuditEvent("account.passkey.registered")
	AuditAccountPasskeyRemoved      = AuditEvent("account.passkey.removed")
	AuditAccountTOTPEnabled         = AuditEvent("account.totp.enabled")
	AuditAccountTOTPDisabled        = AuditEvent("account.totp.disabled")
	AuditAccountPasswordChanged     = AuditEvent("account.password.changed")
	AuditAccountRecoveryRegenerated = AuditEvent("account.recovery_codes.regenerated")
	AuditRecoverySupportEscalation  = AuditEvent("recovery.support_escalation")
	AuditAccountFederationLinked    = AuditEvent("federation.linked")
	AuditAccountFederationUnlinked  = AuditEvent("federation.unlinked")
)

// Login / MFA / step-up events. Fire from the authenticator chain
// after each factor resolves.
const (
	AuditLoginSuccess   = AuditEvent("login.success")
	AuditLoginFailed    = AuditEvent("login.failed")
	AuditMFARequired    = AuditEvent("mfa.required")
	AuditMFASuccess     = AuditEvent("mfa.success")
	AuditMFAFailed      = AuditEvent("mfa.failed")
	AuditStepUpRequired = AuditEvent("step_up.required")
	AuditStepUpSuccess  = AuditEvent("step_up.success")
)

// Consent events. AuditConsentSkippedExisting fires when the existing
// grant already covers the requested scope set; AuditConsentGrantedFirstParty
// fires when first-party auto-consent applies; AuditConsentGrantedDelta
// fires when delta-consent forces a re-prompt for a newly requested
// sensitive scope.
const (
	AuditConsentGranted           = AuditEvent("consent.granted")
	AuditConsentGrantedFirstParty = AuditEvent("consent.granted.first_party")
	AuditConsentGrantedDelta      = AuditEvent("consent.granted.delta")
	AuditConsentSkippedExisting   = AuditEvent("consent.skipped.existing")
	AuditConsentRevoked           = AuditEvent("consent.revoked")
)

// Code / token events. Fire from the authorize-code issuance path
// and the token / revoke endpoints. AuditTokenRevokeFailed is the
// /revoke companion to AuditTokenRevoked: the wire response stays
// HTTP 200 per RFC 7009 §2.2, but a non-NotFound storage fault
// raises this event so SOC tooling can detect the silent-failure
// class (GHSA-7mqr-2v3q-v2wm).
//
// AuditRefreshChainRevokeFailed and AuditRefreshGrantRevokeFailed fire
// when a refresh-token replay detection successfully observes the
// replay (the wire response is invalid_grant) but the cascade side-
// effects encounter a transport fault. The events are warn-level and
// surface so SOC tooling can distinguish "chain successfully revoked"
// from "chain revoke silently failed" — the latter leaves the
// rotation chain intact even though the wire response indicated
// rejection, which is the audit gap H-A2 closes.
const (
	AuditCodeIssued               = AuditEvent("code.issued")
	AuditCodeConsumed             = AuditEvent("code.consumed")
	AuditCodeReplayDetected       = AuditEvent("code.replay_detected")
	AuditTokenIssued              = AuditEvent("token.issued")
	AuditTokenRefreshed           = AuditEvent("token.refreshed")
	AuditTokenRevoked             = AuditEvent("token.revoked")
	AuditTokenRevokeFailed        = AuditEvent("token.revoke_failed")
	AuditRefreshReplayDetected    = AuditEvent("refresh.replay_detected")
	AuditRefreshChainRevokeFailed = AuditEvent("refresh.chain_revoke_failed")
	AuditRefreshGrantRevokeFailed = AuditEvent("refresh.grant_revoke_failed")
)

// Session / logout events. Fire from the session manager and the
// /end_session handler.
const (
	AuditSessionCreated             = AuditEvent("session.created")
	AuditSessionDestroyed           = AuditEvent("session.destroyed")
	AuditLogoutRPInitiated          = AuditEvent("logout.rp_initiated")
	AuditLogoutBackChannelDelivered = AuditEvent("logout.back_channel.delivered")
	AuditLogoutBackChannelFailed    = AuditEvent("logout.back_channel.failed")

	// AuditBCLNoSessionsForSubject fires when /end_session or
	// Provider.Logout names a session_id-bearing subject but the
	// back-channel coordinator finds zero RPs to notify. Under a
	// volatile SessionStore (Redis without persistence, Memcached,
	// or any in-memory tier under maxmemory eviction) this is the
	// signal that a session was evicted between establishment and
	// logout, narrowing OIDC Back-Channel Logout 1.0 §2.7's
	// best-effort delivery floor to zero. INFO-level: under volatile
	// placement the gap is expected; SOC tooling alerts on elevated
	// rates rather than per-event.
	AuditBCLNoSessionsForSubject = AuditEvent("bcl.no_sessions_for_subject")
)

// Defensive events. Fire from request-validation paths that detect
// abuse signals or operator-visible policy hits.
const (
	AuditRateLimitExceeded   = AuditEvent("rate_limit.exceeded")
	AuditRateLimitBypassed   = AuditEvent("rate_limit.bypassed")
	AuditPKCEViolation       = AuditEvent("pkce.violation")
	AuditRedirectURIMismatch = AuditEvent("redirect_uri.mismatch")
	AuditAlgLegacyUsed       = AuditEvent("alg.legacy_used")

	// AuditCORSPreflightAllowed fires every time the strict CORS layer
	// admits a cross-origin OPTIONS preflight (Origin in allowlist,
	// Access-Control-Request-Method present). The event surfaces the
	// short-circuit so SOC tooling can correlate dashboards that
	// otherwise observe only the actual (non-preflight) request — the
	// CORS wrapper answers the preflight with 204 directly and bypasses
	// every inner handler / outer middleware that the embedder
	// configured *below* the wrapper. The CORS handler MUST sit
	// outermost so embedder middleware (rate-limit, audit, metrics)
	// observes the request before this short-circuit; the audit event
	// makes the short-circuit visible regardless of wrapper order.
	AuditCORSPreflightAllowed = AuditEvent("cors.preflight.allowed")

	// AuditDPoPLooseMethodCaseAdmitted fires when the embedder has
	// opted into the DPoP verifier's AllowLooseMethodCase bridge AND
	// a proof was admitted whose "htm" claim differed from the
	// request method only in ASCII case. The wire response is
	// unchanged — the proof was admitted — but SOC tooling needs
	// the signal so the loose-mode bridge stays visible while the
	// responsible RP library is fixed. The RFC 9449 §4.3 strict
	// posture is the default; loose mode is opt-in and produces
	// this warn-level event on every admission.
	AuditDPoPLooseMethodCaseAdmitted = AuditEvent("dpop.loose_method_case_admitted")

	// AuditKeyRetiredKidPresented fires when a JWS / JWE presented
	// for verification carries a "kid" header that matches an entry
	// in the OP signing keyset whose [SigningKey.NotAfter] retirement
	// deadline has elapsed. The wire response is the existing
	// signature-invalid taxonomy — the verifier treats the kid as if
	// it were unknown — but SOC tooling needs the signal because a
	// retired kid surfacing at verification time is the canonical
	// "rotation-after-leak token forge" attempt: an attacker who
	// captured the old private key before the rotation tries to ride
	// past the JWKS grace window by minting a fresh JWS that names
	// the retiring kid. The event is warn-level and carries the
	// rejected kid in [Event.Extras] so dashboards can correlate
	// against the rotation timeline without parsing the slog message.
	// Tracks H-F1.
	AuditKeyRetiredKidPresented = AuditEvent("key.retired_kid_presented")
)

// Introspection events. Fire from the /introspect endpoint. Only the
// pre-authentication failure is surfaced today: a client that presents
// invalid credentials at /introspect MUST be visible to SOC tooling so
// the embedder can spot probing for a known client_id even though RFC
// 7662 §2.3 mandates the wire response stays at the generic
// "invalid_client" code.
const (
	AuditIntrospectionError = AuditEvent("introspection.error")
)

// Client authentication events. Fire from every pre-issuance surface
// that runs the client-authentication chain (/token, /par). The wire
// response is collapsed onto the canonical RFC 6749 §5.2 "invalid_client"
// shape — it deliberately hides whether the client_id was unknown, the
// secret was wrong, or the signed assertion failed verification — so SOC
// tooling needs an audit signal that carries the attempted client_id (when
// known), the auth method, and a short reason code for triage. This event
// fills that gap; the wire shape is unchanged.
const (
	AuditClientAuthnFailure = AuditEvent("client_authn.failure")
)

// Dynamic Client Registration events. Fire from /register and
// /register/{client_id}.
const (
	AuditDCRIATConsumed           = AuditEvent("dcr.iat.consumed")
	AuditDCRIATExpired            = AuditEvent("dcr.iat.expired")
	AuditDCRIATInvalid            = AuditEvent("dcr.iat.invalid")
	AuditDCROpenRegistrationUsed  = AuditEvent("dcr.open_registration_used")
	AuditDCRClientRegistered      = AuditEvent("dcr.client.registered")
	AuditDCRClientMetadataRead    = AuditEvent("dcr.client.metadata_read")
	AuditDCRClientMetadataUpdated = AuditEvent("dcr.client.metadata_updated")
	AuditDCRClientDeleted         = AuditEvent("dcr.client.deleted")
	AuditDCRRATInvalid            = AuditEvent("dcr.rat.invalid")
	AuditDCRMetadataValidation    = AuditEvent("dcr.metadata.validation_failed")
)

// Device-flow events. Fire from the /device_authorization endpoint,
// the verification ceremony, and the token-endpoint device_code grant.
// The internal package cannot import op (one-way import graph), so the
// values are duplicated as raw strings inside
// internal/devicecode/audit.go and a mirror test (TestAuditEvent_DeviceCodeMirror)
// pins them together.
const (
	AuditDeviceAuthorizationIssued          = AuditEvent("device_authorization.issued")
	AuditDeviceAuthorizationRejected        = AuditEvent("device_authorization.rejected")
	AuditDeviceAuthorizationUnboundRejected = AuditEvent("device_authorization.unbound_rejected")
	AuditDeviceCodeVerificationApproved     = AuditEvent("device_code.verification.approved")
	AuditDeviceCodeVerificationDenied       = AuditEvent("device_code.verification.denied")
	AuditDeviceCodeUserCodeBruteForce       = AuditEvent("device_code.verification.user_code_brute_force")
	AuditDeviceCodeTokenIssued              = AuditEvent("device_code.token.issued")
	AuditDeviceCodeTokenRejected            = AuditEvent("device_code.token.rejected")
	AuditDeviceCodeTokenSlowDown            = AuditEvent("device_code.token.slow_down")
)

// CIBA events. Fire from the /bc-authorize endpoint, the embedder's
// authentication-device interaction, and the token-endpoint CIBA
// grant. The internal package cannot import op (one-way import graph),
// so the values are duplicated as raw strings inside
// internal/ciba/audit.go and a mirror test (TestAuditEvent_CIBAMirror)
// pins them together.
const (
	AuditCIBAAuthorizationIssued          = AuditEvent("ciba.authorization.issued")
	AuditCIBAAuthorizationRejected        = AuditEvent("ciba.authorization.rejected")
	AuditCIBAAuthorizationUnboundRejected = AuditEvent("ciba.authorization.unbound_rejected")
	AuditCIBAAuthDeviceApproved           = AuditEvent("ciba.auth_device.approved")
	AuditCIBAAuthDeviceDenied             = AuditEvent("ciba.auth_device.denied")
	AuditCIBAPollAbuseLockout             = AuditEvent("ciba.poll_abuse.lockout")
	AuditCIBATokenIssued                  = AuditEvent("ciba.token.issued")
	AuditCIBATokenRejected                = AuditEvent("ciba.token.rejected")
	AuditCIBATokenSlowDown                = AuditEvent("ciba.token.slow_down")

	// AuditCIBAPollObservationFailed fires when the token-endpoint
	// CIBA grant observed a substore fault while persisting the
	// LastPolledAt stamp on a poll. The wire response is unchanged —
	// the poll decision still proceeds, fail-open, because the
	// stamp is best-effort observability rather than a single-use
	// gate — but SOC tooling needs the signal so a transient store
	// outage that quietly defeats the slow_down ladder is visible.
	// Warn-level: a healthy deployment should never emit this event.
	AuditCIBAPollObservationFailed = AuditEvent("ciba.poll_observation.failed")
)

// Token-exchange events. Fire from the in-tree RFC 8693 handler.
// Every successful exchange emits Requested + Granted; rejections
// emit Requested + one of the failure-class events depending on the
// gate that fired. The internal package cannot import op (one-way
// import graph), so the values are duplicated as raw strings inside
// internal/customgrant/tokenexchange/audit.go and a mirror test
// pins them together.
const (
	AuditTokenExchangeRequested             = AuditEvent("token_exchange.requested")
	AuditTokenExchangeGranted               = AuditEvent("token_exchange.granted")
	AuditTokenExchangePolicyDenied          = AuditEvent("token_exchange.policy_denied")
	AuditTokenExchangePolicyError           = AuditEvent("token_exchange.policy_error")
	AuditTokenExchangeScopeInflationBlocked = AuditEvent("token_exchange.scope_inflation_blocked")
	AuditTokenExchangeAudienceBlocked       = AuditEvent("token_exchange.audience_blocked")
	AuditTokenExchangeTTLCapped             = AuditEvent("token_exchange.ttl_capped")
	AuditTokenExchangeActChainTooDeep       = AuditEvent("token_exchange.act_chain_too_deep")
	AuditTokenExchangeEmptyScopeRejected    = AuditEvent("token_exchange.empty_scope_rejected")
	AuditTokenExchangeActorEqualsSubject    = AuditEvent("token_exchange.actor_equals_subject")
	AuditTokenExchangeSubjectTokenExternal  = AuditEvent("token_exchange.subject_token_external")
	AuditTokenExchangeActorTokenExternal    = AuditEvent("token_exchange.actor_token_external")
	AuditTokenExchangeSubjectTokenInvalid   = AuditEvent("token_exchange.subject_token_invalid")
	AuditTokenExchangeRefreshIssued         = AuditEvent("token_exchange.refresh_issued")
	AuditTokenExchangeSelfExchange          = AuditEvent("token_exchange.self_exchange")
)

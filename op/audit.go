package op

import "github.com/libraz/go-oidc-provider/internal/auditevent"

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

// AuditEventDefinition describes one row in the OP's closed audit-event
// catalog. MetricName is empty for audit-only events. MetricLabel is the
// bounded label value used by category or fixed-kind counters; it is empty for
// scalar counters and counters whose labels come from structured event fields.
type AuditEventDefinition struct {
	Event       AuditEvent
	MetricName  string
	MetricLabel string
}

// AuditEventCatalog returns a copy of the complete audit-event catalog. The
// same internal registry drives the Prometheus bridge, so event discovery and
// metric routing cannot drift.
func AuditEventCatalog() []AuditEventDefinition {
	internalCatalog := auditevent.Catalog()
	out := make([]AuditEventDefinition, 0, len(internalCatalog))
	for _, definition := range internalCatalog {
		out = append(out, AuditEventDefinition{
			Event:       AuditEvent(definition.Name),
			MetricName:  auditevent.MetricName(definition.Metric),
			MetricLabel: definition.Label,
		})
	}
	return out
}

// Account-management events. Most fire from out-of-band admin paths
// the OP does not host directly; they are listed here so a single
// catalogue exists for SOC dashboards to subscribe to.
const (
	AuditAccountCreated             = AuditEvent(auditevent.AuditAccountCreated)
	AuditAccountDeleted             = AuditEvent(auditevent.AuditAccountDeleted)
	AuditAccountEmailAdded          = AuditEvent(auditevent.AuditAccountEmailAdded)
	AuditAccountEmailVerified       = AuditEvent(auditevent.AuditAccountEmailVerified)
	AuditAccountEmailRemoved        = AuditEvent(auditevent.AuditAccountEmailRemoved)
	AuditAccountEmailSetPrimary     = AuditEvent(auditevent.AuditAccountEmailSetPrimary)
	AuditAccountPasskeyRegistered   = AuditEvent(auditevent.AuditAccountPasskeyRegistered)
	AuditAccountPasskeyRemoved      = AuditEvent(auditevent.AuditAccountPasskeyRemoved)
	AuditAccountTOTPEnabled         = AuditEvent(auditevent.AuditAccountTOTPEnabled)
	AuditAccountTOTPDisabled        = AuditEvent(auditevent.AuditAccountTOTPDisabled)
	AuditAccountPasswordChanged     = AuditEvent(auditevent.AuditAccountPasswordChanged)
	AuditAccountRecoveryRegenerated = AuditEvent(auditevent.AuditAccountRecoveryRegenerated)
	AuditRecoverySupportEscalation  = AuditEvent(auditevent.AuditRecoverySupportEscalation)
	AuditAccountFederationLinked    = AuditEvent(auditevent.AuditAccountFederationLinked)
	AuditAccountFederationUnlinked  = AuditEvent(auditevent.AuditAccountFederationUnlinked)
)

// Login / MFA / step-up events. Fire from the authenticator chain
// after each factor resolves.
const (
	AuditLoginSuccess   = AuditEvent(auditevent.AuditLoginSuccess)
	AuditLoginFailed    = AuditEvent(auditevent.AuditLoginFailed)
	AuditMFARequired    = AuditEvent(auditevent.AuditMFARequired)
	AuditMFASuccess     = AuditEvent(auditevent.AuditMFASuccess)
	AuditMFAFailed      = AuditEvent(auditevent.AuditMFAFailed)
	AuditStepUpRequired = AuditEvent(auditevent.AuditStepUpRequired)
	AuditStepUpSuccess  = AuditEvent(auditevent.AuditStepUpSuccess)
)

// Consent events. AuditConsentSkippedExisting fires when the existing
// grant already covers the requested scope set; AuditConsentGrantedFirstParty
// fires when first-party auto-consent applies; AuditConsentGrantedDelta
// fires when delta-consent forces a re-prompt for a newly requested
// sensitive scope.
const (
	AuditConsentGranted           = AuditEvent(auditevent.AuditConsentGranted)
	AuditConsentGrantedFirstParty = AuditEvent(auditevent.AuditConsentGrantedFirstParty)
	AuditConsentGrantedDelta      = AuditEvent(auditevent.AuditConsentGrantedDelta)
	AuditConsentSkippedExisting   = AuditEvent(auditevent.AuditConsentSkippedExisting)
	AuditConsentRevoked           = AuditEvent(auditevent.AuditConsentRevoked)
)

// Grant-management events. Fire from the OAuth 2.0 Grant Management
// endpoint after a client successfully revokes one of its own grants.
const (
	AuditGrantManagementRevoked = AuditEvent(auditevent.AuditGrantManagementRevoked)
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
	AuditCodeIssued               = AuditEvent(auditevent.AuditCodeIssued)
	AuditCodeConsumed             = AuditEvent(auditevent.AuditCodeConsumed)
	AuditCodeReplayDetected       = AuditEvent(auditevent.AuditCodeReplayDetected)
	AuditTokenIssued              = AuditEvent(auditevent.AuditTokenIssued)
	AuditTokenRefreshed           = AuditEvent(auditevent.AuditTokenRefreshed)
	AuditTokenRevoked             = AuditEvent(auditevent.AuditTokenRevoked)
	AuditTokenRevokeFailed        = AuditEvent(auditevent.AuditTokenRevokeFailed)
	AuditRefreshReplayDetected    = AuditEvent(auditevent.AuditRefreshReplayDetected)
	AuditRefreshChainRevokeFailed = AuditEvent(auditevent.AuditRefreshChainRevokeFailed)
	AuditRefreshGrantRevokeFailed = AuditEvent(auditevent.AuditRefreshGrantRevokeFailed)
)

// Session / logout events. Fire from the session manager and the
// /end_session handler.
const (
	AuditSessionCreated                 = AuditEvent(auditevent.AuditSessionCreated)
	AuditSessionDestroyed               = AuditEvent(auditevent.AuditSessionDestroyed)
	AuditSessionAlreadyAbsent           = AuditEvent(auditevent.AuditSessionAlreadyAbsent)
	AuditSessionDestroyFailed           = AuditEvent(auditevent.AuditSessionDestroyFailed)
	AuditLogoutRPInitiated              = AuditEvent(auditevent.AuditLogoutRPInitiated)
	AuditLogoutTokenRevokeFailed        = AuditEvent(auditevent.AuditLogoutTokenRevokeFailed)
	AuditLogoutBackChannelDelivered     = AuditEvent(auditevent.AuditLogoutBackChannelDelivered)
	AuditLogoutBackChannelFailed        = AuditEvent(auditevent.AuditLogoutBackChannelFailed)
	AuditLogoutBackChannelResolveFailed = AuditEvent(auditevent.AuditLogoutBackChannelResolveFailed)
	AuditLogoutBackChannelOverflow      = AuditEvent(auditevent.AuditLogoutBackChannelOverflow)

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
	AuditBCLNoSessionsForSubject = AuditEvent(auditevent.AuditBCLNoSessionsForSubject)
)

// Defensive events. Fire from request-validation paths that detect
// abuse signals or operator-visible policy hits.
const (
	// AuditRateLimitExceeded and AuditRateLimitBypassed are reserved
	// vocabulary for embedder-emitted events from operator-side
	// rate-limit middleware (reverse proxy, gateway, Go handler
	// chains). The library does NOT implement a generic per-IP /
	// per-endpoint HTTP rate limit — that responsibility lives with
	// the embedder per the project charter. The OP only owns the
	// authentication-flow brute-force gate wired through
	// [WithAuthnLockoutStore] (and the device-code user-code gate
	// surfaced via [AuditDeviceCodeUserCodeBruteForce]); those paths
	// emit their own dedicated events. These two constants exist so
	// audit pipelines can ingest embedder-side throttle decisions
	// under a vocabulary consistent with the rest of the OIDC
	// audit catalog.
	AuditRateLimitExceeded   = AuditEvent(auditevent.AuditRateLimitExceeded)
	AuditRateLimitBypassed   = AuditEvent(auditevent.AuditRateLimitBypassed)
	AuditPKCEViolation       = AuditEvent(auditevent.AuditPKCEViolation)
	AuditRedirectURIMismatch = AuditEvent(auditevent.AuditRedirectURIMismatch)
	AuditAlgLegacyUsed       = AuditEvent(auditevent.AuditAlgLegacyUsed)

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
	AuditCORSPreflightAllowed = AuditEvent(auditevent.AuditCORSPreflightAllowed)

	// AuditDPoPLooseMethodCaseAdmitted fires when the embedder has
	// opted into the DPoP verifier's AllowLooseMethodCase bridge AND
	// a proof was admitted whose "htm" claim differed from the
	// request method only in ASCII case. The wire response is
	// unchanged — the proof was admitted — but SOC tooling needs
	// the signal so the loose-mode bridge stays visible while the
	// responsible RP library is fixed. The RFC 9449 §4.3 strict
	// posture is the default; loose mode is opt-in and produces
	// this warn-level event on every admission.
	AuditDPoPLooseMethodCaseAdmitted = AuditEvent(auditevent.AuditDPoPLooseMethodCaseAdmitted)

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
	AuditKeyRetiredKidPresented = AuditEvent(auditevent.AuditKeyRetiredKidPresented)
)

// Introspection events. Fire from the /introspect endpoint. Only the
// pre-authentication failure is surfaced today: a client that presents
// invalid credentials at /introspect MUST be visible to SOC tooling so
// the embedder can spot probing for a known client_id even though RFC
// 7662 §2.3 mandates the wire response stays at the generic
// "invalid_client" code.
const (
	AuditIntrospectionError = AuditEvent(auditevent.AuditIntrospectionError)
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
	AuditClientAuthnFailure = AuditEvent(auditevent.AuditClientAuthnFailure)
)

// Dynamic Client Registration events. Fire from /register and
// /register/{client_id}.
const (
	AuditDCRIATConsumed           = AuditEvent(auditevent.AuditDCRIATConsumed)
	AuditDCRIATExpired            = AuditEvent(auditevent.AuditDCRIATExpired)
	AuditDCRIATInvalid            = AuditEvent(auditevent.AuditDCRIATInvalid)
	AuditDCROpenRegistrationUsed  = AuditEvent(auditevent.AuditDCROpenRegistrationUsed)
	AuditDCRClientRegistered      = AuditEvent(auditevent.AuditDCRClientRegistered)
	AuditDCRClientMetadataRead    = AuditEvent(auditevent.AuditDCRClientMetadataRead)
	AuditDCRClientMetadataUpdated = AuditEvent(auditevent.AuditDCRClientMetadataUpdated)
	AuditDCRClientDeleted         = AuditEvent(auditevent.AuditDCRClientDeleted)
	AuditDCRRATInvalid            = AuditEvent(auditevent.AuditDCRRATInvalid)
	AuditDCRMetadataValidation    = AuditEvent(auditevent.AuditDCRMetadataValidation)

	// Cascade failures are operational signals emitted after a client record
	// has been deleted but one credential substore could not revoke its rows.
	AuditDCRCascadeRefreshRevokeFailed           = AuditEvent(auditevent.AuditDCRCascadeRefreshRevokeFailed)
	AuditDCRCascadeGrantRevokeFailed             = AuditEvent(auditevent.AuditDCRCascadeGrantRevokeFailed)
	AuditDCRCascadeAccessTokenRevokeFailed       = AuditEvent(auditevent.AuditDCRCascadeAccessTokenRevokeFailed)
	AuditDCRCascadeOpaqueAccessTokenRevokeFailed = AuditEvent(auditevent.AuditDCRCascadeOpaqueAccessTokenRevokeFailed)
)

// Device-flow events. Fire from the /device_authorization endpoint,
// the verification ceremony, and the token-endpoint device_code grant.
const (
	AuditDeviceAuthorizationIssued          = AuditEvent(auditevent.AuditDeviceAuthorizationIssued)
	AuditDeviceAuthorizationRejected        = AuditEvent(auditevent.AuditDeviceAuthorizationRejected)
	AuditDeviceAuthorizationUnboundRejected = AuditEvent(auditevent.AuditDeviceAuthorizationUnboundRejected)
	AuditDeviceCodeVerificationApproved     = AuditEvent(auditevent.AuditDeviceCodeVerificationApproved)
	AuditDeviceCodeVerificationDenied       = AuditEvent(auditevent.AuditDeviceCodeVerificationDenied)
	AuditDeviceCodeUserCodeBruteForce       = AuditEvent(auditevent.AuditDeviceCodeUserCodeBruteForce)
	AuditDeviceCodeTokenIssued              = AuditEvent(auditevent.AuditDeviceCodeTokenIssued)
	AuditDeviceCodeTokenRejected            = AuditEvent(auditevent.AuditDeviceCodeTokenRejected)
	AuditDeviceCodeTokenSlowDown            = AuditEvent(auditevent.AuditDeviceCodeTokenSlowDown)

	// AuditDeviceCodeRevoked fires from the public revoke helper
	// ([github.com/libraz/go-oidc-provider/op/devicecodekit.Revoke]).
	// The helper atomically disables Pending / Approved records and
	// cascade-revokes every configured credential store whose GrantID
	// matches the device_code: JWT access tokens (per-JTI registry or
	// grant tombstone), opaque access tokens, and refresh tokens.
	// Consumed records retain their issuance-history state while the
	// credential cascade runs; repeating the helper retries any partial
	// cascade.
	//
	// Extras carry client_id, reason, previous_status,
	// device_code_hash, and cascade_complete. Substore-specific extras
	// are present when that surface was attempted:
	// revoked_access_tokens, grant_tombstone_written,
	// revoked_opaque_access_tokens, and
	// refresh_token_cascade_complete.
	AuditDeviceCodeRevoked = AuditEvent(auditevent.AuditDeviceCodeRevoked)

	// AuditDeviceCodePollObservationFailed fires when the
	// token-endpoint device_code grant observed a substore fault
	// while persisting the LastPolledAt stamp on a poll. The wire
	// response is unchanged — the poll decision still proceeds,
	// fail-open, because the stamp is best-effort observability
	// rather than a single-use gate — but SOC tooling needs the
	// signal so a transient store outage that quietly defeats the
	// slow_down ladder is visible. Warn-level: a healthy deployment
	// should never emit this event. Mirrors
	// [AuditCIBAPollObservationFailed] for the device-flow surface.
	AuditDeviceCodePollObservationFailed = AuditEvent(auditevent.AuditDeviceCodePollObservationFailed)
)

// CIBA events. Fire from the /bc-authorize endpoint, the embedder's
// authentication-device interaction, and the token-endpoint CIBA grant.
const (
	AuditCIBAAuthorizationIssued          = AuditEvent(auditevent.AuditCIBAAuthorizationIssued)
	AuditCIBAAuthorizationRejected        = AuditEvent(auditevent.AuditCIBAAuthorizationRejected)
	AuditCIBAAuthorizationUnboundRejected = AuditEvent(auditevent.AuditCIBAAuthorizationUnboundRejected)
	AuditCIBAAuthDeviceApproved           = AuditEvent(auditevent.AuditCIBAAuthDeviceApproved)
	AuditCIBAAuthDeviceDenied             = AuditEvent(auditevent.AuditCIBAAuthDeviceDenied)
	AuditCIBAPollAbuseLockout             = AuditEvent(auditevent.AuditCIBAPollAbuseLockout)
	AuditCIBATokenIssued                  = AuditEvent(auditevent.AuditCIBATokenIssued)
	AuditCIBATokenRejected                = AuditEvent(auditevent.AuditCIBATokenRejected)
	AuditCIBATokenSlowDown                = AuditEvent(auditevent.AuditCIBATokenSlowDown)

	// AuditCIBAPollObservationFailed fires when the token-endpoint
	// CIBA grant observed a substore fault while persisting the
	// LastPolledAt stamp on a poll. The wire response is unchanged —
	// the poll decision still proceeds, fail-open, because the
	// stamp is best-effort observability rather than a single-use
	// gate — but SOC tooling needs the signal so a transient store
	// outage that quietly defeats the slow_down ladder is visible.
	// Warn-level: a healthy deployment should never emit this event.
	AuditCIBAPollObservationFailed = AuditEvent(auditevent.AuditCIBAPollObservationFailed)
)

// Custom-grant dispatch events. Requested and Failed describe dispatcher
// outcomes; RefreshDropped records a successful response whose refresh token
// was removed because the client was not registered for that grant.
const (
	AuditCustomGrantRequested      = AuditEvent(auditevent.AuditCustomGrantRequested)
	AuditCustomGrantFailed         = AuditEvent(auditevent.AuditCustomGrantFailed)
	AuditCustomGrantRefreshDropped = AuditEvent(auditevent.AuditCustomGrantRefreshDropped)
)

// Token-exchange events. Fire from the in-tree RFC 8693 handler.
// Every successful exchange emits Requested + Granted; rejections
// emit Requested + one of the failure-class events depending on the
// gate that fired. The internal package cannot import op (one-way
// import graph), so the values are duplicated as raw strings inside
const (
	AuditTokenExchangeRequested             = AuditEvent(auditevent.AuditTokenExchangeRequested)
	AuditTokenExchangeGranted               = AuditEvent(auditevent.AuditTokenExchangeGranted)
	AuditTokenExchangePolicyDenied          = AuditEvent(auditevent.AuditTokenExchangePolicyDenied)
	AuditTokenExchangePolicyError           = AuditEvent(auditevent.AuditTokenExchangePolicyError)
	AuditTokenExchangeScopeInflationBlocked = AuditEvent(auditevent.AuditTokenExchangeScopeInflationBlocked)
	AuditTokenExchangeAudienceBlocked       = AuditEvent(auditevent.AuditTokenExchangeAudienceBlocked)
	AuditTokenExchangeTTLCapped             = AuditEvent(auditevent.AuditTokenExchangeTTLCapped)
	AuditTokenExchangeActChainTooDeep       = AuditEvent(auditevent.AuditTokenExchangeActChainTooDeep)
	AuditTokenExchangeEmptyScopeRejected    = AuditEvent(auditevent.AuditTokenExchangeEmptyScopeRejected)
	AuditTokenExchangeActorEqualsSubject    = AuditEvent(auditevent.AuditTokenExchangeActorEqualsSubject)
	AuditTokenExchangeSubjectTokenExternal  = AuditEvent(auditevent.AuditTokenExchangeSubjectTokenExternal)
	AuditTokenExchangeActorTokenExternal    = AuditEvent(auditevent.AuditTokenExchangeActorTokenExternal)
	AuditTokenExchangeSubjectTokenInvalid   = AuditEvent(auditevent.AuditTokenExchangeSubjectTokenInvalid)
	AuditTokenExchangeRefreshIssued         = AuditEvent(auditevent.AuditTokenExchangeRefreshIssued)
	AuditTokenExchangeSelfExchange          = AuditEvent(auditevent.AuditTokenExchangeSelfExchange)

	// AuditTokenExchangeSubjectTokenRegistryError fires when the in-tree
	// RFC 8693 handler observed a non-NotFound fault from the access-
	// token registry while looking up subject_token (or actor_token).
	// The wire response is unchanged — the request still collapses to
	// invalid_grant per RFC 6749 §5.2 — but SOC tooling needs a separate
	// observation channel so a transient registry outage (DB blip,
	// network partition, secondary failover) is visible as something
	// other than an ordinary revocation. Warn-level: a healthy
	// deployment should never emit this event. Extras carry: reason
	// ("registry_error"), is_subject (true when the failed lookup was
	// for subject_token, false for actor_token).
	AuditTokenExchangeSubjectTokenRegistryError = AuditEvent(auditevent.AuditTokenExchangeSubjectTokenRegistryError)
)

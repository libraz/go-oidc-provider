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
// Stable since v1.0. New events MAY be added in a minor release;
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

// Account-management events.
//
// Reserved vocabulary: the library emits none of the constants in this
// block. Account management — creating and deleting accounts,
// registering a passkey, enabling TOTP, changing a password, linking a
// federated identity — happens on the deployment's own admin surface,
// which the OP does not host. The names are catalogued so that surface
// and the OP's own records land in one vocabulary.
//
// A dashboard MUST NOT read silence here as evidence. No enrolment
// having been recorded means the deployment has not wired its
// account-management plane to this stream, not that no passkey was
// registered.
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

// Login / MFA events. One fires from the authenticator chain each
// time a factor resolves: the login.* pair for the factor that first
// identifies the user, the mfa.* pair for every factor after it. The
// event carries the subject as ActorID on the failure path as well as
// the success path — the [LoginAttemptObserver] feed withholds it
// there so a policy hook cannot be turned into an enumeration oracle,
// but this stream reaches the deployment's own audit sink and nothing
// on the wire, and a failed-login record without the account being
// guessed at answers no question worth asking.
const (
	AuditLoginSuccess = AuditEvent(auditevent.AuditLoginSuccess)
	AuditLoginFailed  = AuditEvent(auditevent.AuditLoginFailed)
	AuditMFASuccess   = AuditEvent(auditevent.AuditMFASuccess)
	AuditMFAFailed    = AuditEvent(auditevent.AuditMFAFailed)

	// Reserved vocabulary: the library never emits AuditMFARequired,
	// AuditStepUpRequired or AuditStepUpSuccess. The OP defines the
	// names so a deployment's audit pipeline can carry them
	// consistently; silence on these three is not evidence that the
	// situation did not arise.
	//
	// Step-up is the embedder's decision. [StepUpChallenge] builds the
	// RFC 9470 WWW-Authenticate value, and the resource server that
	// sends it is the only party that knows which request needed a
	// stronger authentication and whether the one that came back
	// satisfied it; the OP sees an ordinary authorization request.
	//
	// AuditMFARequired has no once-per-attempt point to fire from. The
	// chain does not decide "MFA is now required" separately from
	// prompting for the next factor, and a prompt is re-emitted on
	// every retry of that factor, so emitting here would count a user
	// mistyping one code as several demands for a second factor.
	// [AuditMFASuccess] and [AuditMFAFailed] carry the same
	// information without that ambiguity.
	AuditMFARequired    = AuditEvent(auditevent.AuditMFARequired)
	AuditStepUpRequired = AuditEvent(auditevent.AuditStepUpRequired)
	AuditStepUpSuccess  = AuditEvent(auditevent.AuditStepUpSuccess)

	// AuditLockoutStalled fires when the cross-factor brute-force
	// counter abandoned a failed attempt because its compare-and-swap
	// lost too many times in a row. The attempt was rejected, but it
	// was NOT counted: the subject's failure budget did not advance,
	// so a party that can sustain the contention can keep guessing
	// without ever reaching the lockout threshold. Sustained emissions
	// for one ActorID are the signal that matters — an isolated one is
	// ordinary contention under load.
	AuditLockoutStalled = AuditEvent(auditevent.AuditLockoutStalled)
)

// Consent events. AuditConsentGranted fires when the user approves a
// consent prompt; AuditConsentGrantedFirstParty fires instead when
// first-party auto-consent applies, so a grant recorded without the
// user seeing a screen is distinguishable in the log from one they
// approved.
const (
	AuditConsentGranted           = AuditEvent(auditevent.AuditConsentGranted)
	AuditConsentGrantedFirstParty = AuditEvent(auditevent.AuditConsentGrantedFirstParty)

	// Reserved vocabulary: the library never emits
	// AuditConsentGrantedDelta, AuditConsentSkippedExisting or
	// AuditConsentRevoked. They name real distinctions — a re-prompt
	// forced by a newly requested sensitive scope, a prompt skipped
	// because the stored grant already covered the request, and a
	// consent withdrawal — and a deployment is free to carry them from
	// its own account-management plane, but no code path in the library
	// raises one today. Do not build an alert that assumes their absence
	// means the situation did not occur.
	//
	// A withdrawal driven through the OAuth 2.0 Grant Management
	// endpoint does raise [AuditGrantManagementRevoked], which is the
	// signal to use for the revocation case.
	AuditConsentGrantedDelta    = AuditEvent(auditevent.AuditConsentGrantedDelta)
	AuditConsentSkippedExisting = AuditEvent(auditevent.AuditConsentSkippedExisting)
	AuditConsentRevoked         = AuditEvent(auditevent.AuditConsentRevoked)
)

// Grant-management events. Fire from the OAuth 2.0 Grant Management
// endpoint after a client successfully revokes one of its own grants,
// or when the revoke side effect fails after the request has been
// authenticated. The failure event contains only fixed-stage evidence;
// it never carries a token or storage error body.
const (
	AuditGrantManagementRevoked      = AuditEvent(auditevent.AuditGrantManagementRevoked)
	AuditGrantManagementRevokeFailed = AuditEvent(auditevent.AuditGrantManagementRevokeFailed)
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
// rejection, which is the audit gap these events close.
const (
	AuditCodeIssued                          = AuditEvent(auditevent.AuditCodeIssued)
	AuditCodeConsumed                        = AuditEvent(auditevent.AuditCodeConsumed)
	AuditCodeReplayDetected                  = AuditEvent(auditevent.AuditCodeReplayDetected)
	AuditTokenIssued                         = AuditEvent(auditevent.AuditTokenIssued)
	AuditTokenRefreshed                      = AuditEvent(auditevent.AuditTokenRefreshed)
	AuditTokenRevoked                        = AuditEvent(auditevent.AuditTokenRevoked)
	AuditTokenRevokeFailed                   = AuditEvent(auditevent.AuditTokenRevokeFailed)
	AuditRefreshReplayDetected               = AuditEvent(auditevent.AuditRefreshReplayDetected)
	AuditRefreshChainRevokeFailed            = AuditEvent(auditevent.AuditRefreshChainRevokeFailed)
	AuditRefreshGrantRevokeFailed            = AuditEvent(auditevent.AuditRefreshGrantRevokeFailed)
	AuditRefreshPriorAccessTokenRevokeFailed = AuditEvent(auditevent.AuditRefreshPriorAccessTokenRevokeFailed)
)

// Session / logout events. Fire from the session manager and the
// /end_session handler.
const (
	AuditSessionCreated                 = AuditEvent(auditevent.AuditSessionCreated)
	AuditSessionDestroyed               = AuditEvent(auditevent.AuditSessionDestroyed)
	AuditSessionAlreadyAbsent           = AuditEvent(auditevent.AuditSessionAlreadyAbsent)
	AuditSessionDestroyFailed           = AuditEvent(auditevent.AuditSessionDestroyFailed)
	AuditLogoutTokenRevokeFailed        = AuditEvent(auditevent.AuditLogoutTokenRevokeFailed)
	AuditLogoutBackChannelDelivered     = AuditEvent(auditevent.AuditLogoutBackChannelDelivered)
	AuditLogoutBackChannelFailed        = AuditEvent(auditevent.AuditLogoutBackChannelFailed)
	AuditLogoutBackChannelResolveFailed = AuditEvent(auditevent.AuditLogoutBackChannelResolveFailed)
	AuditLogoutBackChannelOverflow      = AuditEvent(auditevent.AuditLogoutBackChannelOverflow)

	// Reserved vocabulary: the library never emits
	// AuditLogoutRPInitiated. /end_session records what it did to the
	// session — [AuditSessionDestroyed], [AuditSessionAlreadyAbsent] or
	// [AuditSessionDestroyFailed] — rather than the fact that an RP
	// asked; those three are the signals to correlate on.
	AuditLogoutRPInitiated = AuditEvent(auditevent.AuditLogoutRPInitiated)

	// AuditBCLNoSessionsForSubject fires when a logout names a
	// session_id-bearing subject but the
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
	// Reserved vocabulary: the library never emits
	// AuditRateLimitExceeded or AuditRateLimitBypassed. They exist for
	// embedder-emitted events from operator-side rate-limit middleware
	// (reverse proxy, gateway, Go handler chains). The library does
	// NOT implement a generic per-IP / per-endpoint HTTP rate limit —
	// that responsibility lives with
	// the embedder per the project charter. The OP only owns the
	// authentication-flow brute-force gate wired through
	// [WithAuthnLockoutStore] (and the device-code user-code gate
	// surfaced via [AuditDeviceCodeUserCodeBruteForce]); those paths
	// emit their own dedicated events. These two constants exist so
	// audit pipelines can ingest embedder-side throttle decisions
	// under a vocabulary consistent with the rest of the OIDC
	// audit catalog.
	AuditRateLimitExceeded = AuditEvent(auditevent.AuditRateLimitExceeded)
	AuditRateLimitBypassed = AuditEvent(auditevent.AuditRateLimitBypassed)

	// Reserved vocabulary: the library never emits AuditPKCEViolation,
	// AuditRedirectURIMismatch or AuditAlgLegacyUsed. Each names a
	// rejection the OP does perform — a code exchanged with the wrong
	// verifier, a redirect_uri that is not the registered one, a
	// request selecting a legacy algorithm —
	// but the rejection is reported to the client on the wire and is
	// not raised on the audit stream. An absent event here therefore
	// means "not instrumented", not "did not happen"; the request log
	// is where those rejections are currently visible.
	//
	// These three sit in this block because they are unemitted, not
	// because they are the embedder's to raise like the two above.
	// The distinction matters if you are deciding what to alert on.
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

	// AuditDPoPLooseMethodCaseAdmitted fires when the DPoP verifier's
	// loose-method-case bridge admits a proof whose "htm" claim
	// differed from the request method only in ASCII case. The wire
	// response is unchanged — the proof was admitted — but SOC tooling
	// needs the signal so the bridge stays visible while the
	// responsible RP library is fixed.
	//
	// No option on this package enables the bridge, so a [Provider]
	// built through [New] verifies proofs in the RFC 9449 §4.3 strict
	// posture and never emits this event; the Prometheus counter it
	// mirrors onto therefore stays at zero. The constant and its
	// counter are part of the catalog so the emission path is already
	// wired if the opt-in is exposed. Warn-level when it does fire.
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

// Interaction ceremony events. Fire from /interaction/{uid}, where the
// configured [interaction.Driver] owns the rendered surface.
const (
	// AuditInteractionRenderFailed fires when the Driver returns an
	// error from Render without having written anything to the response.
	// The OP answers the request with a server_error page of its own, so
	// the wire response is honest, but only the audit stream carries the
	// cause: the endpoint sees a failed Render and nothing about which
	// template, field or data binding produced it.
	//
	// The event is warn-level and names the prompt type that could not be
	// rendered, which is what makes a broken template attributable. It is
	// a deployment fault rather than an attack signal — a prompt no user
	// can be shown blocks every login that reaches it — so a non-zero
	// rate here warrants a page even though the request count looks
	// normal.
	//
	// A Driver that fails after committing its own status line does not
	// raise this event: the response already belongs to the Driver, and
	// the OP has nothing to add to what it already sent.
	AuditInteractionRenderFailed = AuditEvent(auditevent.AuditInteractionRenderFailed)
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
//
// The verification-ceremony and revocation events are raised by the
// helpers in
// [github.com/libraz/go-oidc-provider/op/devicecodekit], which run in
// the embedder's HTTP layer rather than in a handler the OP mounts.
// They therefore ride the logger set on that package's dependency
// bundle, not the one given to [WithAuditLogger]; a deployment that
// wants them in its audit stream points both at the same sink.
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
//
// AuditCIBAAuthDeviceApproved and AuditCIBAAuthDeviceDenied are the
// exception: the OP never emits them. The approval and denial
// transitions are made by the embedder calling
// store.CIBARequestStore.Approve / Deny directly, and no library code
// path sits between that call and the store, so there is nowhere for
// the OP to observe the decision. The names are reserved so a
// deployment raising them from its own authentication device lands in
// the same vocabulary as the events the OP does raise for the request.
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
// was withheld by one of the issuance gates documented on
// [CustomGrantResponse.IssueRefreshToken]. The event's extras name the gate
// that fired under the "reason" key.
const (
	AuditCustomGrantRequested      = AuditEvent(auditevent.AuditCustomGrantRequested)
	AuditCustomGrantFailed         = AuditEvent(auditevent.AuditCustomGrantFailed)
	AuditCustomGrantRefreshDropped = AuditEvent(auditevent.AuditCustomGrantRefreshDropped)
)

// Token-exchange events. Fire from the in-tree RFC 8693 handler.
// Every successful exchange emits Requested + Granted; rejections
// emit Requested + one of the failure-class events depending on the
// gate that fired.
//
// The handler cannot import op — the import graph runs one way — so it
// names its own constants. Those constants are not a second copy of
// these: both sides resolve the same internal/auditevent registry, so
// an event renamed there moves the public constant and the handler's
// together.
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

// Provider lifecycle events.
const (
	// AuditStartupProfile fires once from [New], after validation
	// succeeds and before the [Provider] is returned. It records the
	// security posture the deployment declared and what that
	// declaration resolved to, so an operator can answer "which
	// profile is this OP running" from the audit stream and every
	// later per-request record has a configuration to be read
	// against.
	//
	// Extras carry the declared axes — profiles, features, grants
	// (each a sorted string slice of the canonical identifiers) —
	// followed by the resolved policy: pkce_required, par_required,
	// state_or_nonce_required, nonce_required, sender_constrained
	// ("dpop", "mtls", "dpop+mtls", or "" when bearer tokens are
	// permitted), client_auth_methods (the set the runtime actually
	// enforces, which may be narrower than the profile permits; empty
	// means no profile narrowed it), access_token_ttl_seconds,
	// access_token_format, refresh_token_ttl_seconds,
	// refresh_grace_period_seconds, dpop_nonce_required,
	// signed_request_object_required, signed_backchannel_request_required,
	// jarm_required, signed_introspection_required.
	//
	// The event rides the audit emitter rather than the operational
	// logger: the two are structurally separate so audit records
	// never leak into the operational stream, and this record is the
	// anchor of the audit stream. A Provider built with neither
	// [WithAuditLogger] nor [WithLogger] emits nothing.
	AuditStartupProfile = AuditEvent(auditevent.AuditStartupProfile)
)

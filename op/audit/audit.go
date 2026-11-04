// Package audit is the closed catalogue of audit event names the OP emits
// through the logger given to op.WithAuditLogger (or op.WithLogger), and the
// catalogue rows that map each event onto its Prometheus counter.
//
// Stable since v1.5.
package audit

import "github.com/libraz/go-oidc-provider/internal/auditevent"

// Event identifies a structured audit event the OP emits. The
// constants below are the closed catalogue handler code selects from;
// new event names are added here once the handler that emits them
// lands.
//
// The naming convention is "<area>.<verb>" (or
// "<area>.<verb>.<qualifier>") so dashboards can pre-aggregate by
// area without parsing a free-form message.
//
// When op.WithPrometheus is configured, a curated subset of these
// events is mirrored onto Prometheus counters by the package-internal
// metrics bridge — a single emission updates both the slog audit
// stream and the matching counter.
//
// Stable since v1.5. New events MAY be added in a minor release;
// existing event names are part of the API surface and only renamed
// in a major release with a deprecation notice.
type Event string

// EventDefinition describes one row in the OP's closed audit-event
// catalog. MetricName is empty for audit-only events. MetricLabel is the
// bounded label value used by category or fixed-kind counters; it is empty for
// scalar counters and counters whose labels come from structured event fields.
type EventDefinition struct {
	Event       Event
	MetricName  string
	MetricLabel string
}

// Catalog returns a copy of the complete audit-event catalog. The
// same internal registry drives the Prometheus bridge, so event discovery and
// metric routing cannot drift.
func Catalog() []EventDefinition {
	internalCatalog := auditevent.Catalog()
	out := make([]EventDefinition, 0, len(internalCatalog))
	for _, definition := range internalCatalog {
		out = append(out, EventDefinition{
			Event:       Event(definition.Name),
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
	AccountCreated             = Event(auditevent.AuditAccountCreated)
	AccountDeleted             = Event(auditevent.AuditAccountDeleted)
	AccountEmailAdded          = Event(auditevent.AuditAccountEmailAdded)
	AccountEmailVerified       = Event(auditevent.AuditAccountEmailVerified)
	AccountEmailRemoved        = Event(auditevent.AuditAccountEmailRemoved)
	AccountEmailSetPrimary     = Event(auditevent.AuditAccountEmailSetPrimary)
	AccountPasskeyRegistered   = Event(auditevent.AuditAccountPasskeyRegistered)
	AccountPasskeyRemoved      = Event(auditevent.AuditAccountPasskeyRemoved)
	AccountTOTPEnabled         = Event(auditevent.AuditAccountTOTPEnabled)
	AccountTOTPDisabled        = Event(auditevent.AuditAccountTOTPDisabled)
	AccountPasswordChanged     = Event(auditevent.AuditAccountPasswordChanged)
	AccountRecoveryRegenerated = Event(auditevent.AuditAccountRecoveryRegenerated)
	RecoverySupportEscalation  = Event(auditevent.AuditRecoverySupportEscalation)
	AccountFederationLinked    = Event(auditevent.AuditAccountFederationLinked)
	AccountFederationUnlinked  = Event(auditevent.AuditAccountFederationUnlinked)
)

// Login / MFA events. One fires from the authenticator chain each
// time a factor resolves: the login.* pair for the factor that first
// identifies the user, the mfa.* pair for every factor after it. The
// event carries the subject as ActorID on the failure path as well as
// the success path — the op.LoginAttemptObserver feed withholds it
// there so a policy hook cannot be turned into an enumeration oracle,
// but this stream reaches the deployment's own audit sink and nothing
// on the wire, and a failed-login record without the account being
// guessed at answers no question worth asking.
const (
	LoginSuccess = Event(auditevent.AuditLoginSuccess)
	LoginFailed  = Event(auditevent.AuditLoginFailed)
	MFASuccess   = Event(auditevent.AuditMFASuccess)
	MFAFailed    = Event(auditevent.AuditMFAFailed)

	// Reserved vocabulary: the library never emits MFARequired,
	// StepUpRequired or StepUpSuccess. The OP defines the
	// names so a deployment's audit pipeline can carry them
	// consistently; silence on these three is not evidence that the
	// situation did not arise.
	//
	// Step-up is the embedder's decision. op.StepUpChallenge builds the
	// RFC 9470 WWW-Authenticate value, and the resource server that
	// sends it is the only party that knows which request needed a
	// stronger authentication and whether the one that came back
	// satisfied it; the OP sees an ordinary authorization request.
	//
	// MFARequired has no once-per-attempt point to fire from. The
	// chain does not decide "MFA is now required" separately from
	// prompting for the next factor, and a prompt is re-emitted on
	// every retry of that factor, so emitting here would count a user
	// mistyping one code as several demands for a second factor.
	// [MFASuccess] and [MFAFailed] carry the same
	// information without that ambiguity.
	MFARequired    = Event(auditevent.AuditMFARequired)
	StepUpRequired = Event(auditevent.AuditStepUpRequired)
	StepUpSuccess  = Event(auditevent.AuditStepUpSuccess)

	// LockoutStalled fires when the cross-factor brute-force
	// counter abandoned a failed attempt because its compare-and-swap
	// lost too many times in a row. The attempt was rejected, but it
	// was NOT counted: the subject's failure budget did not advance,
	// so a party that can sustain the contention can keep guessing
	// without ever reaching the lockout threshold. Sustained emissions
	// for one ActorID are the signal that matters — an isolated one is
	// ordinary contention under load.
	LockoutStalled = Event(auditevent.AuditLockoutStalled)

	// LockoutEngaged fires once when a failed attempt newly
	// engages the cross-factor brute-force lock: the subject was not
	// locked before the attempt and is locked after it. Attempts made
	// while the lock is already running do not repeat it. ActorID is
	// the subject. It is the operator's signal for "this user cannot
	// log in": the wire response for a locked password attempt stays
	// identical to a wrong password so it cannot enumerate accounts.
	//
	// Stable since v1.5.
	LockoutEngaged = Event(auditevent.AuditLockoutEngaged)

	// StepBeginFailed fires once when a LoginFlow step could not
	// begin, so a factor that refuses before prompting leaves a record.
	// Extras carry "step_kind" and "reason", one of "not_enrolled",
	// "aborted", "locked", "not_enrolled_skipped" (a one-of step passed
	// over because the subject has none of its factors) and "error".
	// ActorID is the subject when one is bound. A request the client
	// cancelled is not recorded.
	//
	// Stable since v1.5.
	StepBeginFailed = Event(auditevent.AuditLoginStepBeginFailed)
)

// Consent events. ConsentGranted fires when the user approves a
// consent prompt; ConsentGrantedFirstParty fires instead when
// first-party auto-consent applies, so a grant recorded without the
// user seeing a screen is distinguishable in the log from one they
// approved.
const (
	ConsentGranted           = Event(auditevent.AuditConsentGranted)
	ConsentGrantedFirstParty = Event(auditevent.AuditConsentGrantedFirstParty)

	// Reserved vocabulary: the library never emits
	// ConsentGrantedDelta, ConsentSkippedExisting or
	// ConsentRevoked. They name real distinctions — a re-prompt
	// forced by a newly requested sensitive scope, a prompt skipped
	// because the stored grant already covered the request, and a
	// consent withdrawal — and a deployment is free to carry them from
	// its own account-management plane, but no code path in the library
	// raises one today. Do not build an alert that assumes their absence
	// means the situation did not occur.
	//
	// A withdrawal driven through the OAuth 2.0 Grant Management
	// endpoint does raise [GrantManagementRevoked], which is the
	// signal to use for the revocation case.
	ConsentGrantedDelta    = Event(auditevent.AuditConsentGrantedDelta)
	ConsentSkippedExisting = Event(auditevent.AuditConsentSkippedExisting)
	ConsentRevoked         = Event(auditevent.AuditConsentRevoked)
)

// Grant-management events. Fire from the OAuth 2.0 Grant Management
// endpoint after a client successfully revokes one of its own grants,
// or when the revoke side effect fails after the request has been
// authenticated. The failure event contains only fixed-stage evidence;
// it never carries a token or storage error body.
const (
	GrantManagementRevoked      = Event(auditevent.AuditGrantManagementRevoked)
	GrantManagementRevokeFailed = Event(auditevent.AuditGrantManagementRevokeFailed)
)

// Code / token events. Fire from the authorize-code issuance path
// and the token / revoke endpoints. TokenRevokeFailed is the
// /revoke companion to TokenRevoked: the wire response stays
// HTTP 200 per RFC 7009 §2.2, but a non-NotFound storage fault
// raises this event so SOC tooling can detect the silent-failure
// class (GHSA-7mqr-2v3q-v2wm).
//
// RefreshChainRevokeFailed and RefreshGrantRevokeFailed fire
// when a refresh-token replay detection successfully observes the
// replay (the wire response is invalid_grant) but the cascade side-
// effects encounter a transport fault. The events are warn-level and
// surface so SOC tooling can distinguish "chain successfully revoked"
// from "chain revoke silently failed" — the latter leaves the
// rotation chain intact even though the wire response indicated
// rejection, which is the audit gap these events close.
const (
	CodeIssued                          = Event(auditevent.AuditCodeIssued)
	CodeConsumed                        = Event(auditevent.AuditCodeConsumed)
	CodeReplayDetected                  = Event(auditevent.AuditCodeReplayDetected)
	TokenIssued                         = Event(auditevent.AuditTokenIssued)
	TokenRefreshed                      = Event(auditevent.AuditTokenRefreshed)
	TokenRevoked                        = Event(auditevent.AuditTokenRevoked)
	TokenRevokeFailed                   = Event(auditevent.AuditTokenRevokeFailed)
	RefreshReplayDetected               = Event(auditevent.AuditRefreshReplayDetected)
	RefreshChainRevokeFailed            = Event(auditevent.AuditRefreshChainRevokeFailed)
	RefreshGrantRevokeFailed            = Event(auditevent.AuditRefreshGrantRevokeFailed)
	RefreshPriorAccessTokenRevokeFailed = Event(auditevent.AuditRefreshPriorAccessTokenRevokeFailed)
)

// Session / logout events. Fire from the session manager and the
// /end_session handler.
const (
	SessionCreated                 = Event(auditevent.AuditSessionCreated)
	SessionDestroyed               = Event(auditevent.AuditSessionDestroyed)
	SessionAlreadyAbsent           = Event(auditevent.AuditSessionAlreadyAbsent)
	SessionDestroyFailed           = Event(auditevent.AuditSessionDestroyFailed)
	LogoutTokenRevokeFailed        = Event(auditevent.AuditLogoutTokenRevokeFailed)
	LogoutBackChannelDelivered     = Event(auditevent.AuditLogoutBackChannelDelivered)
	LogoutBackChannelFailed        = Event(auditevent.AuditLogoutBackChannelFailed)
	LogoutBackChannelResolveFailed = Event(auditevent.AuditLogoutBackChannelResolveFailed)
	LogoutBackChannelOverflow      = Event(auditevent.AuditLogoutBackChannelOverflow)
	LogoutClientLookupFailed       = Event(auditevent.AuditLogoutClientLookupFailed)

	// Reserved vocabulary: the library never emits
	// LogoutRPInitiated. /end_session records what it did to the
	// session — [SessionDestroyed], [SessionAlreadyAbsent] or
	// [SessionDestroyFailed] — rather than the fact that an RP
	// asked; those three are the signals to correlate on.
	LogoutRPInitiated = Event(auditevent.AuditLogoutRPInitiated)

	// BCLNoSessionsForSubject fires when a logout names a
	// session_id-bearing subject but the
	// back-channel coordinator finds zero RPs to notify. Under a
	// volatile SessionStore (Redis without persistence, Memcached,
	// or any in-memory tier under maxmemory eviction) this is the
	// signal that a session was evicted between establishment and
	// logout, narrowing OIDC Back-Channel Logout 1.0 §2.7's
	// best-effort delivery floor to zero. INFO-level: under volatile
	// placement the gap is expected; SOC tooling alerts on elevated
	// rates rather than per-event.
	BCLNoSessionsForSubject = Event(auditevent.AuditBCLNoSessionsForSubject)
)

// Defensive events. Fire from request-validation paths that detect
// abuse signals or operator-visible policy hits.
const (
	// Reserved vocabulary: the library never emits
	// RateLimitExceeded or RateLimitBypassed. They exist for
	// embedder-emitted events from operator-side rate-limit middleware
	// (reverse proxy, gateway, Go handler chains). The library does
	// NOT implement a generic per-IP / per-endpoint HTTP rate limit —
	// that responsibility lives with
	// the embedder per the project charter. The OP only owns the
	// authentication-flow brute-force gate wired through
	// op.WithAuthnLockoutStore, whose counted guesses — the one that
	// engages the lock included — are reported under the login.* /
	// mfa.* failure events, and the device-code user-code gate, which
	// emits [DeviceCodeUserCodeBruteForce]. These two constants exist so
	// audit pipelines can ingest embedder-side throttle decisions
	// under a vocabulary consistent with the rest of the OIDC
	// audit catalog.
	RateLimitExceeded = Event(auditevent.AuditRateLimitExceeded)
	RateLimitBypassed = Event(auditevent.AuditRateLimitBypassed)

	// PKCEViolation fires at the token endpoint when a code_verifier
	// fails: Extras carry endpoint "token" and reason "verifier_mismatch",
	// "verifier_format" or "challenge_method_unsupported", never the
	// verifier itself.
	PKCEViolation = Event(auditevent.AuditPKCEViolation)

	// RedirectURIMismatch fires when /authorize receives a
	// redirect_uri the client never registered, and when the token
	// endpoint receives one that differs from the authorization request.
	// Extras carry endpoint ("authorize" or "token") and the presented
	// redirect_uri. The wire answer stays generic at the token endpoint,
	// so this event is where the cause is visible.
	RedirectURIMismatch = Event(auditevent.AuditRedirectURIMismatch)

	// Reserved vocabulary: the library never emits AlgLegacyUsed. A
	// request selecting a legacy algorithm is rejected on the wire and not
	// raised on the audit stream, so an absent event means "not
	// instrumented", not "did not happen".
	AlgLegacyUsed = Event(auditevent.AuditAlgLegacyUsed)

	// CORSPreflightAllowed fires every time the strict CORS layer
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
	CORSPreflightAllowed = Event(auditevent.AuditCORSPreflightAllowed)

	// DPoPLooseMethodCaseAdmitted fires when the DPoP verifier's
	// loose-method-case bridge admits a proof whose "htm" claim
	// differed from the request method only in ASCII case. The wire
	// response is unchanged — the proof was admitted — but SOC tooling
	// needs the signal so the bridge stays visible while the
	// responsible RP library is fixed.
	//
	// No option on this package enables the bridge, so a op.Provider
	// built through op.New verifies proofs in the RFC 9449 §4.3 strict
	// posture and never emits this event; the Prometheus counter it
	// mirrors onto therefore stays at zero. The constant and its
	// counter are part of the catalog so the emission path is already
	// wired if the opt-in is exposed. Warn-level when it does fire.
	DPoPLooseMethodCaseAdmitted = Event(auditevent.AuditDPoPLooseMethodCaseAdmitted)

	// KeyRetiredKidPresented fires when a JWS / JWE presented
	// for verification carries a "kid" header that matches an entry
	// in the OP signing keyset whose op.SigningKey.NotAfter retirement
	// deadline has elapsed. The wire response is the existing
	// signature-invalid taxonomy — the verifier treats the kid as if
	// it were unknown — but SOC tooling needs the signal because a
	// retired kid surfacing at verification time is the canonical
	// "rotation-after-leak token forge" attempt: an attacker who
	// captured the old private key before the rotation tries to ride
	// past the JWKS grace window by minting a fresh JWS that names
	// the retiring kid. The event is warn-level and carries the
	// rejected kid in the record's extras so dashboards can correlate
	// against the rotation timeline without parsing the slog message.
	KeyRetiredKidPresented = Event(auditevent.AuditKeyRetiredKidPresented)
)

// Interaction ceremony events. Fire from /interaction/{uid}, where the
// configured [interaction.Driver] owns the rendered surface.
const (
	// InteractionRenderFailed fires when the Driver returns an
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
	InteractionRenderFailed = Event(auditevent.AuditInteractionRenderFailed)
)

// Introspection events. Fire from the /introspect endpoint. Only the
// pre-authentication failure is surfaced today: a client that presents
// invalid credentials at /introspect MUST be visible to SOC tooling so
// the embedder can spot probing for a known client_id even though RFC
// 7662 §2.3 mandates the wire response stays at the generic
// "invalid_client" code.
const (
	IntrospectionError = Event(auditevent.AuditIntrospectionError)
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
	ClientAuthnFailure = Event(auditevent.AuditClientAuthnFailure)

	// ClientAuthnPreviousSecret fires when a client authenticates
	// with client_secret_basic or client_secret_post using its previous
	// secret inside the rotation window. ClientID is the client and
	// Extras["method"] the method used; the secret is never attached.
	// Operators use it to find clients that still have to switch before
	// the window closes.
	//
	// Stable since v1.5.
	ClientAuthnPreviousSecret = Event(auditevent.AuditClientAuthnPreviousSecret)
)

// Dynamic Client Registration events. Fire from /register and
// /register/{client_id}.
const (
	DCRIATConsumed           = Event(auditevent.AuditDCRIATConsumed)
	DCRIATExpired            = Event(auditevent.AuditDCRIATExpired)
	DCRIATInvalid            = Event(auditevent.AuditDCRIATInvalid)
	DCROpenRegistrationUsed  = Event(auditevent.AuditDCROpenRegistrationUsed)
	DCRClientRegistered      = Event(auditevent.AuditDCRClientRegistered)
	DCRClientMetadataRead    = Event(auditevent.AuditDCRClientMetadataRead)
	DCRClientMetadataUpdated = Event(auditevent.AuditDCRClientMetadataUpdated)
	DCRClientDeleted         = Event(auditevent.AuditDCRClientDeleted)
	DCRRATInvalid            = Event(auditevent.AuditDCRRATInvalid)
	DCRMetadataValidation    = Event(auditevent.AuditDCRMetadataValidation)

	// Cascade failures are operational signals emitted after a client record
	// has been deleted but one credential substore could not revoke its rows.
	DCRCascadeRefreshRevokeFailed           = Event(auditevent.AuditDCRCascadeRefreshRevokeFailed)
	DCRCascadeGrantRevokeFailed             = Event(auditevent.AuditDCRCascadeGrantRevokeFailed)
	DCRCascadeAccessTokenRevokeFailed       = Event(auditevent.AuditDCRCascadeAccessTokenRevokeFailed)
	DCRCascadeOpaqueAccessTokenRevokeFailed = Event(auditevent.AuditDCRCascadeOpaqueAccessTokenRevokeFailed)
)

// Device-flow events. Fire from the /device_authorization endpoint,
// the verification ceremony, and the token-endpoint device_code grant.
//
// The verification-ceremony and revocation events are raised by the
// helpers in
// [github.com/libraz/go-oidc-provider/op/devicecodekit], which run in
// the embedder's HTTP layer rather than in a handler the OP mounts.
// They therefore ride the logger set on that package's dependency
// bundle, not the one given to op.WithAuditLogger; a deployment that
// wants them in its audit stream points both at the same sink.
const (
	DeviceAuthorizationIssued          = Event(auditevent.AuditDeviceAuthorizationIssued)
	DeviceAuthorizationRejected        = Event(auditevent.AuditDeviceAuthorizationRejected)
	DeviceAuthorizationUnboundRejected = Event(auditevent.AuditDeviceAuthorizationUnboundRejected)
	DeviceCodeVerificationApproved     = Event(auditevent.AuditDeviceCodeVerificationApproved)
	DeviceCodeVerificationDenied       = Event(auditevent.AuditDeviceCodeVerificationDenied)
	DeviceCodeUserCodeBruteForce       = Event(auditevent.AuditDeviceCodeUserCodeBruteForce)
	DeviceCodeTokenIssued              = Event(auditevent.AuditDeviceCodeTokenIssued)
	DeviceCodeTokenRejected            = Event(auditevent.AuditDeviceCodeTokenRejected)
	DeviceCodeTokenSlowDown            = Event(auditevent.AuditDeviceCodeTokenSlowDown)

	// DeviceCodeRevoked fires from the public revoke helper
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
	DeviceCodeRevoked = Event(auditevent.AuditDeviceCodeRevoked)

	// DeviceCodePollObservationFailed fires when the
	// token-endpoint device_code grant observed a substore fault
	// while persisting the LastPolledAt stamp on a poll. The wire
	// response is unchanged — the poll decision still proceeds,
	// fail-open, because the stamp is best-effort observability
	// rather than a single-use gate — but SOC tooling needs the
	// signal so a transient store outage that quietly defeats the
	// slow_down ladder is visible. Warn-level: a healthy deployment
	// should never emit this event. Mirrors
	// [CIBAPollObservationFailed] for the device-flow surface.
	DeviceCodePollObservationFailed = Event(auditevent.AuditDeviceCodePollObservationFailed)
)

// CIBA events. Fire from the /bc-authorize endpoint, the embedder's
// authentication-device interaction, and the token-endpoint CIBA grant.
const (
	CIBAAuthorizationIssued          = Event(auditevent.AuditCIBAAuthorizationIssued)
	CIBAAuthorizationRejected        = Event(auditevent.AuditCIBAAuthorizationRejected)
	CIBAAuthorizationUnboundRejected = Event(auditevent.AuditCIBAAuthorizationUnboundRejected)

	// Reserved vocabulary: the library never emits
	// CIBAAuthDeviceApproved or CIBAAuthDeviceDenied. The
	// approval and denial transitions are made by the embedder calling
	// store.CIBARequestStore.Approve / Deny directly, and no library code
	// path sits between that call and the store, so there is nowhere for
	// the OP to observe the decision. The names are reserved so a
	// deployment raising them from its own authentication device lands in
	// the same vocabulary as the events the OP does raise for the request.
	CIBAAuthDeviceApproved = Event(auditevent.AuditCIBAAuthDeviceApproved)
	CIBAAuthDeviceDenied   = Event(auditevent.AuditCIBAAuthDeviceDenied)

	// Token-endpoint CIBA grant outcomes.
	CIBAPollAbuseLockout = Event(auditevent.AuditCIBAPollAbuseLockout)
	CIBATokenIssued      = Event(auditevent.AuditCIBATokenIssued)
	CIBATokenRejected    = Event(auditevent.AuditCIBATokenRejected)
	CIBATokenSlowDown    = Event(auditevent.AuditCIBATokenSlowDown)

	// CIBAPollObservationFailed fires when the token-endpoint
	// CIBA grant observed a substore fault while persisting the
	// LastPolledAt stamp on a poll. The wire response is unchanged —
	// the poll decision still proceeds, fail-open, because the
	// stamp is best-effort observability rather than a single-use
	// gate — but SOC tooling needs the signal so a transient store
	// outage that quietly defeats the slow_down ladder is visible.
	// Warn-level: a healthy deployment should never emit this event.
	CIBAPollObservationFailed = Event(auditevent.AuditCIBAPollObservationFailed)
)

// Custom-grant dispatch events. Requested and Failed describe dispatcher
// outcomes; RefreshDropped records a successful response whose refresh token
// was withheld by one of the issuance gates documented on
// op.CustomGrantResponse.IssueRefreshToken. The event's extras name the gate
// that fired under the "reason" key.
const (
	CustomGrantRequested      = Event(auditevent.AuditCustomGrantRequested)
	CustomGrantFailed         = Event(auditevent.AuditCustomGrantFailed)
	CustomGrantRefreshDropped = Event(auditevent.AuditCustomGrantRefreshDropped)
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
	TokenExchangeRequested             = Event(auditevent.AuditTokenExchangeRequested)
	TokenExchangeGranted               = Event(auditevent.AuditTokenExchangeGranted)
	TokenExchangePolicyDenied          = Event(auditevent.AuditTokenExchangePolicyDenied)
	TokenExchangePolicyError           = Event(auditevent.AuditTokenExchangePolicyError)
	TokenExchangeScopeInflationBlocked = Event(auditevent.AuditTokenExchangeScopeInflationBlocked)
	TokenExchangeAudienceBlocked       = Event(auditevent.AuditTokenExchangeAudienceBlocked)
	TokenExchangeTTLCapped             = Event(auditevent.AuditTokenExchangeTTLCapped)
	TokenExchangeActChainTooDeep       = Event(auditevent.AuditTokenExchangeActChainTooDeep)
	TokenExchangeEmptyScopeRejected    = Event(auditevent.AuditTokenExchangeEmptyScopeRejected)
	TokenExchangeActorEqualsSubject    = Event(auditevent.AuditTokenExchangeActorEqualsSubject)
	TokenExchangeSubjectTokenExternal  = Event(auditevent.AuditTokenExchangeSubjectTokenExternal)
	TokenExchangeActorTokenExternal    = Event(auditevent.AuditTokenExchangeActorTokenExternal)
	TokenExchangeSubjectTokenInvalid   = Event(auditevent.AuditTokenExchangeSubjectTokenInvalid)
	TokenExchangeRefreshIssued         = Event(auditevent.AuditTokenExchangeRefreshIssued)
	TokenExchangeSelfExchange          = Event(auditevent.AuditTokenExchangeSelfExchange)

	// TokenExchangeSubjectTokenRegistryError fires when the in-tree
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
	TokenExchangeSubjectTokenRegistryError = Event(auditevent.AuditTokenExchangeSubjectTokenRegistryError)

	// TokenExchangeIDJAGIssued fires when the token-exchange handler
	// issues an Identity Assertion JWT Authorization Grant under
	// op.WithIDJAGIssuance.
	//
	// Experimental: tracks an IETF draft, so the event MAY change in a
	// minor release on a wire-incompatible draft bump.
	TokenExchangeIDJAGIssued = Event(auditevent.AuditTokenExchangeIDJAGIssued)
)

// JWT bearer grant events. Fire from the token endpoint's RFC 7523
// grant enabled by op.WithJWTBearerGrant.
const (
	// JWTBearerGranted fires when an assertion is redeemed for an
	// access token.
	//
	// Stable since v1.5.
	JWTBearerGranted = Event(auditevent.AuditJWTBearerGranted)

	// JWTBearerRejected fires when an assertion is refused.
	// Extras["reason"] names the verification stage that failed (parse,
	// issuer, typ, signature, claims, idjag, replay), so an operator can
	// tell a misconfigured issuer from a replayed assertion.
	//
	// Stable since v1.5.
	JWTBearerRejected = Event(auditevent.AuditJWTBearerRejected)
)

// Client ID Metadata Document events. Fire when the OP resolves a
// URL-form client_id through op.WithClientIDMetadataDocuments.
const (
	// CIMDFetched fires when a client ID metadata document is
	// fetched and validated.
	//
	// Experimental: tracks an IETF draft, so the event MAY change in a
	// minor release on a wire-incompatible draft bump.
	CIMDFetched = Event(auditevent.AuditCIMDFetched)

	// CIMDFetchFailed fires when the fetch or validation of a
	// client ID metadata document fails. Extras["reason"] is one of
	// status, network, too_large, content_type, json, validation; for
	// validation, Extras["error_code"] carries the validation error code.
	//
	// Experimental: tracks an IETF draft, so the event MAY change in a
	// minor release on a wire-incompatible draft bump.
	CIMDFetchFailed = Event(auditevent.AuditCIMDFetchFailed)

	// CIMDClientDenied fires when op.ClientIDMetadataDocuments.Allow
	// refuses a client_id URL.
	//
	// Experimental: tracks an IETF draft, so the event MAY change in a
	// minor release on a wire-incompatible draft bump.
	CIMDClientDenied = Event(auditevent.AuditCIMDClientDenied)
)

// Shared Signals Framework transmitter events. Fire when the OP runs as
// an SSF 1.0 transmitter under op.WithSharedSignals. None of them updates
// a metric.
const (
	// SSFStreamCreated fires when a receiver creates its stream.
	//
	// Stable since v1.5.
	SSFStreamCreated = Event(auditevent.AuditSSFStreamCreated)

	// SSFStreamUpdated fires when a receiver updates, replaces or
	// changes the status of its stream.
	//
	// Stable since v1.5.
	SSFStreamUpdated = Event(auditevent.AuditSSFStreamUpdated)

	// SSFStreamDeleted fires when a receiver deletes its stream,
	// dropping every event still queued for it.
	//
	// Stable since v1.5.
	SSFStreamDeleted = Event(auditevent.AuditSSFStreamDeleted)

	// SSFSETEnqueued fires when a Security Event Token is queued
	// for a stream.
	//
	// Stable since v1.5.
	SSFSETEnqueued = Event(auditevent.AuditSSFSETEnqueued)

	// SSFEnqueueFailed fires when a security event could not be
	// queued for its receivers. The operation that raised the event is
	// not failed. Extras["reason"] names the cause; fanout_capacity
	// means the subject had more receivers than one fan-out reads.
	//
	// Stable since v1.5.
	SSFEnqueueFailed = Event(auditevent.AuditSSFEnqueueFailed)

	// SSFPushDelivered fires when a receiver accepts a pushed SET
	// with 202.
	//
	// Stable since v1.5.
	SSFPushDelivered = Event(auditevent.AuditSSFPushDelivered)

	// SSFPushRejected fires when a receiver answers a pushed SET
	// with 400. The SET is dropped without a retry.
	//
	// Stable since v1.5.
	SSFPushRejected = Event(auditevent.AuditSSFPushRejected)

	// SSFPushRetried fires when a push does not end in 202 or 400 (any
	// other status, or a transport failure) and the SET is rescheduled.
	//
	// Stable since v1.5.
	SSFPushRetried = Event(auditevent.AuditSSFPushRetried)

	// SSFPushAbandoned fires when a SET is dropped after its last
	// retry, when its stream's authorization header can no longer be
	// unsealed (Extras["reason"] = "seal"), or when its claims cannot be
	// signed (Extras["reason"] = "claims").
	//
	// Stable since v1.5.
	SSFPushAbandoned = Event(auditevent.AuditSSFPushAbandoned)

	// SSFPollSETError fires when a polling receiver reports a SET
	// it could not process (RFC 8936 setErrs). The SET is dropped.
	//
	// Stable since v1.5.
	SSFPollSETError = Event(auditevent.AuditSSFPollSETError)
)

// Provider lifecycle events.
const (
	// StartupProfile fires once from op.New, after validation
	// succeeds and before the op.Provider is returned. It records the
	// security posture the deployment declared and what that
	// declaration resolved to, so an operator can answer "which
	// profile is this OP running" from the audit stream and every
	// later per-request record has a configuration to be read
	// against.
	//
	// Extras carry the declared axes — profiles (in declaration order),
	// features and grants (in resolved order, including the flags a
	// profile auto-enabled and the default grant set), each a string
	// slice of the canonical identifiers — followed by the resolved
	// policy: pkce_required, par_required,
	// state_or_nonce_required, nonce_required, sender_constrained
	// ("dpop", "mtls", "dpop+mtls", or "" when bearer tokens are
	// permitted), client_auth_methods (the set the runtime actually
	// enforces, which may be narrower than the profile permits; empty
	// means no profile narrowed it), access_token_ttl_seconds,
	// access_token_format, refresh_token_ttl_seconds,
	// refresh_grace_period_seconds, refresh_rotation (false when the
	// profile keeps one refresh token for its lifetime instead of
	// rotating it on every use), dpop_nonce_required,
	// signed_request_object_required, signed_backchannel_request_required,
	// jarm_required, signed_introspection_required,
	// insecure_backchannel_logout_for_dev,
	// insecure_shared_signals_push_for_dev.
	//
	// The event rides the audit emitter rather than the operational
	// logger: the two are structurally separate so audit records
	// never leak into the operational stream, and this record is the
	// anchor of the audit stream. A Provider built with neither
	// op.WithAuditLogger nor op.WithLogger emits nothing.
	StartupProfile = Event(auditevent.AuditStartupProfile)
)

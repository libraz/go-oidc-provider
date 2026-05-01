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
const (
	AuditCodeIssued            = AuditEvent("code.issued")
	AuditCodeConsumed          = AuditEvent("code.consumed")
	AuditCodeReplayDetected    = AuditEvent("code.replay_detected")
	AuditTokenIssued           = AuditEvent("token.issued")
	AuditTokenRefreshed        = AuditEvent("token.refreshed")
	AuditTokenRevoked          = AuditEvent("token.revoked")
	AuditTokenRevokeFailed     = AuditEvent("token.revoke_failed")
	AuditRefreshReplayDetected = AuditEvent("refresh.replay_detected")
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

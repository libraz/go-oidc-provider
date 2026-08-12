// Package auditevent owns the closed audit-event vocabulary and its
// Prometheus projection. It sits below both op and internal/metrics so the
// public catalog and the metrics bridge cannot maintain competing lists.
package auditevent

// Name is a stable audit-event wire name.
type Name string

// Metric identifies the Prometheus collector an event updates.
type Metric uint8

// Metric projections. MetricNone marks audit-only events.
const (
	MetricNone Metric = iota
	MetricTokenIssued
	MetricTokensRefreshed
	MetricLoginAttempts
	MetricRefreshReplay
	MetricCodeReplay
	MetricClientAuthnFailures
	MetricDCR
	MetricDeviceAuthorization
	MetricDeviceCode
	MetricCIBA
	MetricTokenExchange
	MetricCustomGrant
	MetricBackChannelLogout
	MetricLogoutFailures
	MetricIntrospectionErrors
	MetricTokenRevokeFailures
	MetricDPoPLooseMethodCase
	MetricKeyRetiredKidPresented
)

// Definition is one row in the closed event catalog. Label is the bounded
// label value for category and fixed-kind counters. It is empty for scalar
// counters and counters whose labels are derived from typed Event fields.
type Definition struct {
	Name   Name
	Metric Metric
	Label  string
}

// Audit event names. Public op constants alias these values, while internal
// emitters may use them without importing op and creating an import cycle.
const (
	AuditAccountCreated             Name = "account.created"
	AuditAccountDeleted             Name = "account.deleted"
	AuditAccountEmailAdded          Name = "account.email.added"
	AuditAccountEmailVerified       Name = "account.email.verified"
	AuditAccountEmailRemoved        Name = "account.email.removed"
	AuditAccountEmailSetPrimary     Name = "account.email.set_primary"
	AuditAccountPasskeyRegistered   Name = "account.passkey.registered"
	AuditAccountPasskeyRemoved      Name = "account.passkey.removed"
	AuditAccountTOTPEnabled         Name = "account.totp.enabled"
	AuditAccountTOTPDisabled        Name = "account.totp.disabled"
	AuditAccountPasswordChanged     Name = "account.password.changed"
	AuditAccountRecoveryRegenerated Name = "account.recovery_codes.regenerated"
	AuditRecoverySupportEscalation  Name = "recovery.support_escalation"
	AuditAccountFederationLinked    Name = "federation.linked"
	AuditAccountFederationUnlinked  Name = "federation.unlinked"

	AuditLoginSuccess   Name = "login.success"
	AuditLoginFailed    Name = "login.failed"
	AuditLockoutStalled Name = "lockout.stalled"
	AuditMFARequired    Name = "mfa.required"
	AuditMFASuccess     Name = "mfa.success"
	AuditMFAFailed      Name = "mfa.failed"
	AuditStepUpRequired Name = "step_up.required"
	AuditStepUpSuccess  Name = "step_up.success"

	AuditConsentGranted              Name = "consent.granted"
	AuditConsentGrantedFirstParty    Name = "consent.granted.first_party"
	AuditConsentGrantedDelta         Name = "consent.granted.delta"
	AuditConsentSkippedExisting      Name = "consent.skipped.existing"
	AuditConsentRevoked              Name = "consent.revoked"
	AuditGrantManagementRevoked      Name = "grant_management.revoked"
	AuditGrantManagementRevokeFailed Name = "grant_management.revoke_failed"

	AuditCodeIssued                          Name = "code.issued"
	AuditCodeConsumed                        Name = "code.consumed"
	AuditCodeReplayDetected                  Name = "code.replay_detected"
	AuditTokenIssued                         Name = "token.issued"
	AuditTokenRefreshed                      Name = "token.refreshed"
	AuditTokenRevoked                        Name = "token.revoked"
	AuditTokenRevokeFailed                   Name = "token.revoke_failed"
	AuditRefreshReplayDetected               Name = "refresh.replay_detected"
	AuditRefreshChainRevokeFailed            Name = "refresh.chain_revoke_failed"
	AuditRefreshGrantRevokeFailed            Name = "refresh.grant_revoke_failed"
	AuditRefreshPriorAccessTokenRevokeFailed Name = "refresh.prior_access_token_revoke_failed"

	AuditSessionCreated       Name = "session.created"
	AuditSessionDestroyed     Name = "session.destroyed"
	AuditSessionAlreadyAbsent Name = "session.already_absent"
	AuditSessionDestroyFailed Name = "session.destroy_failed"
	AuditLogoutRPInitiated    Name = "logout.rp_initiated"
	//nolint:gosec // Event name, not a credential.
	AuditLogoutTokenRevokeFailed        Name = "logout.token_revoke_failed"
	AuditLogoutBackChannelDelivered     Name = "logout.back_channel.delivered"
	AuditLogoutBackChannelFailed        Name = "logout.back_channel.failed"
	AuditLogoutBackChannelResolveFailed Name = "logout.back_channel.resolve_failed"
	AuditLogoutBackChannelOverflow      Name = "logout.back_channel.overflow"
	AuditBCLNoSessionsForSubject        Name = "bcl.no_sessions_for_subject"

	AuditRateLimitExceeded Name = "rate_limit.exceeded"
	//nolint:gosec // Event name, not a credential.
	AuditRateLimitBypassed           Name = "rate_limit.bypassed"
	AuditPKCEViolation               Name = "pkce.violation"
	AuditRedirectURIMismatch         Name = "redirect_uri.mismatch"
	AuditAlgLegacyUsed               Name = "alg.legacy_used"
	AuditCORSPreflightAllowed        Name = "cors.preflight.allowed"
	AuditDPoPLooseMethodCaseAdmitted Name = "dpop.loose_method_case_admitted"
	AuditKeyRetiredKidPresented      Name = "key.retired_kid_presented"
	AuditIntrospectionError          Name = "introspection.error"
	AuditClientAuthnFailure          Name = "client_authn.failure"

	AuditDCRIATConsumed                Name = "dcr.iat.consumed"
	AuditDCRIATExpired                 Name = "dcr.iat.expired"
	AuditDCRIATInvalid                 Name = "dcr.iat.invalid"
	AuditDCROpenRegistrationUsed       Name = "dcr.open_registration_used"
	AuditDCRClientRegistered           Name = "dcr.client.registered"
	AuditDCRClientMetadataRead         Name = "dcr.client.metadata_read"
	AuditDCRClientMetadataUpdated      Name = "dcr.client.metadata_updated"
	AuditDCRClientDeleted              Name = "dcr.client.deleted"
	AuditDCRRATInvalid                 Name = "dcr.rat.invalid"
	AuditDCRMetadataValidation         Name = "dcr.metadata.validation_failed"
	AuditDCRCascadeRefreshRevokeFailed Name = "dcr.cascade.refresh_revoke_failed"
	AuditDCRCascadeGrantRevokeFailed   Name = "dcr.cascade.grant_revoke_failed"
	//nolint:gosec // Event name, not a credential.
	AuditDCRCascadeAccessTokenRevokeFailed Name = "dcr.cascade.access_token_revoke_failed"
	//nolint:gosec // Event name, not a credential.
	AuditDCRCascadeOpaqueAccessTokenRevokeFailed Name = "dcr.cascade.opaque_access_token_revoke_failed"

	AuditDeviceAuthorizationIssued          Name = "device_authorization.issued"
	AuditDeviceAuthorizationRejected        Name = "device_authorization.rejected"
	AuditDeviceAuthorizationUnboundRejected Name = "device_authorization.unbound_rejected"
	AuditDeviceCodeVerificationApproved     Name = "device_code.verification.approved"
	AuditDeviceCodeVerificationDenied       Name = "device_code.verification.denied"
	AuditDeviceCodeUserCodeBruteForce       Name = "device_code.verification.user_code_brute_force"
	AuditDeviceCodeTokenIssued              Name = "device_code.token.issued"
	AuditDeviceCodeTokenRejected            Name = "device_code.token.rejected"
	AuditDeviceCodeTokenSlowDown            Name = "device_code.token.slow_down"
	AuditDeviceCodeRevoked                  Name = "device_code.revoked"
	AuditDeviceCodePollObservationFailed    Name = "device_code.poll_observation.failed"

	AuditCIBAAuthorizationIssued          Name = "ciba.authorization.issued"
	AuditCIBAAuthorizationRejected        Name = "ciba.authorization.rejected"
	AuditCIBAAuthorizationUnboundRejected Name = "ciba.authorization.unbound_rejected"
	AuditCIBAAuthDeviceApproved           Name = "ciba.auth_device.approved"
	AuditCIBAAuthDeviceDenied             Name = "ciba.auth_device.denied"
	AuditCIBAPollAbuseLockout             Name = "ciba.poll_abuse.lockout"
	AuditCIBATokenIssued                  Name = "ciba.token.issued"
	//nolint:gosec // Event name, not a credential.
	AuditCIBATokenRejected         Name = "ciba.token.rejected"
	AuditCIBATokenSlowDown         Name = "ciba.token.slow_down"
	AuditCIBAPollObservationFailed Name = "ciba.poll_observation.failed"

	AuditCustomGrantRequested      Name = "custom_grant.requested"
	AuditCustomGrantFailed         Name = "custom_grant.failed"
	AuditCustomGrantRefreshDropped Name = "custom_grant.refresh_dropped"

	AuditTokenExchangeRequested                 Name = "token_exchange.requested"
	AuditTokenExchangeGranted                   Name = "token_exchange.granted"
	AuditTokenExchangePolicyDenied              Name = "token_exchange.policy_denied"
	AuditTokenExchangePolicyError               Name = "token_exchange.policy_error"
	AuditTokenExchangeScopeInflationBlocked     Name = "token_exchange.scope_inflation_blocked"
	AuditTokenExchangeAudienceBlocked           Name = "token_exchange.audience_blocked"
	AuditTokenExchangeTTLCapped                 Name = "token_exchange.ttl_capped"
	AuditTokenExchangeActChainTooDeep           Name = "token_exchange.act_chain_too_deep"
	AuditTokenExchangeEmptyScopeRejected        Name = "token_exchange.empty_scope_rejected"
	AuditTokenExchangeActorEqualsSubject        Name = "token_exchange.actor_equals_subject"
	AuditTokenExchangeSubjectTokenExternal      Name = "token_exchange.subject_token_external"
	AuditTokenExchangeActorTokenExternal        Name = "token_exchange.actor_token_external"
	AuditTokenExchangeSubjectTokenInvalid       Name = "token_exchange.subject_token_invalid"
	AuditTokenExchangeRefreshIssued             Name = "token_exchange.refresh_issued"
	AuditTokenExchangeSelfExchange              Name = "token_exchange.self_exchange"
	AuditTokenExchangeSubjectTokenRegistryError Name = "token_exchange.subject_token_registry_error"

	// AuditStartupProfile records the security posture a Provider was
	// constructed with: the declared profiles, features, and grants,
	// plus the policy values they resolved to. It fires once per
	// successful op.New, before the Provider serves a request, so
	// every later per-request record can be read against a known
	// configuration.
	AuditStartupProfile Name = "startup.profile"
)

//nolint:gochecknoglobals // immutable closed registry; callers receive copies.
var definitions = []Definition{
	{Name: AuditAccountCreated},
	{Name: AuditAccountDeleted},
	{Name: AuditAccountEmailAdded},
	{Name: AuditAccountEmailVerified},
	{Name: AuditAccountEmailRemoved},
	{Name: AuditAccountEmailSetPrimary},
	{Name: AuditAccountPasskeyRegistered},
	{Name: AuditAccountPasskeyRemoved},
	{Name: AuditAccountTOTPEnabled},
	{Name: AuditAccountTOTPDisabled},
	{Name: AuditAccountPasswordChanged},
	{Name: AuditAccountRecoveryRegenerated},
	{Name: AuditRecoverySupportEscalation},
	{Name: AuditAccountFederationLinked},
	{Name: AuditAccountFederationUnlinked},
	{Name: AuditLoginSuccess, Metric: MetricLoginAttempts, Label: "success"},
	{Name: AuditLoginFailed, Metric: MetricLoginAttempts, Label: "failed"},
	{Name: AuditLockoutStalled},
	{Name: AuditMFARequired},
	{Name: AuditMFASuccess, Metric: MetricLoginAttempts, Label: "success"},
	{Name: AuditMFAFailed, Metric: MetricLoginAttempts, Label: "failed"},
	{Name: AuditStepUpRequired},
	{Name: AuditStepUpSuccess},
	{Name: AuditConsentGranted},
	{Name: AuditConsentGrantedFirstParty},
	{Name: AuditConsentGrantedDelta},
	{Name: AuditConsentSkippedExisting},
	{Name: AuditConsentRevoked},
	{Name: AuditGrantManagementRevoked},
	{Name: AuditGrantManagementRevokeFailed},
	{Name: AuditCodeIssued},
	{Name: AuditCodeConsumed},
	{Name: AuditCodeReplayDetected, Metric: MetricCodeReplay},
	{Name: AuditTokenIssued, Metric: MetricTokenIssued},
	{Name: AuditTokenRefreshed, Metric: MetricTokensRefreshed},
	{Name: AuditTokenRevoked},
	{Name: AuditTokenRevokeFailed, Metric: MetricTokenRevokeFailures, Label: "token"},
	{Name: AuditRefreshReplayDetected, Metric: MetricRefreshReplay},
	{Name: AuditRefreshChainRevokeFailed, Metric: MetricTokenRevokeFailures, Label: "refresh_chain"},
	{Name: AuditRefreshGrantRevokeFailed, Metric: MetricTokenRevokeFailures, Label: "refresh_grant"},
	{Name: AuditRefreshPriorAccessTokenRevokeFailed, Metric: MetricTokenRevokeFailures, Label: "prior_access_token"},
	{Name: AuditSessionCreated},
	{Name: AuditSessionDestroyed},
	{Name: AuditSessionAlreadyAbsent},
	{Name: AuditSessionDestroyFailed, Metric: MetricLogoutFailures, Label: "session_destroy"},
	{Name: AuditLogoutRPInitiated},
	{Name: AuditLogoutTokenRevokeFailed, Metric: MetricLogoutFailures, Label: "token_revoke"},
	{Name: AuditLogoutBackChannelDelivered, Metric: MetricBackChannelLogout, Label: "delivered"},
	{Name: AuditLogoutBackChannelFailed, Metric: MetricBackChannelLogout, Label: "failed"},
	{Name: AuditLogoutBackChannelResolveFailed, Metric: MetricBackChannelLogout, Label: "resolve_failed"},
	{Name: AuditLogoutBackChannelOverflow, Metric: MetricBackChannelLogout, Label: "overflow"},
	{Name: AuditBCLNoSessionsForSubject, Metric: MetricBackChannelLogout, Label: "no_sessions_for_subject"},
	{Name: AuditRateLimitExceeded},
	{Name: AuditRateLimitBypassed},
	{Name: AuditPKCEViolation},
	{Name: AuditRedirectURIMismatch},
	{Name: AuditAlgLegacyUsed},
	{Name: AuditCORSPreflightAllowed},
	{Name: AuditDPoPLooseMethodCaseAdmitted, Metric: MetricDPoPLooseMethodCase},
	{Name: AuditKeyRetiredKidPresented, Metric: MetricKeyRetiredKidPresented},
	{Name: AuditIntrospectionError, Metric: MetricIntrospectionErrors},
	{Name: AuditClientAuthnFailure, Metric: MetricClientAuthnFailures},
	{Name: AuditDCRIATConsumed, Metric: MetricDCR, Label: "iat.consumed"},
	{Name: AuditDCRIATExpired, Metric: MetricDCR, Label: "iat.expired"},
	{Name: AuditDCRIATInvalid, Metric: MetricDCR, Label: "iat.invalid"},
	{Name: AuditDCROpenRegistrationUsed, Metric: MetricDCR, Label: "open_registration_used"},
	{Name: AuditDCRClientRegistered, Metric: MetricDCR, Label: "client.registered"},
	{Name: AuditDCRClientMetadataRead, Metric: MetricDCR, Label: "client.metadata_read"},
	{Name: AuditDCRClientMetadataUpdated, Metric: MetricDCR, Label: "client.metadata_updated"},
	{Name: AuditDCRClientDeleted, Metric: MetricDCR, Label: "client.deleted"},
	{Name: AuditDCRRATInvalid, Metric: MetricDCR, Label: "rat.invalid"},
	{Name: AuditDCRMetadataValidation, Metric: MetricDCR, Label: "metadata.validation_failed"},
	{Name: AuditDCRCascadeRefreshRevokeFailed, Metric: MetricDCR, Label: "cascade.refresh_revoke_failed"},
	{Name: AuditDCRCascadeGrantRevokeFailed, Metric: MetricDCR, Label: "cascade.grant_revoke_failed"},
	{Name: AuditDCRCascadeAccessTokenRevokeFailed, Metric: MetricDCR, Label: "cascade.access_token_revoke_failed"},
	{Name: AuditDCRCascadeOpaqueAccessTokenRevokeFailed, Metric: MetricDCR, Label: "cascade.opaque_access_token_revoke_failed"},
	{Name: AuditDeviceAuthorizationIssued, Metric: MetricDeviceAuthorization, Label: "issued"},
	{Name: AuditDeviceAuthorizationRejected, Metric: MetricDeviceAuthorization, Label: "rejected"},
	{Name: AuditDeviceAuthorizationUnboundRejected, Metric: MetricDeviceAuthorization, Label: "unbound_rejected"},
	{Name: AuditDeviceCodeVerificationApproved, Metric: MetricDeviceCode, Label: "verification.approved"},
	{Name: AuditDeviceCodeVerificationDenied, Metric: MetricDeviceCode, Label: "verification.denied"},
	{Name: AuditDeviceCodeUserCodeBruteForce, Metric: MetricDeviceCode, Label: "verification.user_code_brute_force"},
	{Name: AuditDeviceCodeTokenIssued, Metric: MetricDeviceCode, Label: "token.issued"},
	{Name: AuditDeviceCodeTokenRejected, Metric: MetricDeviceCode, Label: "token.rejected"},
	{Name: AuditDeviceCodeTokenSlowDown, Metric: MetricDeviceCode, Label: "token.slow_down"},
	{Name: AuditDeviceCodeRevoked, Metric: MetricDeviceCode, Label: "revoked"},
	{Name: AuditDeviceCodePollObservationFailed, Metric: MetricDeviceCode, Label: "poll_observation.failed"},
	{Name: AuditCIBAAuthorizationIssued, Metric: MetricCIBA, Label: "authorization.issued"},
	{Name: AuditCIBAAuthorizationRejected, Metric: MetricCIBA, Label: "authorization.rejected"},
	{Name: AuditCIBAAuthorizationUnboundRejected, Metric: MetricCIBA, Label: "authorization.unbound_rejected"},
	{Name: AuditCIBAAuthDeviceApproved, Metric: MetricCIBA, Label: "auth_device.approved"},
	{Name: AuditCIBAAuthDeviceDenied, Metric: MetricCIBA, Label: "auth_device.denied"},
	{Name: AuditCIBAPollAbuseLockout, Metric: MetricCIBA, Label: "poll_abuse.lockout"},
	{Name: AuditCIBATokenIssued, Metric: MetricCIBA, Label: "token.issued"},
	{Name: AuditCIBATokenRejected, Metric: MetricCIBA, Label: "token.rejected"},
	{Name: AuditCIBATokenSlowDown, Metric: MetricCIBA, Label: "token.slow_down"},
	{Name: AuditCIBAPollObservationFailed, Metric: MetricCIBA, Label: "poll_observation.failed"},
	{Name: AuditCustomGrantRequested, Metric: MetricCustomGrant, Label: "requested"},
	{Name: AuditCustomGrantFailed, Metric: MetricCustomGrant, Label: "failed"},
	{Name: AuditCustomGrantRefreshDropped, Metric: MetricCustomGrant, Label: "refresh_dropped"},
	{Name: AuditTokenExchangeRequested, Metric: MetricTokenExchange, Label: "requested"},
	{Name: AuditTokenExchangeGranted, Metric: MetricTokenExchange, Label: "granted"},
	{Name: AuditTokenExchangePolicyDenied, Metric: MetricTokenExchange, Label: "policy_denied"},
	{Name: AuditTokenExchangePolicyError, Metric: MetricTokenExchange, Label: "policy_error"},
	{Name: AuditTokenExchangeScopeInflationBlocked, Metric: MetricTokenExchange, Label: "scope_inflation_blocked"},
	{Name: AuditTokenExchangeAudienceBlocked, Metric: MetricTokenExchange, Label: "audience_blocked"},
	{Name: AuditTokenExchangeTTLCapped, Metric: MetricTokenExchange, Label: "ttl_capped"},
	{Name: AuditTokenExchangeActChainTooDeep, Metric: MetricTokenExchange, Label: "act_chain_too_deep"},
	{Name: AuditTokenExchangeEmptyScopeRejected, Metric: MetricTokenExchange, Label: "empty_scope_rejected"},
	{Name: AuditTokenExchangeActorEqualsSubject, Metric: MetricTokenExchange, Label: "actor_equals_subject"},
	{Name: AuditTokenExchangeSubjectTokenExternal, Metric: MetricTokenExchange, Label: "subject_token_external"},
	{Name: AuditTokenExchangeActorTokenExternal, Metric: MetricTokenExchange, Label: "actor_token_external"},
	{Name: AuditTokenExchangeSubjectTokenInvalid, Metric: MetricTokenExchange, Label: "subject_token_invalid"},
	{Name: AuditTokenExchangeRefreshIssued, Metric: MetricTokenExchange, Label: "refresh_issued"},
	{Name: AuditTokenExchangeSelfExchange, Metric: MetricTokenExchange, Label: "self_exchange"},
	{Name: AuditTokenExchangeSubjectTokenRegistryError, Metric: MetricTokenExchange, Label: "subject_token_registry_error"},
	{Name: AuditStartupProfile},
}

//nolint:gochecknoglobals // immutable index derived exclusively from definitions.
var definitionsByName = indexDefinitions(definitions)

//nolint:gochecknoglobals,gosec // Immutable names; "token" is not a credential.
var metricNames = map[Metric]string{
	MetricTokenIssued:            "oidc_token_issued_total",
	MetricTokensRefreshed:        "oidc_tokens_refreshed_total",
	MetricLoginAttempts:          "oidc_login_attempts_total",
	MetricRefreshReplay:          "oidc_refresh_replay_detected_total",
	MetricCodeReplay:             "oidc_code_replay_detected_total",
	MetricClientAuthnFailures:    "oidc_client_authn_failures_total",
	MetricDCR:                    "oidc_dcr_events_total",
	MetricDeviceAuthorization:    "oidc_device_authorization_events_total",
	MetricDeviceCode:             "oidc_device_code_events_total",
	MetricCIBA:                   "oidc_ciba_events_total",
	MetricTokenExchange:          "oidc_token_exchange_events_total",
	MetricCustomGrant:            "oidc_custom_grant_events_total",
	MetricBackChannelLogout:      "oidc_back_channel_logout_total",
	MetricLogoutFailures:         "oidc_logout_failures_total",
	MetricIntrospectionErrors:    "oidc_introspection_errors_total",
	MetricTokenRevokeFailures:    "oidc_token_revoke_failures_total",
	MetricDPoPLooseMethodCase:    "oidc_dpop_loose_method_case_admitted_total",
	MetricKeyRetiredKidPresented: "oidc_key_retired_kid_presented_total",
}

// Catalog returns a copy of the closed event registry.
func Catalog() []Definition {
	return append([]Definition(nil), definitions...)
}

// Lookup resolves one exact wire name. Unknown names are deliberately not
// prefix-routed: that keeps metric label cardinality closed to this registry.
func Lookup(name string) (Definition, bool) {
	definition, ok := definitionsByName[name]
	return definition, ok
}

func indexDefinitions(catalog []Definition) map[string]Definition {
	out := make(map[string]Definition, len(catalog))
	for _, definition := range catalog {
		name := string(definition.Name)
		out[name] = definition
	}
	return out
}

// MetricName returns the registered Prometheus family name for metric.
func MetricName(metric Metric) string {
	return metricNames[metric]
}

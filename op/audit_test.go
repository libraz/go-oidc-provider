package op_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestAuditEvent_BCLMirror keeps the public op.AuditBCLNoSessionsForSubject
// constant aligned with the raw string that
// internal/backchannel/coordinator.go emits. Same drift-guard pattern
// as TestAuditEvent_DCRMirror: the internal package cannot import op
// (one-way import graph), so the value is duplicated as a string and
// this test pins them together.
func TestAuditEvent_BCLMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"bcl.no_sessions_for_subject": op.AuditBCLNoSessionsForSubject,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_TokenMirror keeps the public token/code audit
// constants aligned with the raw strings the token and revoke
// endpoints emit. The internal handlers cannot import op/, so the
// values are duplicated as strings and this test pins them together.
func TestAuditEvent_TokenMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"code.issued":          op.AuditCodeIssued,
		"code.consumed":        op.AuditCodeConsumed,
		"code.replay_detected": op.AuditCodeReplayDetected,
		"token.issued":         op.AuditTokenIssued,
		"token.refreshed":      op.AuditTokenRefreshed,
		"token.revoked":        op.AuditTokenRevoked,
		"token.revoke_failed":  op.AuditTokenRevokeFailed,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

func TestAuditEvent_ConsentSessionMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"consent.granted":   op.AuditConsentGranted,
		"session.created":   op.AuditSessionCreated,
		"session.destroyed": op.AuditSessionDestroyed,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_RefreshChainRevokeMirror keeps the public
// op.AuditRefreshChainRevokeFailed / op.AuditRefreshGrantRevokeFailed
// constants aligned with the raw strings the refresh exchanger emits
// when the post-replay cascade encounters a transport fault. The
// internal package cannot import op/, so the strings are duplicated
// (auditRefreshChainRevokeFailed / auditRefreshGrantRevokeFailed in
// internal/grants/refresh/refresh.go) and this test pins the values.
func TestAuditEvent_RefreshChainRevokeMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"refresh.chain_revoke_failed": op.AuditRefreshChainRevokeFailed,
		"refresh.grant_revoke_failed": op.AuditRefreshGrantRevokeFailed,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_IntrospectionMirror keeps the public
// op.AuditIntrospectionError constant aligned with the raw string the
// introspection endpoint emits. The internal handler cannot import op/,
// so the value is duplicated as a string (auditIntrospectionError in
// internal/introspectendpoint/handler.go) and this test pins them
// together.
func TestAuditEvent_IntrospectionMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"introspection.error": op.AuditIntrospectionError,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_DeviceCodeMirror keeps the public
// op.AuditDeviceAuthorization* / op.AuditDeviceCode* constants aligned
// with the raw strings the device-flow surfaces emit. The internal
// devicecode helpers (internal/devicecode/audit.go) and the
// devicecodeendpoint / token-endpoint device_code handler all consume
// the raw strings; the public constants are the SOC-facing API and
// must agree byte-for-byte.
func TestAuditEvent_DeviceCodeMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"device_authorization.issued":                    op.AuditDeviceAuthorizationIssued,
		"device_authorization.rejected":                  op.AuditDeviceAuthorizationRejected,
		"device_authorization.unbound_rejected":          op.AuditDeviceAuthorizationUnboundRejected,
		"device_code.verification.approved":              op.AuditDeviceCodeVerificationApproved,
		"device_code.verification.denied":                op.AuditDeviceCodeVerificationDenied,
		"device_code.verification.user_code_brute_force": op.AuditDeviceCodeUserCodeBruteForce,
		"device_code.token.issued":                       op.AuditDeviceCodeTokenIssued,
		"device_code.token.rejected":                     op.AuditDeviceCodeTokenRejected,
		"device_code.token.slow_down":                    op.AuditDeviceCodeTokenSlowDown,
		"device_code.revoked":                            op.AuditDeviceCodeRevoked,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_CIBAMirror keeps the public op.AuditCIBA* constants
// aligned with the raw strings the CIBA surfaces emit. The internal
// ciba helpers (internal/ciba/audit.go) and the cibaendpoint /
// token-endpoint CIBA handler all consume the raw strings; the public
// constants are the SOC-facing API and must agree byte-for-byte.
func TestAuditEvent_CIBAMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"ciba.authorization.issued":           op.AuditCIBAAuthorizationIssued,
		"ciba.authorization.rejected":         op.AuditCIBAAuthorizationRejected,
		"ciba.authorization.unbound_rejected": op.AuditCIBAAuthorizationUnboundRejected,
		"ciba.auth_device.approved":           op.AuditCIBAAuthDeviceApproved,
		"ciba.auth_device.denied":             op.AuditCIBAAuthDeviceDenied,
		"ciba.poll_abuse.lockout":             op.AuditCIBAPollAbuseLockout,
		"ciba.token.issued":                   op.AuditCIBATokenIssued,
		"ciba.token.rejected":                 op.AuditCIBATokenRejected,
		"ciba.token.slow_down":                op.AuditCIBATokenSlowDown,
		"ciba.poll_observation.failed":        op.AuditCIBAPollObservationFailed,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_TokenExchangeMirror keeps the public op.AuditTokenExchange*
// constants aligned with the raw strings the in-tree RFC 8693 handler
// emits. The internal customgrant/tokenexchange package cannot import
// op (one-way import graph), so the values are duplicated as raw
// strings inside internal/customgrant/tokenexchange/audit.go and this
// test pins the two lists together.
func TestAuditEvent_TokenExchangeMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"token_exchange.requested":                    op.AuditTokenExchangeRequested,
		"token_exchange.granted":                      op.AuditTokenExchangeGranted,
		"token_exchange.policy_denied":                op.AuditTokenExchangePolicyDenied,
		"token_exchange.policy_error":                 op.AuditTokenExchangePolicyError,
		"token_exchange.scope_inflation_blocked":      op.AuditTokenExchangeScopeInflationBlocked,
		"token_exchange.audience_blocked":             op.AuditTokenExchangeAudienceBlocked,
		"token_exchange.ttl_capped":                   op.AuditTokenExchangeTTLCapped,
		"token_exchange.act_chain_too_deep":           op.AuditTokenExchangeActChainTooDeep,
		"token_exchange.empty_scope_rejected":         op.AuditTokenExchangeEmptyScopeRejected,
		"token_exchange.actor_equals_subject":         op.AuditTokenExchangeActorEqualsSubject,
		"token_exchange.subject_token_external":       op.AuditTokenExchangeSubjectTokenExternal,
		"token_exchange.actor_token_external":         op.AuditTokenExchangeActorTokenExternal,
		"token_exchange.subject_token_invalid":        op.AuditTokenExchangeSubjectTokenInvalid,
		"token_exchange.refresh_issued":               op.AuditTokenExchangeRefreshIssued,
		"token_exchange.self_exchange":                op.AuditTokenExchangeSelfExchange,
		"token_exchange.subject_token_registry_error": op.AuditTokenExchangeSubjectTokenRegistryError,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_DPoPLooseMethodCaseMirror keeps the public
// op.AuditDPoPLooseMethodCaseAdmitted constant aligned with the raw
// string that the DPoP verifier emits when the
// AllowLooseMethodCase bridge admits a case-mismatched proof. The
// internal package cannot import op/, so the value is duplicated as
// a string (dpop.AuditEventLooseMethodCaseAdmitted in
// internal/dpop/verify.go) and this test pins them together.
func TestAuditEvent_DPoPLooseMethodCaseMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"dpop.loose_method_case_admitted": op.AuditDPoPLooseMethodCaseAdmitted,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_KeyRetiredKidValuePin pins the wire form of the H-F1
// audit event. The constant is emitted from op.go directly (not from
// an internal package) so there is no internal-vs-public drift hazard,
// but pinning the string here keeps SOC dashboards / log queries
// stable across renames: a future contributor who renames the constant
// without updating the wire form sees a loud test failure rather than
// silent breakage of the operator's saved searches.
//
// Tracks H-F1.
func TestAuditEvent_KeyRetiredKidValuePin(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"key.retired_kid_presented": op.AuditKeyRetiredKidPresented,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_ClientAuthnMirror keeps the public
// op.AuditClientAuthnFailure constant aligned with the raw string the
// token and PAR endpoints emit. The internal handlers cannot import
// op/, so the value is duplicated as a string
// (auditClientAuthnFailure in internal/tokenendpoint/handler.go and
// internal/parendpoint/handler.go) and this test pins them together.
func TestAuditEvent_ClientAuthnMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"client_authn.failure": op.AuditClientAuthnFailure,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_FirstPartyMirror keeps the public
// op.AuditConsentGrantedFirstParty constant aligned with the raw
// string the authorize endpoint emits when the [WithFirstPartyClients]
// auto-consent path fires. The internal handler cannot import op/, so
// the value is duplicated as a string
// (opAuditConsentGrantedFirstParty in
// internal/authorizeendpoint/authorize.go) and this test pins them
// together.
func TestAuditEvent_FirstPartyMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"consent.granted.first_party": op.AuditConsentGrantedFirstParty,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_DCRMirror keeps the public op.AuditDCR* constants
// aligned with the strings that the registration endpoint emits.
// The internal handler cannot reference op.AuditEvent (no
// internal-→-op import), so this guard ensures a rename in either
// list produces a loud test failure rather than silent drift.
func TestAuditEvent_DCRMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"dcr.iat.consumed":               op.AuditDCRIATConsumed,
		"dcr.iat.expired":                op.AuditDCRIATExpired,
		"dcr.iat.invalid":                op.AuditDCRIATInvalid,
		"dcr.open_registration_used":     op.AuditDCROpenRegistrationUsed,
		"dcr.client.registered":          op.AuditDCRClientRegistered,
		"dcr.client.metadata_read":       op.AuditDCRClientMetadataRead,
		"dcr.client.metadata_updated":    op.AuditDCRClientMetadataUpdated,
		"dcr.client.deleted":             op.AuditDCRClientDeleted,
		"dcr.rat.invalid":                op.AuditDCRRATInvalid,
		"dcr.metadata.validation_failed": op.AuditDCRMetadataValidation,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestWithAuditLogger_BuildsProvider exercises the option only at
// the construction surface: a non-nil logger is accepted and the
// provider builds. End-to-end audit-emit assertions live in the
// handler-specific tests (e.g. registrationendpoint), where a real
// flow drives the emitter.
func TestWithAuditLogger_BuildsProvider(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	provider, err := op.New(append(validBaseOpts(t), op.WithAuditLogger(logger))...)
	if err != nil {
		t.Fatalf("op.New with audit logger: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}

// TestWithAuditLogger_AcceptsNil documents that passing a nil
// logger is a no-op rather than an error: embedders can call the
// option unconditionally without a guard.
func TestWithAuditLogger_AcceptsNil(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t), op.WithAuditLogger(nil))...)
	if err != nil {
		t.Fatalf("op.New with nil audit logger: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}

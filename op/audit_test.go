package op_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/audit"
)

func TestAuditEventCatalog_ContainsOperationalAndCustomGrantEvents(t *testing.T) {
	t.Parallel()

	want := map[audit.Event]bool{
		audit.SessionAlreadyAbsent:                    false,
		audit.SessionDestroyFailed:                    false,
		audit.LogoutTokenRevokeFailed:                 false,
		audit.LogoutBackChannelResolveFailed:          false,
		audit.LogoutBackChannelOverflow:               false,
		audit.DCRCascadeRefreshRevokeFailed:           false,
		audit.DCRCascadeGrantRevokeFailed:             false,
		audit.DCRCascadeAccessTokenRevokeFailed:       false,
		audit.DCRCascadeOpaqueAccessTokenRevokeFailed: false,
		audit.GrantManagementRevokeFailed:             false,
		audit.RefreshPriorAccessTokenRevokeFailed:     false,
		audit.CustomGrantRequested:                    false,
		audit.CustomGrantFailed:                       false,
		audit.CustomGrantRefreshDropped:               false,
	}
	seen := make(map[audit.Event]struct{}, len(audit.Catalog()))
	for _, definition := range audit.Catalog() {
		if _, duplicate := seen[definition.Event]; duplicate {
			t.Fatalf("duplicate public audit event %q", definition.Event)
		}
		seen[definition.Event] = struct{}{}
		if _, expected := want[definition.Event]; expected {
			want[definition.Event] = true
		}
	}
	for event, found := range want {
		if !found {
			t.Errorf("AuditEventCatalog missing %q", event)
		}
	}
}

// TestAuditEvent_BCLMirror keeps the public audit.BCLNoSessionsForSubject
// constant aligned with the raw string that
// internal/backchannel/coordinator.go emits. Same drift-guard pattern
// as TestAuditEvent_DCRMirror: the internal package cannot import op
// (one-way import graph), so the value is duplicated as a string and
// this test pins them together.
func TestAuditEvent_BCLMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"bcl.no_sessions_for_subject": audit.BCLNoSessionsForSubject,
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

	want := map[string]audit.Event{
		"code.issued":          audit.CodeIssued,
		"code.consumed":        audit.CodeConsumed,
		"code.replay_detected": audit.CodeReplayDetected,
		"token.issued":         audit.TokenIssued,
		"token.refreshed":      audit.TokenRefreshed,
		"token.revoked":        audit.TokenRevoked,
		"token.revoke_failed":  audit.TokenRevokeFailed,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

func TestAuditEvent_ConsentSessionMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"consent.granted":   audit.ConsentGranted,
		"session.created":   audit.SessionCreated,
		"session.destroyed": audit.SessionDestroyed,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_GrantManagementMirror keeps the public
// audit.GrantManagementRevoked constant aligned with the raw string
// the grant-management endpoint emits. The internal handler cannot
// import op/, so the value is duplicated as a string
// (auditGrantManagementRevoked in internal/grantmgmtendpoint/handler.go)
// and this test pins them together.
func TestAuditEvent_GrantManagementMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"grant_management.revoked":       audit.GrantManagementRevoked,
		"grant_management.revoke_failed": audit.GrantManagementRevokeFailed,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_RefreshChainRevokeMirror keeps the public
// audit.RefreshChainRevokeFailed / audit.RefreshGrantRevokeFailed
// constants aligned with the raw strings the refresh exchanger emits
// when the post-replay cascade encounters a transport fault. The
// internal package cannot import op/, so the strings are duplicated
// (auditRefreshChainRevokeFailed / auditRefreshGrantRevokeFailed in
// internal/grants/refresh/refresh.go) and this test pins the values.
func TestAuditEvent_RefreshChainRevokeMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"refresh.chain_revoke_failed":              audit.RefreshChainRevokeFailed,
		"refresh.grant_revoke_failed":              audit.RefreshGrantRevokeFailed,
		"refresh.prior_access_token_revoke_failed": audit.RefreshPriorAccessTokenRevokeFailed,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_IntrospectionMirror keeps the public
// audit.IntrospectionError constant aligned with the raw string the
// introspection endpoint emits. The internal handler cannot import op/,
// so the value is duplicated as a string (auditIntrospectionError in
// internal/introspectendpoint/handler.go) and this test pins them
// together.
func TestAuditEvent_IntrospectionMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"introspection.error": audit.IntrospectionError,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_DeviceCodeMirror keeps the public
// audit.DeviceAuthorization* / audit.DeviceCode* constants aligned
// with the raw strings the device-flow surfaces emit. The internal
// devicecode helpers (internal/devicecode/audit.go) and the
// devicecodeendpoint / token-endpoint device_code handler all consume
// the raw strings; the public constants are the SOC-facing API and
// must agree byte-for-byte.
func TestAuditEvent_DeviceCodeMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"device_authorization.issued":                    audit.DeviceAuthorizationIssued,
		"device_authorization.rejected":                  audit.DeviceAuthorizationRejected,
		"device_authorization.unbound_rejected":          audit.DeviceAuthorizationUnboundRejected,
		"device_code.verification.approved":              audit.DeviceCodeVerificationApproved,
		"device_code.verification.denied":                audit.DeviceCodeVerificationDenied,
		"device_code.verification.user_code_brute_force": audit.DeviceCodeUserCodeBruteForce,
		"device_code.token.issued":                       audit.DeviceCodeTokenIssued,
		"device_code.token.rejected":                     audit.DeviceCodeTokenRejected,
		"device_code.token.slow_down":                    audit.DeviceCodeTokenSlowDown,
		"device_code.revoked":                            audit.DeviceCodeRevoked,
		"device_code.poll_observation.failed":            audit.DeviceCodePollObservationFailed,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_CIBAMirror keeps the public audit.CIBA* constants
// aligned with the raw strings the CIBA surfaces emit. The internal
// ciba helpers (internal/ciba/audit.go) and the cibaendpoint /
// token-endpoint CIBA handler all consume the raw strings; the public
// constants are the SOC-facing API and must agree byte-for-byte.
func TestAuditEvent_CIBAMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"ciba.authorization.issued":           audit.CIBAAuthorizationIssued,
		"ciba.authorization.rejected":         audit.CIBAAuthorizationRejected,
		"ciba.authorization.unbound_rejected": audit.CIBAAuthorizationUnboundRejected,
		"ciba.auth_device.approved":           audit.CIBAAuthDeviceApproved,
		"ciba.auth_device.denied":             audit.CIBAAuthDeviceDenied,
		"ciba.poll_abuse.lockout":             audit.CIBAPollAbuseLockout,
		"ciba.token.issued":                   audit.CIBATokenIssued,
		"ciba.token.rejected":                 audit.CIBATokenRejected,
		"ciba.token.slow_down":                audit.CIBATokenSlowDown,
		"ciba.poll_observation.failed":        audit.CIBAPollObservationFailed,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_TokenExchangeMirror keeps the public audit.TokenExchange*
// constants aligned with the raw strings the in-tree RFC 8693 handler
// emits. The internal customgrant/tokenexchange package cannot import
// op (one-way import graph), so the values are duplicated as raw
// strings inside internal/customgrant/tokenexchange/audit.go and this
// test pins the two lists together.
func TestAuditEvent_TokenExchangeMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"token_exchange.requested":                    audit.TokenExchangeRequested,
		"token_exchange.granted":                      audit.TokenExchangeGranted,
		"token_exchange.policy_denied":                audit.TokenExchangePolicyDenied,
		"token_exchange.policy_error":                 audit.TokenExchangePolicyError,
		"token_exchange.scope_inflation_blocked":      audit.TokenExchangeScopeInflationBlocked,
		"token_exchange.audience_blocked":             audit.TokenExchangeAudienceBlocked,
		"token_exchange.ttl_capped":                   audit.TokenExchangeTTLCapped,
		"token_exchange.act_chain_too_deep":           audit.TokenExchangeActChainTooDeep,
		"token_exchange.empty_scope_rejected":         audit.TokenExchangeEmptyScopeRejected,
		"token_exchange.actor_equals_subject":         audit.TokenExchangeActorEqualsSubject,
		"token_exchange.subject_token_external":       audit.TokenExchangeSubjectTokenExternal,
		"token_exchange.actor_token_external":         audit.TokenExchangeActorTokenExternal,
		"token_exchange.subject_token_invalid":        audit.TokenExchangeSubjectTokenInvalid,
		"token_exchange.refresh_issued":               audit.TokenExchangeRefreshIssued,
		"token_exchange.self_exchange":                audit.TokenExchangeSelfExchange,
		"token_exchange.subject_token_registry_error": audit.TokenExchangeSubjectTokenRegistryError,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_DPoPLooseMethodCaseMirror keeps the public
// audit.DPoPLooseMethodCaseAdmitted constant aligned with the raw
// string that the DPoP verifier emits when the
// AllowLooseMethodCase bridge admits a case-mismatched proof. The
// internal package cannot import op/, so the value is duplicated as
// a string (dpop.AuditEventLooseMethodCaseAdmitted in
// internal/dpop/verify.go) and this test pins them together.
func TestAuditEvent_DPoPLooseMethodCaseMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"dpop.loose_method_case_admitted": audit.DPoPLooseMethodCaseAdmitted,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_KeyRetiredKidValuePin pins the wire form of the
// key-retirement audit event. The constant is emitted from op.go
// directly (not from an internal package) so there is no internal-vs-public drift hazard,
// but pinning the string here keeps SOC dashboards / log queries
// stable across renames: a future contributor who renames the constant
// without updating the wire form sees a loud test failure rather than
// silent breakage of the operator's saved searches.
func TestAuditEvent_KeyRetiredKidValuePin(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"key.retired_kid_presented": audit.KeyRetiredKidPresented,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_ClientAuthnMirror keeps the public
// audit.ClientAuthnFailure constant aligned with the raw string the
// token and PAR endpoints emit. The internal handlers cannot import
// op/, so the value is duplicated as a string
// (auditClientAuthnFailure in internal/tokenendpoint/handler.go and
// internal/parendpoint/handler.go) and this test pins them together.
func TestAuditEvent_ClientAuthnMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"client_authn.failure":         audit.ClientAuthnFailure,
		"client_authn.previous_secret": audit.ClientAuthnPreviousSecret,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_LockoutStalledMirror pins the public constant to the
// wire string the cross-factor brute-force counter emits. The counter
// lives under internal/authn/lockout and cannot import op/, so an
// embedder filtering its audit stream on audit.LockoutStalled is
// matching against a value only this test keeps aligned. A silent drift
// would leave the filter matching nothing — and the event it exists to
// catch reports a brute-force gate that has stopped counting.
func TestAuditEvent_LockoutStalledMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"lockout.stalled": audit.LockoutStalled,
		"lockout.engaged": audit.LockoutEngaged,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_FirstPartyMirror keeps the public
// audit.ConsentGrantedFirstParty constant aligned with the raw
// string the authorize endpoint emits when the [WithFirstPartyClients]
// auto-consent path fires. The internal handler cannot import op/, so
// the value is duplicated as a string
// (opAuditConsentGrantedFirstParty in
// internal/authorizeendpoint/authorize.go) and this test pins them
// together.
func TestAuditEvent_FirstPartyMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"consent.granted.first_party": audit.ConsentGrantedFirstParty,
	}
	for s, ev := range want {
		if string(ev) != s {
			t.Fatalf("AuditEvent %q has value %q, want %q", ev, string(ev), s)
		}
	}
}

// TestAuditEvent_DCRMirror keeps the public audit.DCR* constants
// aligned with the strings that the registration endpoint emits.
// The internal handler cannot reference audit.Event (no
// internal-→-op import), so this guard ensures a rename in either
// list produces a loud test failure rather than silent drift.
func TestAuditEvent_DCRMirror(t *testing.T) {
	t.Parallel()

	want := map[string]audit.Event{
		"dcr.iat.consumed":               audit.DCRIATConsumed,
		"dcr.iat.expired":                audit.DCRIATExpired,
		"dcr.iat.invalid":                audit.DCRIATInvalid,
		"dcr.open_registration_used":     audit.DCROpenRegistrationUsed,
		"dcr.client.registered":          audit.DCRClientRegistered,
		"dcr.client.metadata_read":       audit.DCRClientMetadataRead,
		"dcr.client.metadata_updated":    audit.DCRClientMetadataUpdated,
		"dcr.client.deleted":             audit.DCRClientDeleted,
		"dcr.rat.invalid":                audit.DCRRATInvalid,
		"dcr.metadata.validation_failed": audit.DCRMetadataValidation,
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

// TestWithClock_StampsAuditRecords drives a real Provider construction
// with a fixed clock and asserts the audit record it writes carries
// that instant.
//
// This is the end-to-end half of the claim [op.WithClock] makes. The
// unit test in internal/audit shows the emitter honours a clock it is
// handed; only building a Provider shows the configured clock actually
// reaches the emitter chain the handlers use. startup.profile is the
// branch chosen because op.New emits it unconditionally — no request,
// store, or flow is needed to reach an emission.
func TestWithClock_StampsAuditRecords(t *testing.T) {
	t.Parallel()

	fixed := time.Date(2021, time.September, 9, 1, 46, 40, 0, time.UTC)
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if _, err := op.New(append(validBaseOpts(t),
		op.WithAuditLogger(logger),
		op.WithClock(fakeClock{now: fixed}),
	)...); err != nil {
		t.Fatalf("op.New: %v", err)
	}

	var found bool
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		if rec["event"] != string(audit.StartupProfile) {
			continue
		}
		found = true
		got, err := time.Parse(time.RFC3339Nano, rec[slog.TimeKey].(string))
		if err != nil {
			t.Fatalf("parse record time: %v", err)
		}
		if !got.Equal(fixed) {
			t.Errorf("audit record time = %s, want %s: the configured clock does not reach the emitter", got, fixed)
		}
	}
	if !found {
		t.Fatalf("no %s record on the audit stream: %s", audit.StartupProfile, buf.String())
	}
}

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

// TestAuditEvent_TokenMirror keeps the public op.AuditTokenIssued /
// op.AuditTokenRefreshed constants aligned with the raw strings the
// token endpoint emits. The internal handler cannot import op/, so
// the values are duplicated as strings (auditTokenIssued /
// auditTokenRefreshed in internal/tokenendpoint/handler.go) and this
// test pins them together.
func TestAuditEvent_TokenMirror(t *testing.T) {
	t.Parallel()

	want := map[string]op.AuditEvent{
		"token.issued":    op.AuditTokenIssued,
		"token.refreshed": op.AuditTokenRefreshed,
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

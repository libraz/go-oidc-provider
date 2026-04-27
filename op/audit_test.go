package op_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

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

package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// Compile-time confirmation that every concrete [op.Decision]
// satisfies the sealed interface. The orchestrator's switch-on-type
// evaluation relies on the four cases being total; if a future change
// accidently breaks the marker method, this block fails to compile.
var (
	_ op.Decision = op.Allow{}
	_ op.Decision = op.Pass{}
	_ op.Decision = op.Require{}
	_ op.Decision = op.Deny{}
)

// TestAuditDenyReasonKey_IsStable pins the sentinel: the slog
// attribute key under which [op.Deny.Reason] flows into the audit
// stream MUST stay "audit.deny.reason" so the redact substring
// matcher (configured in internal/redact and tested in op-store
// scope) can keep masking the field without bespoke per-emission
// wiring. A drift in this constant would silently bypass the
// redaction allow-list and leak whatever a misbehaving [op.Decider]
// stuffed into [op.Deny.Reason].
func TestAuditDenyReasonKey_IsStable(t *testing.T) {
	t.Parallel()

	const want = "audit.deny.reason"
	if op.AuditDenyReasonKey != want {
		t.Fatalf("AuditDenyReasonKey = %q, want %q (redaction allow-list depends on this exact string)", op.AuditDenyReasonKey, want)
	}
}

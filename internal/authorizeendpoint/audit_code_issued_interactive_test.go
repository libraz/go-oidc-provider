package authorizeendpoint_test

import (
	"log/slog"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_AuditCodeIssuedOnInteractiveConsent pins that the
// interaction-completion exit emits code.issued exactly once, with the
// same extras shape the silent exit uses.
//
// Operators correlate code.issued against code.consumed to spot replayed
// or injected authorization codes: a consumption with no matching
// issuance is the signal. Every user who passes through the consent
// ceremony takes this exit, so an issuance record missing here would put
// the entire interactive population on the wrong side of that check, and
// would make anyone counting issued codes undercount by the same
// population.
func TestEndToEnd_AuditCodeIssuedOnInteractiveConsent(t *testing.T) {
	t.Parallel()

	sink := &auditSink{}
	f := newE2EFlow(t, "rp-code-issued-interactive",
		testkit.WithOptions(op.WithAuditLogger(slog.New(slog.NewJSONHandler(sink, nil)))))

	code := f.completeLogin(t, f.authorize(t, f.values()), "user-code-issued")

	stream := sink.String()
	if stream == "" {
		t.Fatal("audit sink captured nothing; the logger was not wired")
	}

	issued := auditExtrasFor(t, stream, "code.issued")
	if len(issued) != 1 {
		t.Fatalf("code.issued emitted %d times, want exactly 1", len(issued))
	}
	extras := issued[0]

	if got, want := extras["code_id"], audit.Fingerprint(code); got != want {
		t.Errorf("extras.code_id=%v want %v (the digest of the issued code)", got, want)
	}
	if got, ok := extras["code_id"].(string); !ok || got == code {
		t.Errorf("extras.code_id=%v is the redeemable code, not its digest", extras["code_id"])
	}

	// The grant_id must be the one the consent ceremony recorded, so the
	// two records join. consent.granted is the only other event that
	// carries it on this exit.
	granted := auditExtrasFor(t, stream, "consent.granted")
	if len(granted) != 1 {
		t.Fatalf("consent.granted emitted %d times, want exactly 1", len(granted))
	}
	if got, want := extras["grant_id"], granted[0]["grant_id"]; got != want || got == nil {
		t.Errorf("code.issued grant_id=%v want %v (the granted grant)", got, want)
	}
	if got, want := extras["scope"], granted[0]["scope"]; !scopesEqual(got, want) {
		t.Errorf("code.issued scope=%v want %v (the scope the code was minted with)", got, want)
	}
}

// scopesEqual compares two decoded JSON scope arrays.
func scopesEqual(a, b any) bool {
	as, aok := a.([]any)
	bs, bok := b.([]any)
	if !aok || !bok || len(as) != len(bs) {
		return false
	}
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

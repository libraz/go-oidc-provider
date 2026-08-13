package devicecodekit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/devicecodekit"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// Deps.AuditLogger is the only audit seam an embedder outside this
// module can assign, so every event the helpers raise has to be
// reachable through it. The assertions read the slog records the
// embedder's handler actually received rather than an in-process
// Emitter's Event struct: an emitter captured before the sink cannot
// tell a record that reached the handler from one that did not.

// auditRecords decodes the JSON log lines carrying the audit routing
// attribute and returns them in emission order.
func auditRecords(tb testing.TB, out []byte) []map[string]any {
	tb.Helper()

	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	records := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			tb.Fatalf("decode log line %q: %v", line, err)
		}
		if rec["audit"] != "true" {
			tb.Fatalf("record reached the sink without the audit routing attribute: %v", rec)
		}
		records = append(records, rec)
	}
	return records
}

// eventNames returns the "event" attribute of each record.
func eventNames(records []map[string]any) []string {
	names := make([]string, 0, len(records))
	for _, rec := range records {
		name, _ := rec["event"].(string)
		names = append(names, name)
	}
	return names
}

// TestDeps_AuditLoggerCarriesEveryDeviceCodeEvent drives the four
// events the helpers raise into an embedder-supplied logger. A seam
// that carries only some of them leaves the rest permanently invisible
// to the deployment, since no other sink can be configured from outside.
func TestDeps_AuditLoggerCarriesEveryDeviceCodeEvent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 7, 24, 13, 0, 0, 0, time.UTC)
	s := inmem.New(inmem.WithClock(fixedClock{now: now}))
	ds := s.DeviceCodes()
	for id, userCode := range map[string]string{
		"dev-logger-strike":  "ABCDEFGH",
		"dev-logger-approve": "BCDEFGHJ",
		"dev-logger-deny":    "CDEFGHJK",
		"dev-logger-revoke":  "DEFGHJKM",
	} {
		if err := ds.Save(ctx, &store.DeviceCode{
			ID:        id,
			UserCode:  userCode,
			ClientID:  "client-1",
			Status:    store.DeviceCodeStatusPending,
			IssuedAt:  now,
			ExpiresAt: now.Add(10 * time.Minute),
		}); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}

	var buf bytes.Buffer
	deps := &devicecodekit.Deps{
		DeviceCodes:      ds,
		GrantRevocations: s.GrantRevocations(),
		Clock:            fixedClock{now: now},
		AuditLogger:      slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}

	if matched, err := devicecodekit.VerifyUserCode(ctx, deps, "dev-logger-strike", "WRONGCDE"); err != nil || matched {
		t.Fatalf("VerifyUserCode: matched = %v, err = %v, want a recorded strike", matched, err)
	}
	if err := devicecodekit.ApproveUserCode(ctx, deps, "BCDEFGHJ", "user-1", now); err != nil {
		t.Fatalf("ApproveUserCode: %v", err)
	}
	if err := devicecodekit.DenyUserCode(ctx, deps, "CDEFGHJK", devicecodekit.DenyReasonUserDenied); err != nil {
		t.Fatalf("DenyUserCode: %v", err)
	}
	if err := devicecodekit.Revoke(ctx, deps, "dev-logger-revoke", devicecodekit.DenyReasonUserRevokedDevice); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	records := auditRecords(t, buf.Bytes())
	got := eventNames(records)
	for _, want := range []string{
		"device_code.verification.user_code_brute_force",
		"device_code.verification.approved",
		"device_code.verification.denied",
		"device_code.revoked",
	} {
		found := false
		for _, name := range got {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s never reached the embedder's logger; records were %v", want, got)
		}
	}
}

// TestDeps_AuditLoggerRecordsCarryTheirEvidence pins the payload as
// well as the name: a deny and a brute-force lockout share an event
// name, and an operator separates them by the reason extra. A seam
// that delivered the record but dropped the extras group would answer
// "something was denied" and nothing more.
func TestDeps_AuditLoggerRecordsCarryTheirEvidence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := newVerificationStore()
	newPendingDeviceCode(t, s, "dev-logger-evidence", "EFGHJKMN")

	var buf bytes.Buffer
	deps := &devicecodekit.Deps{
		DeviceCodes: s.DeviceCodes(),
		AuditLogger: slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if err := devicecodekit.DenyUserCode(ctx, deps, "EFGHJKMN", devicecodekit.DenyReasonUserDenied); err != nil {
		t.Fatalf("DenyUserCode: %v", err)
	}

	extras := loggedExtras(t, buf.Bytes(), "device_code.verification.denied")
	if got := extras["reason"]; got != devicecodekit.DenyReasonUserDenied {
		t.Errorf("reason extra reached the sink as %v, want %q", got, devicecodekit.DenyReasonUserDenied)
	}
}

// TestDeps_AuditEmitterPrefersTheInternalSink keeps the precedence
// documented on the deprecated field honest: a library caller that
// still sets Audit keeps its sink, and the logger is not written twice.
func TestDeps_AuditEmitterPrefersTheInternalSink(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := newVerificationStore()
	newPendingDeviceCode(t, s, "dev-logger-precedence", "FGHJKMNP")

	var buf bytes.Buffer
	emitter := &captureEmitter{}
	deps := &devicecodekit.Deps{
		DeviceCodes: s.DeviceCodes(),
		Audit:       emitter,
		AuditLogger: slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if err := devicecodekit.ApproveUserCode(ctx, deps, "FGHJKMNP", "user-1", verificationNow); err != nil {
		t.Fatalf("ApproveUserCode: %v", err)
	}

	if !emitter.containsName("device_code.verification.approved") {
		t.Errorf("the configured Emitter received nothing: %v", emitter.names())
	}
	if buf.Len() != 0 {
		t.Errorf("the same event was also written to AuditLogger, duplicating the record:\n%s", buf.String())
	}
}

// TestDeps_NoAuditSinkStaysSilent keeps the documented default: a Deps
// with neither sink set drops records instead of panicking, so the
// helpers remain safe to call before observability is wired.
func TestDeps_NoAuditSinkStaysSilent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := newVerificationStore()
	newPendingDeviceCode(t, s, "dev-logger-silent", "GHJKMNPQ")

	deps := &devicecodekit.Deps{DeviceCodes: s.DeviceCodes()}
	if err := devicecodekit.ApproveUserCode(ctx, deps, "GHJKMNPQ", "user-1", verificationNow); err != nil {
		t.Fatalf("ApproveUserCode: %v", err)
	}
}

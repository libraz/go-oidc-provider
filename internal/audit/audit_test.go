package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
)

func TestDiscard_DoesNotPanic(t *testing.T) {
	t.Parallel()

	em := audit.Discard()
	em.Emit(context.Background(), audit.Event{Name: "ignored"})
}

func TestSlog_NilLoggerCollapsesToDiscard(t *testing.T) {
	t.Parallel()

	em := audit.Slog(nil)
	em.Emit(context.Background(), audit.Event{Name: "ignored"})
}

func TestSlog_EmitsCanonicalFields(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	em := audit.Slog(logger)

	em.Emit(context.Background(), audit.Event{
		Name:      "login.success",
		Message:   "user signed in",
		ActorID:   "user-123",
		ClientID:  "spa-mainapp",
		SessionID: "sess-abc",
		RequestID: "req-xyz",
		IP:        "192.0.2.10",
		UserAgent: "Mozilla/5.0",
		Extras: map[string]any{
			"authenticator": "passkey",
			"aal":           "AAL2",
		},
	})

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}

	if got := rec["audit"]; got != "true" {
		t.Fatalf("audit attr = %v, want true", got)
	}
	if got := rec["event"]; got != "login.success" {
		t.Fatalf("event = %v, want login.success", got)
	}
	if got := rec["actor_id"]; got != "user-123" {
		t.Fatalf("actor_id = %v", got)
	}
	if got := rec["client_id"]; got != "spa-mainapp" {
		t.Fatalf("client_id = %v", got)
	}
	if got := rec["session_id"]; got != "sess-abc" {
		t.Fatalf("session_id = %v", got)
	}
	if got := rec["request_id"]; got != "req-xyz" {
		t.Fatalf("request_id = %v", got)
	}
	if got := rec["msg"]; got != "user signed in" {
		t.Fatalf("msg = %v", got)
	}
	extras, ok := rec["extras"].(map[string]any)
	if !ok {
		t.Fatalf("extras group missing or wrong type: %T", rec["extras"])
	}
	if extras["authenticator"] != "passkey" {
		t.Fatalf("extras.authenticator = %v", extras["authenticator"])
	}
	if extras["aal"] != "AAL2" {
		t.Fatalf("extras.aal = %v", extras["aal"])
	}
}

func TestSlog_OmitsEmptyCanonicalFields(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	em := audit.Slog(logger)

	em.Emit(context.Background(), audit.Event{
		Name:    "code.issued",
		Message: "auth code minted",
	})

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}

	for _, key := range []string{"actor_id", "client_id", "session_id", "request_id", "ip", "user_agent", "tag", "extras"} {
		if _, present := rec[key]; present {
			t.Fatalf("expected %s to be omitted, got %v", key, rec[key])
		}
	}
}

func TestSlog_LevelMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		lvl  audit.Level
		want string
	}{
		{"info", audit.LevelInfo, "INFO"},
		{"warn", audit.LevelWarn, "WARN"},
		{"error", audit.LevelError, "ERROR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			em := audit.Slog(logger)
			em.Emit(context.Background(), audit.Event{Name: "x", Level: tc.lvl})

			var rec map[string]any
			if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := rec["level"]; got != tc.want {
				t.Fatalf("level = %v, want %s", got, tc.want)
			}
		})
	}
}

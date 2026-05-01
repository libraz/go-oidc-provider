package introspectendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// auditCapture wraps a slog logger that emits audit events as JSON
// records into a bytes.Buffer. The shape mirrors the helper in the
// tokenendpoint suite so a reader who knows that suite can navigate
// here without re-learning the capture surface.
type auditCapture struct {
	buf *bytes.Buffer
}

func newAuditCapture() *auditCapture {
	return &auditCapture{buf: &bytes.Buffer{}}
}

func (c *auditCapture) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(c.buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// findEvents returns every audit record whose "event" attribute
// matches name. The decoder pre-filters non-audit lines by the
// "audit"="true" sentinel so unrelated info records do not pollute
// the assertion.
func (c *auditCapture) findEvents(t *testing.T, name string) []map[string]any {
	t.Helper()
	var out []map[string]any
	dec := json.NewDecoder(strings.NewReader(c.buf.String()))
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("decode audit line: %v", err)
		}
		if rec["audit"] != "true" {
			continue
		}
		if rec["event"] == name {
			out = append(out, rec)
		}
	}
	return out
}

// TestAudit_IntrospectionError_BadSecretEmitsEvent drives a
// /introspect POST whose Basic-auth header carries the right
// client_id but the wrong secret. The handler MUST reject the
// request with 401 invalid_client AND emit a single
// "introspection.error" audit event carrying the failing client_id
// and a "invalid_client_credentials" reason code so SOC tooling can
// distinguish probing patterns the wire response deliberately
// hides.
//
// Spec: RFC 6749 §2.3 / RFC 7662 §2.1.
func TestAudit_IntrospectionError_BadSecretEmitsEvent(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	capture := newAuditCapture()
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithAuditLogger(capture.logger()),
		),
	)
	const (
		clientID = "rp-introspect-bad-secret"
		secret   = "rp-introspect-bad-secret-correct" //nolint:gosec // G101: test fixture credential
	)
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{"token": {"any-value"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, "wrong-secret")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}

	events := capture.findEvents(t, string(op.AuditIntrospectionError))
	if len(events) != 1 {
		t.Fatalf("got %d introspection.error events, want exactly 1; capture=%s",
			len(events), capture.buf.String())
	}
	rec := events[0]
	if got := rec["client_id"]; got != clientID {
		t.Errorf("client_id=%v want %q", got, clientID)
	}
	extras, _ := rec["extras"].(map[string]any)
	if extras == nil {
		t.Fatalf("extras missing on introspection.error: %v", rec)
	}
	if got := extras["reason"]; got != "invalid_client_credentials" {
		t.Errorf("extras.reason=%v want invalid_client_credentials", got)
	}
}

package op_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// rotationClock is a settable clock shared by the OP and its store.
type rotationClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *rotationClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *rotationClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// rotationAuditCounter counts audit records by their event attribute.
type rotationAuditCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (*rotationAuditCounter) Enabled(context.Context, slog.Level) bool { return true }

func (h *rotationAuditCounter) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *rotationAuditCounter) WithGroup(string) slog.Handler { return h }

func (h *rotationAuditCounter) Handle(_ context.Context, rec slog.Record) error {
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == "event" {
			h.mu.Lock()
			h.counts[a.Value.String()]++
			h.mu.Unlock()
		}
		return true
	})
	return nil
}

func (h *rotationAuditCounter) count(event op.AuditEvent) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counts[string(event)]
}

// TestClientSecretRotation_EndToEnd drives the rotation overlap over the
// wire: during the window both secrets authenticate at /token and each
// use of the previous one is audited; from PreviousSecretExpiresAt on,
// only the current secret does.
func TestClientSecretRotation_EndToEnd(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-rotation"
		current  = "rotation-secret-current-0123456789-abcdef"
		previous = "rotation-secret-previous"
	)
	start := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	expiry := start.Add(time.Hour)
	clock := &rotationClock{now: start}
	audit := &rotationAuditCounter{counts: map[string]int{}}

	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithGrants(grant.AuthorizationCode, grant.ClientCredentials),
			op.WithAuditLogger(slog.New(audit)),
			op.WithStaticClients(op.ConfidentialClient{
				ID:                      clientID,
				Secret:                  current,
				PreviousSecret:          previous,
				PreviousSecretExpiresAt: expiry,
				RedirectURIs:            []string{"https://rp.example.com/cb"},
				Scopes:                  []string{"api"},
				GrantTypes:              []string{"client_credentials"},
			}),
		),
	)

	exchange := func(t *testing.T, secret string) (int, map[string]any) {
		t.Helper()
		form := url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("build /token request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, secret)
		resp, err := tk.HTTPClient(nil).Do(req)
		if err != nil {
			t.Fatalf("POST /token: %v", err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		body := map[string]any{}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode body %q: %v", raw, err)
		}
		return resp.StatusCode, body
	}
	requireIssued := func(t *testing.T, secret string) {
		t.Helper()
		status, body := exchange(t, secret)
		if at, _ := body["access_token"].(string); status != http.StatusOK || at == "" {
			t.Fatalf("status=%d body=%v, want 200 with an access_token", status, body)
		}
	}
	requireInvalidClient := func(t *testing.T, secret string) {
		t.Helper()
		status, body := exchange(t, secret)
		if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Fatalf("status=%d body=%v, want 401 invalid_client", status, body)
		}
		if _, ok := body["access_token"]; ok {
			t.Fatalf("body=%v carries an access_token for a refused secret", body)
		}
	}

	requireIssued(t, current)
	if got := audit.count(op.AuditClientAuthnPreviousSecret); got != 0 {
		t.Fatalf("%s emitted %d times for the current secret, want 0", op.AuditClientAuthnPreviousSecret, got)
	}
	requireIssued(t, previous)
	if got := audit.count(op.AuditClientAuthnPreviousSecret); got != 1 {
		t.Fatalf("%s emitted %d times after one previous-secret use, want 1", op.AuditClientAuthnPreviousSecret, got)
	}
	requireInvalidClient(t, "not-either-secret")

	// The expiry instant is already outside the window.
	clock.set(expiry)
	requireInvalidClient(t, previous)
	requireIssued(t, current)
	if got := audit.count(op.AuditClientAuthnPreviousSecret); got != 1 {
		t.Fatalf("%s emitted %d times after the window closed, want 1", op.AuditClientAuthnPreviousSecret, got)
	}
}

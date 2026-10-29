package endpointsupport_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// previousSecretSinks fans one event out to a recorder (for field
// assertions) and to the production slog emitter (for the rendered line).
type previousSecretSinks struct {
	rec  *recordingEmitter
	slog audit.Emitter
}

func (s previousSecretSinks) Emit(ctx context.Context, ev audit.Event) {
	s.rec.Emit(ctx, ev)
	s.slog.Emit(ctx, ev)
}

// TestAuthenticateClient_PreviousSecretAudit pins the success-path event
// raised when a client authenticates with its previous secret: the name,
// the client_id and method attributes, and the absence of the secret from
// both the event and the rendered audit line.
func TestAuthenticateClient_PreviousSecretAudit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	current, currentHash, err := clientauth.NewHighEntropySecret()
	if err != nil {
		t.Fatalf("NewHighEntropySecret current: %v", err)
	}
	previous, previousHash, err := clientauth.NewHighEntropySecret()
	if err != nil {
		t.Fatalf("NewHighEntropySecret previous: %v", err)
	}
	clients := inmem.New()
	if err := clients.RegisterClient(t.Context(), &store.Client{
		ID:                      "client-1",
		SecretHash:              currentHash,
		PreviousSecretHash:      previousHash,
		PreviousSecretExpiresAt: now.Add(time.Hour),
		TokenEndpointAuthMethod: string(clientauth.MethodSecretBasic),
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	cases := []struct {
		name      string
		secret    string
		wantEvent bool
	}{
		{name: "previous secret emits", secret: previous, wantEvent: true},
		{name: "current secret is silent", secret: current, wantEvent: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			sinks := previousSecretSinks{
				rec:  &recordingEmitter{},
				slog: audit.Slog(slog.New(slog.NewJSONHandler(&buf, nil))),
			}
			form := url.Values{"grant_type": {"client_credentials"}}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.SetBasicAuth("client-1", tc.secret)
			rec := httptest.NewRecorder()

			client, _, ok := endpointsupport.AuthenticateClient(t.Context(), rec, r,
				endpointsupport.AuthenticateOpts{
					Clients:        clients,
					SecretVerifier: clientauth.HighEntropy{},
					Now:            now,
					Audit:          sinks,
				},
				func(_ *clientauth.Credentials, err error) { t.Errorf("onFailure: %v", err) },
			)
			if !ok || client == nil || client.ID != "client-1" {
				t.Fatalf("AuthenticateClient: ok=%v client=%v", ok, client)
			}

			if !tc.wantEvent {
				if len(sinks.rec.events) != 0 {
					t.Fatalf("events: got %+v, want none", sinks.rec.events)
				}
				return
			}
			if len(sinks.rec.events) != 1 {
				t.Fatalf("events: got %d, want 1", len(sinks.rec.events))
			}
			ev := sinks.rec.events[0]
			if ev.Name != "client_authn.previous_secret" {
				t.Errorf("name: got %q", ev.Name)
			}
			if ev.ClientID != "client-1" {
				t.Errorf("client_id: got %q", ev.ClientID)
			}
			if ev.Extras["method"] != string(clientauth.MethodSecretBasic) {
				t.Errorf("method: got %v", ev.Extras["method"])
			}
			for _, s := range []string{previous, current, previousHash, currentHash} {
				if strings.Contains(fmt.Sprintf("%+v", ev), s) {
					t.Errorf("event carries secret material: %+v", ev)
				}
				if strings.Contains(buf.String(), s) {
					t.Errorf("audit line carries secret material: %s", buf.String())
				}
			}
			if !strings.Contains(buf.String(), "client_authn.previous_secret") {
				t.Errorf("audit line missing event name: %s", buf.String())
			}
		})
	}
}

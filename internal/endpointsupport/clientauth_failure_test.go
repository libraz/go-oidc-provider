package endpointsupport_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
)

func TestAuthenticateClient_NilClientsReturnsInvalidClient(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(url.Values{
		"client_id":     {"client-1"},
		"client_secret": {"secret"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	_, _, ok := endpointsupport.AuthenticateClient(context.Background(), rr, req, endpointsupport.AuthenticateOpts{}, nil)
	if ok {
		t.Fatal("AuthenticateClient ok=true; want false")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate=%q; want absent for client_secret_post", got)
	}
}

func TestAuthenticateClient_BearerAuthorizationDoesNotTriggerBasicChallenge(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(url.Values{
		"client_id": {"client-1"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()

	_, _, ok := endpointsupport.AuthenticateClient(context.Background(), rr, req, endpointsupport.AuthenticateOpts{}, nil)
	if ok {
		t.Fatal("AuthenticateClient ok=true; want false")
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate=%q; want absent for non-Basic Authorization", got)
	}
}

// TestAuditAuthnFailure_EmitsNamedEventWithClientAndMethod pins the hook
// the token, PAR, CIBA and device-authorization endpoints share: the
// event carries the caller's name and message, the attempted client_id
// and the parsed method.
func TestAuditAuthnFailure_EmitsNamedEventWithClientAndMethod(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(url.Values{
		"client_id":     {"client-1"},
		"client_secret": {"secret"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	rec := &recordingEmitter{}

	_, _, ok := endpointsupport.AuthenticateClient(context.Background(), rr, req, endpointsupport.AuthenticateOpts{},
		endpointsupport.AuditAuthnFailure(context.Background(), rec, endpointsupport.EventClientAuthnFailure, "client authentication failed at token endpoint"))
	if ok {
		t.Fatal("AuthenticateClient ok=true; want false")
	}
	if len(rec.events) != 1 {
		t.Fatalf("events=%d want 1", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Name != endpointsupport.EventClientAuthnFailure || ev.Message != "client authentication failed at token endpoint" {
		t.Errorf("name=%q message=%q", ev.Name, ev.Message)
	}
	if ev.ClientID != "client-1" {
		t.Errorf("ClientID=%q want client-1", ev.ClientID)
	}
	if got := ev.Extras["method"]; got != string(clientauth.MethodSecretPost) {
		t.Errorf("method=%v want %s", got, clientauth.MethodSecretPost)
	}
}

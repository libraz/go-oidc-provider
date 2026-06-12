package clientauthhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth/clientauthhttp"
)

func TestAuthenticate_NilClientsReturnsInvalidClient(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(url.Values{
		"client_id":     {"client-1"},
		"client_secret": {"secret"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	authn := clientauthhttp.Authenticator{}
	_, _, ok := authn.Authenticate(context.Background(), rr, req)
	if ok {
		t.Fatal("Authenticate ok=true; want false")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate=%q; want absent for client_secret_post", got)
	}
}

func TestAuthenticate_BearerAuthorizationDoesNotTriggerBasicChallenge(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(url.Values{
		"client_id": {"client-1"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()

	authn := clientauthhttp.Authenticator{}
	_, _, ok := authn.Authenticate(context.Background(), rr, req)
	if ok {
		t.Fatal("Authenticate ok=true; want false")
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate=%q; want absent for non-Basic Authorization", got)
	}
}

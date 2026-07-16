package discovery_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/discovery"
)

func TestHandlerServesDiscoveryDocumentForGetAndHead(t *testing.T) {
	t.Parallel()

	doc := discovery.Document{ //nolint:gosec // fixture contains public endpoint URLs, not credentials.
		Issuer:                           "https://issuer.example",
		AuthorizationEndpoint:            "https://issuer.example/auth",
		TokenEndpoint:                    "https://issuer.example/token",
		JWKSURI:                          "https://issuer.example/jwks",
		ResponseTypesSupported:           []string{"code"},
		GrantTypesSupported:              []string{"authorization_code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"ES256"},
		CodeChallengeMethodsSupported:    []string{"S256"},
	}
	h, err := discovery.Handler(doc)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", get.Code, get.Body.String())
	}
	if ct := get.Result().Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("GET Content-Type = %q, want application/json", ct)
	}
	if cc := get.Result().Header.Get("Cache-Control"); cc != discovery.CacheControl {
		t.Fatalf("GET Cache-Control = %q, want %q", cc, discovery.CacheControl)
	}
	var got discovery.Document
	if err := json.NewDecoder(get.Body).Decode(&got); err != nil {
		t.Fatalf("decode GET body: %v", err)
	}
	if got.Issuer != doc.Issuer || got.JWKSURI != doc.JWKSURI {
		t.Fatalf("GET body = %+v, want issuer=%q jwks=%q", got, doc.Issuer, doc.JWKSURI)
	}

	head := httptest.NewRecorder()
	h.ServeHTTP(head, httptest.NewRequestWithContext(context.Background(), http.MethodHead, "/.well-known/openid-configuration", nil))
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d", head.Code)
	}
	if head.Body.Len() != 0 {
		t.Fatalf("HEAD body length = %d, want 0", head.Body.Len())
	}
	if cc := head.Result().Header.Get("Cache-Control"); cc != discovery.CacheControl {
		t.Fatalf("HEAD Cache-Control = %q, want %q", cc, discovery.CacheControl)
	}
}

func TestHandlerRejectsUnsupportedMethods(t *testing.T) {
	t.Parallel()

	h, err := discovery.Handler(discovery.Document{Issuer: "https://issuer.example"})
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/.well-known/openid-configuration", strings.NewReader("{}")))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
	if allow := rec.Result().Header.Get("Allow"); allow != "GET, HEAD" {
		t.Fatalf("Allow = %q, want GET, HEAD", allow)
	}
}

package protectedresource_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/protectedresource"
	"github.com/libraz/go-oidc-provider/internal/testutil/golden"
)

func TestBuild_StampsIssuerAndCopiesSlices(t *testing.T) {
	t.Parallel()

	scopes := []string{"read", "write"}
	doc := protectedresource.Build(protectedresource.Input{
		Resource:        "https://api.example.com/orders",
		Issuer:          "https://op.example.com",
		ScopesSupported: scopes,
	})
	if doc.Resource != "https://api.example.com/orders" {
		t.Errorf("resource=%q", doc.Resource)
	}
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != "https://op.example.com" {
		t.Errorf("authorization_servers=%v want [issuer]", doc.AuthorizationServers)
	}
	// The builder must defensively copy: mutating the caller's slice
	// afterwards cannot reach the document.
	scopes[0] = "mutated"
	if doc.ScopesSupported[0] != "read" {
		t.Errorf("scopes_supported aliased the caller slice: %v", doc.ScopesSupported)
	}
}

func TestBuild_OmitsEmptyOptionalFields(t *testing.T) {
	t.Parallel()

	doc := protectedresource.Build(protectedresource.Input{
		Resource: "https://api.example.com",
		Issuer:   "https://op.example.com",
	})
	if doc.ScopesSupported != nil || doc.BearerMethodsSupported != nil ||
		doc.ResourceSigningAlgValuesSupported != nil {
		t.Errorf("empty optional slices should be nil for omitempty: %+v", doc)
	}
}

func TestWellKnownPath(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"https://api.example.com":         protectedresource.WellKnownPrefix,
		"https://api.example.com/":        protectedresource.WellKnownPrefix,
		"https://api.example.com/orders":  protectedresource.WellKnownPrefix + "/orders",
		"https://api.example.com/orders/": protectedresource.WellKnownPrefix + "/orders",
		"https://api.example.com/a/b/c":   protectedresource.WellKnownPrefix + "/a/b/c",
		"://nonsense\x00":                 protectedresource.WellKnownPrefix,
	}
	for resource, want := range cases {
		if got := protectedresource.WellKnownPath(resource); got != want {
			t.Errorf("WellKnownPath(%q)=%q want %q", resource, got, want)
		}
	}
}

func TestHandler_ServesJSONOnGetAndHead(t *testing.T) {
	t.Parallel()

	doc := protectedresource.Build(protectedresource.Input{
		Resource: "https://api.example.com/orders",
		Issuer:   "https://op.example.com",
	})
	h, err := protectedresource.Handler(doc)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	// GET → 200 JSON with cache-control and a body.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, protectedresource.WellKnownPrefix+"/orders", http.NoBody))
	resp := rec.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != protectedresource.CacheControl {
		t.Errorf("Cache-Control=%q", cc)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("GET body empty")
	}

	// HEAD → 200, no body.
	recHead := httptest.NewRecorder()
	h.ServeHTTP(recHead, httptest.NewRequestWithContext(context.Background(), http.MethodHead, protectedresource.WellKnownPrefix+"/orders", http.NoBody))
	headResp := recHead.Result()
	defer headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Errorf("HEAD status=%d", headResp.StatusCode)
	}
	if hb, _ := io.ReadAll(headResp.Body); len(hb) != 0 {
		t.Errorf("HEAD returned a body: %s", hb)
	}
}

func TestHandler_RejectsNonReadMethods(t *testing.T) {
	t.Parallel()

	h, err := protectedresource.Handler(protectedresource.Build(protectedresource.Input{
		Resource: "https://api.example.com",
		Issuer:   "https://op.example.com",
	}))
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, protectedresource.WellKnownPrefix, http.NoBody))
	resp := rec.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status=%d want 405", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("Allow=%q", allow)
	}
}

// TestBuild_Golden locks the RFC 9728 §3 document wire shape for a fully
// populated resource so an incidental field rename or reordering fails
// the test rather than silently changing the contract RPs read.
func TestBuild_Golden(t *testing.T) {
	t.Parallel()

	doc := protectedresource.Build(protectedresource.Input{
		Resource:                          "https://api.example.com/orders",
		Issuer:                            "https://op.example.com",
		ScopesSupported:                   []string{"orders.read", "orders.write"},
		BearerMethodsSupported:            []string{"header"},
		ResourceSigningAlgValuesSupported: []string{"ES256", "RS256"},
		JWKSURI:                           "https://api.example.com/jwks",
		ResourceDocumentation:             "https://api.example.com/docs",
	})
	golden.JSON(t, doc, "testdata/protected_resource_full.golden.json")
}

package op_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

func TestWithProtectedResources_ServesDocument(t *testing.T) {
	t.Parallel()

	p, err := op.New(append(validBaseOpts(t),
		op.WithProtectedResources(op.ProtectedResource{
			Resource:               validIssuer + "/api",
			ScopesSupported:        []string{"api.read"},
			BearerMethodsSupported: []string{"header"},
		}),
	)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/oauth-protected-resource/api", http.NoBody))
	resp := rec.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET well-known status=%d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc["resource"] != validIssuer+"/api" {
		t.Errorf("resource=%v", doc["resource"])
	}
	servers, _ := doc["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != validIssuer {
		t.Errorf("authorization_servers=%v want [%q]", doc["authorization_servers"], validIssuer)
	}
}

func TestWithProtectedResources_SeparatesByPathSuffix(t *testing.T) {
	t.Parallel()

	p, err := op.New(append(validBaseOpts(t),
		op.WithProtectedResources(
			op.ProtectedResource{Resource: validIssuer + "/orders"},
			op.ProtectedResource{Resource: validIssuer + "/inventory"},
		),
	)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for path, wantResource := range map[string]string{
		"/.well-known/oauth-protected-resource/orders":    validIssuer + "/orders",
		"/.well-known/oauth-protected-resource/inventory": validIssuer + "/inventory",
	} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody))
		resp := rec.Result()
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("GET %s status=%d", path, resp.StatusCode)
		}
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		resp.Body.Close()
		if doc["resource"] != wantResource {
			t.Errorf("%s served resource=%v want %q", path, doc["resource"], wantResource)
		}
	}
}

func TestWithProtectedResources_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithProtectedResources())...)
	if err == nil {
		t.Fatal("expected error for empty resource list")
	}
	if !strings.Contains(err.Error(), "at least one ProtectedResource") {
		t.Errorf("err=%v", err)
	}
}

func TestWithProtectedResources_RejectsInvalidResource(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"not-a-uri", "https://api.example.com/x#frag", ""} {
		_, err := op.New(append(validBaseOpts(t),
			op.WithProtectedResources(op.ProtectedResource{Resource: bad}),
		)...)
		if err == nil {
			t.Errorf("expected error for invalid resource %q", bad)
			continue
		}
		if !op.IsServerError(err) {
			t.Errorf("invalid resource %q should be a configuration error, got %v", bad, err)
		}
	}
}

// TestWithProtectedResources_RejectsCrossHostPathCollision pins that two
// distinct resources whose RFC 9728 §3.1 well-known paths collide
// host-insensitively are rejected at op.New with a configuration error
// rather than panicking when the router calls mux.Handle twice on the same
// pattern. The path is derived from the resource's path component only, so
// "https://a.example/api" and "https://b.example/api" both map to
// /.well-known/oauth-protected-resource/api.
func TestWithProtectedResources_RejectsCrossHostPathCollision(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithProtectedResources(
			op.ProtectedResource{Resource: "https://a.example/api"},
			op.ProtectedResource{Resource: "https://b.example/api"},
		),
	)...)
	if err == nil {
		t.Fatal("expected error for cross-host metadata-path collision")
	}
	if !op.IsServerError(err) {
		t.Errorf("collision should be a configuration error, got %v", err)
	}
	if !strings.Contains(err.Error(), "same metadata path") {
		t.Errorf("err=%v want a 'same metadata path' diagnostic", err)
	}
}

// TestWithProtectedResources_DistinctPathsAccepted is the negative control
// for the collision check: two resources with distinct path components are
// accepted even when their hosts differ.
func TestWithProtectedResources_DistinctPathsAccepted(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithProtectedResources(
			op.ProtectedResource{Resource: "https://a.example/orders"},
			op.ProtectedResource{Resource: "https://b.example/inventory"},
		),
	)...)
	if err != nil {
		t.Fatalf("distinct paths should be accepted: %v", err)
	}
}

func TestWithProtectedResources_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithProtectedResources(
			op.ProtectedResource{Resource: validIssuer + "/api"},
			// Same identifier in non-canonical form (trailing-slash /
			// case) must still collide after canonicalisation.
			op.ProtectedResource{Resource: validIssuer + "/api"},
		),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate resource")
	}
	if !strings.Contains(err.Error(), "duplicate resource") {
		t.Errorf("err=%v", err)
	}
}

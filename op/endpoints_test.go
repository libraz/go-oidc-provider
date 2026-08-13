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

// TestEndpoints_SessionIsReservedButUnserved pins what the deprecation
// note on Endpoints.Session states, so the field's documentation cannot
// drift from its behaviour: the prefix is validated and reserved against
// the OP's other endpoint paths, but no handler answers under it and the
// discovery document never advertises it.
func TestEndpoints_SessionIsReservedButUnserved(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithEndpoints(op.Endpoints{
			Session: "/spa-session",
		}),
	)...)
	if err != nil {
		t.Fatalf("op.New with a Session override: %v", err)
	}

	for _, path := range []string{"/oidc/spa-session", "/oidc/spa-session/state"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
		rec := httptest.NewRecorder()
		provider.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404: the session prefix mounts no handler", path, rec.Code)
		}
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", http.NoBody)
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status=%d want 200", rec.Code)
	}
	var doc map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	for key, value := range doc {
		if s, ok := value.(string); ok && strings.Contains(s, "spa-session") {
			t.Errorf("discovery advertises the session prefix under %q = %q", key, s)
		}
	}
}

// TestEndpoints_RejectsOverrideOccupyingConcatenatedDiscoveryPath pins that an
// endpoint override may not take the path a relying party derives by appending
// the well-known suffix to a path-carrying issuer. Serving the OP's own
// endpoints from that URL would leave conformant discovery unreachable, so the
// configuration is refused at construction time.
func TestEndpoints_RejectsOverrideOccupyingConcatenatedDiscoveryPath(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithIssuer(validIssuer+"/tenant"),
		op.WithMountPrefix("/"),
		op.WithEndpoints(op.Endpoints{
			UserInfo: "/.well-known/openid-configuration",
		}),
	)...)
	if err == nil {
		t.Fatal("op.New accepted an endpoint override occupying the concatenated discovery path")
	}
	if !strings.Contains(err.Error(), "/tenant/.well-known/openid-configuration") {
		t.Errorf("error %q does not name the contested path", err)
	}
}

// The other half of the field's documented behaviour — the prefix still
// takes part in the construction-time collision check — is covered by
// the "interaction session prefix" row of
// TestWithEndpoints_RejectsActiveRouteCollisions in options_test.go.

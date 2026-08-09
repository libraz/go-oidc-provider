package scenarios_test

// Catalog: test/scenarios/catalog/protected_resource_metadata.yaml (PRM-NNN)
// Spec:
//   - RFC 9728 §2 (resource metadata parameters)
//   - RFC 9728 §3 / §3.1 (well-known URI, path-suffix)
//   - RFC 9728 §3.3 (authorization_servers)

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const prmWellKnown = "/.well-known/oauth-protected-resource"

func prmProvider(t *testing.T, resources ...op.ProtectedResource) *testkit.Provider {
	t.Helper()
	return testkit.NewProvider(t, testkit.WithOptions(op.WithProtectedResources(resources...)))
}

// prmGet fetches path and returns the status, response headers, and the
// decoded JSON document (empty on a non-200). The response body is closed
// inside the helper so callers never hold an open body.
func prmGet(t *testing.T, tk *testkit.Provider, path string, hdr map[string]string) (int, http.Header, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tk.Server.URL+path, http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	doc := map[string]any{}
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return resp.StatusCode, resp.Header, doc
}

// TestScenario_PRM_001_DocumentServed verifies the registered resource's
// metadata document is served at the well-known path with the resource
// identifier and its advertised scopes / bearer methods.
func TestScenario_PRM_001_DocumentServed(t *testing.T) {
	t.Parallel()
	resource := testkit.DefaultIssuer + "/api"
	tk := prmProvider(t, op.ProtectedResource{
		Resource:               resource,
		ScopesSupported:        []string{"api.read", "api.write"},
		BearerMethodsSupported: []string{"header"},
	})

	status, _, doc := prmGet(t, tk, prmWellKnown+"/api", nil)
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if doc["resource"] != resource {
		t.Errorf("resource=%v want %q", doc["resource"], resource)
	}
	if scopes := toStrings(doc["scopes_supported"]); len(scopes) != 2 || scopes[0] != "api.read" {
		t.Errorf("scopes_supported=%v", doc["scopes_supported"])
	}
	if methods := toStrings(doc["bearer_methods_supported"]); len(methods) != 1 || methods[0] != "header" {
		t.Errorf("bearer_methods_supported=%v", doc["bearer_methods_supported"])
	}
}

// TestScenario_PRM_002_MultipleResourcesSeparatedByPath verifies two
// registered resources are served independently at the path carrying
// each resource identifier's path component (RFC 9728 §3.1).
func TestScenario_PRM_002_MultipleResourcesSeparatedByPath(t *testing.T) {
	t.Parallel()
	orders := testkit.DefaultIssuer + "/orders"
	inventory := testkit.DefaultIssuer + "/inventory"
	tk := prmProvider(t,
		op.ProtectedResource{Resource: orders},
		op.ProtectedResource{Resource: inventory},
	)

	if _, _, doc := prmGet(t, tk, prmWellKnown+"/orders", nil); doc["resource"] != orders {
		t.Errorf("/orders served resource=%v want %q", doc["resource"], orders)
	}
	if _, _, doc := prmGet(t, tk, prmWellKnown+"/inventory", nil); doc["resource"] != inventory {
		t.Errorf("/inventory served resource=%v want %q", doc["resource"], inventory)
	}
}

// TestScenario_PRM_003_AuthorizationServersNamesIssuer verifies
// authorization_servers is the single-element array naming the OP issuer.
func TestScenario_PRM_003_AuthorizationServersNamesIssuer(t *testing.T) {
	t.Parallel()
	tk := prmProvider(t, op.ProtectedResource{Resource: testkit.DefaultIssuer + "/api"})

	_, _, doc := prmGet(t, tk, prmWellKnown+"/api", nil)
	servers := toStrings(doc["authorization_servers"])
	if len(servers) != 1 || servers[0] != testkit.DefaultIssuer {
		t.Errorf("authorization_servers=%v want [%q]", doc["authorization_servers"], testkit.DefaultIssuer)
	}
}

// TestScenario_PRM_004_CrossOriginFetchable verifies the document is
// served with an open CORS posture (Access-Control-Allow-Origin: *).
func TestScenario_PRM_004_CrossOriginFetchable(t *testing.T) {
	t.Parallel()
	tk := prmProvider(t, op.ProtectedResource{Resource: testkit.DefaultIssuer + "/api"})

	status, hdr, _ := prmGet(t, tk, prmWellKnown+"/api", map[string]string{"Origin": "https://rp.example.com"})
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if acao := hdr.Get("Access-Control-Allow-Origin"); acao != "*" {
		t.Errorf("Access-Control-Allow-Origin=%q want *", acao)
	}
}

// TestScenario_PRM_005_InvalidResourceRejectedAtBuild marks where the
// scenario-level test would go. The testkit fails the test on a build
// error, so it cannot observe a construction-time rejection; the row
// names its own coverage in `covered_by` and the gate resolves that
// name, which repeating it here would not.
func TestScenario_PRM_005_InvalidResourceRejectedAtBuild(t *testing.T) {
	t.Parallel()
	t.Skip("covered outside the suite; see the protected_resource_metadata catalog row's covered_by")
}

// toStrings narrows a decoded JSON array to a []string, dropping any
// non-string element. Empty or absent values yield a nil slice.
func toStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

package scenarios_test

// Catalog: test/scenarios/catalog/cors.yaml (COR-NNN)
// Spec:
//   - Fetch / W3C CORS specification
//   - OIDC Discovery 1.0 §5
//   - OIDC Core 1.0 §10 (jwks_uri)
//   - RFC 6749 §3.2 (token endpoint), RFC 7009 / 7662, RFC 8628

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const corsOrigin = "https://rp.example.org"

// corsRequest issues an HTTP request with an Origin header and returns
// the status code and response headers. The body is fully consumed and
// closed inside the helper because all CORS scenarios assert on
// headers, not bodies.
func corsRequest(tb testing.TB, method, url string) (int, http.Header) {
	tb.Helper()
	return corsRequestFrom(tb, method, url, corsOrigin, http.MethodGet)
}

// corsRequestFrom is the variant of corsRequest used by Strict CORS
// scenarios that need to exercise an allowed vs. denied Origin against
// a credentialed endpoint that only accepts POST. preflightMethod is
// echoed in Access-Control-Request-Method on OPTIONS; non-OPTIONS
// requests ignore it.
func corsRequestFrom(tb testing.TB, method, url, origin, preflightMethod string) (int, http.Header) {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Origin", origin)
	if method == http.MethodOptions {
		req.Header.Set("Access-Control-Request-Method", preflightMethod)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		tb.Fatalf("drain body: %v", err)
	}
	return resp.StatusCode, resp.Header.Clone()
}

// TestScenario_COR_001_DiscoveryAllowsAnyOrigin asserts that
// `/.well-known/openid-configuration` echoes the requesting Origin in
// `Access-Control-Allow-Origin` for every caller.
//
// Spec: OIDC Discovery §5.
func TestScenario_COR_001_DiscoveryAllowsAnyOrigin(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	status, headers := corsRequest(t, http.MethodGet, p.Server.URL+"/.well-known/openid-configuration")
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200", status)
	}
	allow := headers.Get("Access-Control-Allow-Origin")
	// Acceptable: either echo the Origin or use "*". Both satisfy
	// "open to any origin".
	if allow != corsOrigin && allow != "*" {
		t.Errorf("Access-Control-Allow-Origin=%q want %q or *", allow, corsOrigin)
	}
	if got := headers.Get("Vary"); !strings.Contains(got, "Origin") {
		t.Errorf("Vary=%q must include Origin", got)
	}
}

// TestScenario_COR_002_DiscoveryPreflightAllowsGET asserts that
// preflight (`OPTIONS`) on the discovery endpoint succeeds with 204.
//
// Spec: OIDC Discovery §5 + Fetch CORS preflight semantics.
func TestScenario_COR_002_DiscoveryPreflightAllowsGET(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	status, headers := corsRequest(t, http.MethodOptions, p.Server.URL+"/.well-known/openid-configuration")
	if status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("preflight status=%d want 204 or 200", status)
	}
	allowMethods := headers.Get("Access-Control-Allow-Methods")
	if !strings.Contains(allowMethods, http.MethodGet) {
		t.Errorf("Access-Control-Allow-Methods=%q must allow GET", allowMethods)
	}
	if got := headers.Get("Access-Control-Allow-Origin"); got == "" {
		t.Errorf("preflight missing Access-Control-Allow-Origin")
	}
}

// TestScenario_COR_003_JWKSAllowsAnyOrigin asserts the JWKS endpoint is
// CORS-open identically to discovery.
//
// Spec: OIDC Core §10 + Fetch CORS.
func TestScenario_COR_003_JWKSAllowsAnyOrigin(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	// Resolve jwks_uri off the discovery doc, then rewrite it onto the
	// httptest base.
	_, _, doc := fetchDiscovery(t, p.Server.URL)
	jwksURI, _ := doc["jwks_uri"].(string)
	if jwksURI == "" {
		t.Fatalf("discovery missing jwks_uri")
	}
	if slash := strings.Index(jwksURI[len("https://"):], "/"); slash >= 0 {
		jwksURI = p.Server.URL + jwksURI[len("https://")+slash:]
	}

	for _, method := range []string{http.MethodGet, http.MethodOptions} {
		_, headers := corsRequest(t, method, jwksURI)
		allow := headers.Get("Access-Control-Allow-Origin")
		if allow != corsOrigin && allow != "*" {
			t.Errorf("[%s] Access-Control-Allow-Origin=%q want %q or *", method, allow, corsOrigin)
		}
	}
}

// --- Pending bindings --------------------------------------------------

func TestScenario_COR_010_UserinfoCORSGatedByClientPolicy(t *testing.T) {
	t.Parallel()
	t.Skip("pending: COR-010 — needs client-based-CORS hook coverage")
}

func TestScenario_COR_011_TokenCORSGatedByClientPolicy(t *testing.T) {
	t.Parallel()
	t.Skip("pending: COR-011")
}

func TestScenario_COR_012_TokenEarlyErrorCarriesCORSHeaders(t *testing.T) {
	t.Parallel()
	t.Skip("pending: COR-012")
}

// TestScenario_COR_013_RevocationCORSGatedByClientPolicy verifies that
// the /revoke endpoint exposes the same Strict-CORS shape as /token: an
// allowlisted Origin gets a 204 preflight and an Access-Control-Allow-Origin
// echo on the actual POST, while a non-allowlisted Origin is rejected with
// 403 on preflight and receives no Allow-Origin echo on the actual POST.
// Vary: Origin is always stamped so a shared cache cannot conflate origins.
//
// Spec: RFC 7009 §2 / plan 002 §F.4.
func TestScenario_COR_013_RevocationCORSGatedByClientPolicy(t *testing.T) {
	t.Parallel()
	p := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithCORSOrigins(allowedRPOrigin),
			op.WithFeature(feature.Revoke),
		),
	)
	assertStrictCORSGatedEndpoint(t, p, "/oidc/revoke", http.MethodPost)
}

// TestScenario_COR_014_IntrospectionCORSGatedByClientPolicy verifies that
// the /introspect endpoint exposes the same Strict-CORS shape as /token: an
// allowlisted Origin gets a 204 preflight and an Access-Control-Allow-Origin
// echo on the actual POST, while a non-allowlisted Origin is rejected with
// 403 on preflight and receives no Allow-Origin echo on the actual POST.
// Vary: Origin is always stamped so a shared cache cannot conflate origins.
//
// Spec: RFC 7662 §2 / plan 002 §F.4.
func TestScenario_COR_014_IntrospectionCORSGatedByClientPolicy(t *testing.T) {
	t.Parallel()
	p := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithCORSOrigins(allowedRPOrigin),
			op.WithFeature(feature.Introspect),
		),
	)
	assertStrictCORSGatedEndpoint(t, p, "/oidc/introspect", http.MethodPost)
}

// assertStrictCORSGatedEndpoint exercises the Strict-CORS shape on a
// credentialed POST endpoint mounted on the given provider. It mirrors
// the assertions used by COR-050/051/052 for /token but consolidates
// preflight + actual checks into a single helper because COR-013/014
// only target one endpoint each. The helper drives both the allowed
// and disallowed Origin axes so callers do not duplicate the matrix.
func assertStrictCORSGatedEndpoint(tb testing.TB, p *testkit.Provider, path, actualMethod string) {
	tb.Helper()
	url := p.Server.URL + path

	// Allowed-Origin preflight: 204 with per-origin echo, credentials,
	// max-age, Vary: Origin.
	status, headers := corsRequestFrom(tb, http.MethodOptions, url, allowedRPOrigin, actualMethod)
	if status != http.StatusNoContent {
		tb.Fatalf("allowed preflight status=%d want 204", status)
	}
	if got := headers.Get("Access-Control-Allow-Origin"); got != allowedRPOrigin {
		tb.Errorf("allowed preflight Access-Control-Allow-Origin=%q want %q", got, allowedRPOrigin)
	}
	if got := headers.Get("Access-Control-Allow-Credentials"); got != "true" {
		tb.Errorf("allowed preflight Access-Control-Allow-Credentials=%q want true", got)
	}
	if got := headers.Get("Access-Control-Max-Age"); got == "" {
		tb.Errorf("allowed preflight Access-Control-Max-Age is empty; preflight should be cacheable")
	}
	if got := headers.Get("Vary"); !strings.Contains(got, "Origin") {
		tb.Errorf("allowed preflight Vary=%q must include Origin", got)
	}

	// Disallowed-Origin preflight: 403, no leak about what would be allowed.
	status, headers = corsRequestFrom(tb, http.MethodOptions, url, disallowedRPOrigin, actualMethod)
	if status != http.StatusForbidden {
		tb.Fatalf("disallowed preflight status=%d want 403", status)
	}
	if got := headers.Get("Access-Control-Allow-Origin"); got != "" {
		tb.Errorf("disallowed preflight Access-Control-Allow-Origin=%q want empty (no leak)", got)
	}
	if got := headers.Get("Access-Control-Allow-Methods"); got != "" {
		tb.Errorf("disallowed preflight Access-Control-Allow-Methods=%q want empty", got)
	}

	// Allowed-Origin actual request: CORS headers stamp before the
	// handler runs and rejects the bare empty body, so we only assert
	// on headers, not on response status.
	_, allowed := corsRequestFrom(tb, actualMethod, url, allowedRPOrigin, actualMethod)
	if got := allowed.Get("Access-Control-Allow-Origin"); got != allowedRPOrigin {
		tb.Errorf("allowed actual Access-Control-Allow-Origin=%q want %q", got, allowedRPOrigin)
	}
	if got := allowed.Get("Vary"); !strings.Contains(got, "Origin") {
		tb.Errorf("allowed actual Vary=%q must include Origin", got)
	}

	// Disallowed-Origin actual request: no Allow-Origin echo, but
	// Vary: Origin still stamped so a shared cache cannot serve the
	// no-CORS response to a later allowed-Origin request.
	_, denied := corsRequestFrom(tb, actualMethod, url, disallowedRPOrigin, actualMethod)
	if got := denied.Get("Access-Control-Allow-Origin"); got != "" {
		tb.Errorf("disallowed actual Access-Control-Allow-Origin=%q want empty", got)
	}
	if got := denied.Get("Vary"); !strings.Contains(got, "Origin") {
		tb.Errorf("disallowed actual Vary=%q must include Origin", got)
	}
}

func TestScenario_COR_015_DeviceAuthorizationCORSGatedByClientPolicy(t *testing.T) {
	t.Parallel()
	t.Skip("pending: COR-015 — device flow not implemented yet")
}

func TestScenario_COR_020_PreflightAlwaysSucceedsForClientGatedEndpoints(t *testing.T) {
	t.Parallel()
	t.Skip("pending: COR-020 — needs clientBasedCORS hook wiring (testkit default uses strict-allowlist gating, not the client-based path this row exercises)")
}

func TestScenario_COR_030_NonBooleanPolicyReturns500WithCORS(t *testing.T) {
	t.Parallel()
	t.Skip("pending: COR-030")
}

func TestScenario_COR_040_EmbedderCORSMiddlewareWins(t *testing.T) {
	t.Parallel()
	t.Skip("pending: COR-040")
}

// strictCORSEndpoints lists the credentialed paths the OP wraps with
// the Strict CORS layer. Each path maps to the HTTP method an SPA would
// preflight; /interaction is GET (UI render), the others are POST (form
// submission or API call).
//
// The list intentionally omits /authorize: that endpoint is reached by
// top-level redirect navigation, not cross-origin fetch, so it is
// served bare.
var strictCORSEndpoints = []struct {
	name           string
	path           string
	preflightForOK string
}{
	{name: "token", path: "/oidc/token", preflightForOK: http.MethodPost},
	{name: "userinfo", path: "/oidc/userinfo", preflightForOK: http.MethodGet},
	{name: "interaction", path: "/oidc/interaction/abc123", preflightForOK: http.MethodGet},
}

// allowedRPOrigin is registered with the OP via WithCORSOrigins and is
// the Origin that Strict CORS scenarios expect to be echoed.
const allowedRPOrigin = "https://rp.example.org"

// disallowedRPOrigin is *not* registered, so Strict CORS scenarios
// expect 403 / no headers when this Origin is presented.
const disallowedRPOrigin = "https://evil.example.org"

// newStrictCORSProvider boots an OP whose CORS allowlist contains
// allowedRPOrigin, used by COR-050/051/052.
func newStrictCORSProvider(tb testing.TB) *testkit.Provider {
	tb.Helper()
	return testkit.NewProvider(tb,
		testkit.WithOptions(op.WithCORSOrigins(allowedRPOrigin)),
	)
}

// TestScenario_COR_050_StrictPreflightAllowsAllowlistOrigin verifies
// that a CORS preflight on a credentialed endpoint from an allowlisted
// Origin returns 204 with the per-origin echo, credentials flag, and
// Vary: Origin. Plan 002 §F.4.
func TestScenario_COR_050_StrictPreflightAllowsAllowlistOrigin(t *testing.T) {
	t.Parallel()
	p := newStrictCORSProvider(t)
	for _, ep := range strictCORSEndpoints {
		t.Run(ep.name, func(t *testing.T) {
			t.Parallel()
			status, headers := corsRequestFrom(t, http.MethodOptions, p.Server.URL+ep.path, allowedRPOrigin, ep.preflightForOK)
			if status != http.StatusNoContent {
				t.Fatalf("preflight status=%d want 204", status)
			}
			if got := headers.Get("Access-Control-Allow-Origin"); got != allowedRPOrigin {
				t.Errorf("Access-Control-Allow-Origin=%q want %q", got, allowedRPOrigin)
			}
			if got := headers.Get("Access-Control-Allow-Credentials"); got != "true" {
				t.Errorf("Access-Control-Allow-Credentials=%q want true", got)
			}
			if got := headers.Get("Access-Control-Max-Age"); got == "" {
				t.Errorf("Access-Control-Max-Age is empty; preflight should be cacheable")
			}
			if got := headers.Get("Vary"); !strings.Contains(got, "Origin") {
				t.Errorf("Vary=%q must include Origin", got)
			}
		})
	}
}

// TestScenario_COR_051_StrictPreflightDeniesUnknownOrigin verifies that
// a CORS preflight on a credentialed endpoint from an Origin outside
// the allowlist is rejected with 403 and no CORS headers (no leak about
// what would have been accepted). Plan 002 §F.4.
func TestScenario_COR_051_StrictPreflightDeniesUnknownOrigin(t *testing.T) {
	t.Parallel()
	p := newStrictCORSProvider(t)
	for _, ep := range strictCORSEndpoints {
		t.Run(ep.name, func(t *testing.T) {
			t.Parallel()
			status, headers := corsRequestFrom(t, http.MethodOptions, p.Server.URL+ep.path, disallowedRPOrigin, ep.preflightForOK)
			if status != http.StatusForbidden {
				t.Fatalf("preflight status=%d want 403", status)
			}
			if got := headers.Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("Access-Control-Allow-Origin=%q want empty (no leak)", got)
			}
			if got := headers.Get("Access-Control-Allow-Methods"); got != "" {
				t.Errorf("Access-Control-Allow-Methods=%q want empty", got)
			}
		})
	}
}

// TestScenario_COR_052_StrictActualEchoGatedByAllowlist verifies that
// an actual (non-preflight) cross-origin request only carries
// Access-Control-Allow-Origin when the Origin is allowlisted, while
// Vary: Origin is set unconditionally. Plan 002 §F.4.
func TestScenario_COR_052_StrictActualEchoGatedByAllowlist(t *testing.T) {
	t.Parallel()
	p := newStrictCORSProvider(t)

	// Allowed Origin: response must echo the Origin even though the
	// underlying handler will reject the bare GET / POST with its own
	// 4xx; CORS headers stamp before the handler runs.
	_, allowed := corsRequestFrom(t, http.MethodGet, p.Server.URL+"/oidc/userinfo", allowedRPOrigin, http.MethodGet)
	if got := allowed.Get("Access-Control-Allow-Origin"); got != allowedRPOrigin {
		t.Errorf("allowed Access-Control-Allow-Origin=%q want %q", got, allowedRPOrigin)
	}
	if got := allowed.Get("Vary"); !strings.Contains(got, "Origin") {
		t.Errorf("allowed Vary=%q must include Origin", got)
	}

	// Disallowed Origin: no Allow-Origin echoed, but Vary: Origin still
	// stamped so a shared cache cannot serve this no-CORS response to a
	// later allowed Origin request.
	_, denied := corsRequestFrom(t, http.MethodGet, p.Server.URL+"/oidc/userinfo", disallowedRPOrigin, http.MethodGet)
	if got := denied.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("disallowed Access-Control-Allow-Origin=%q want empty", got)
	}
	if got := denied.Get("Vary"); !strings.Contains(got, "Origin") {
		t.Errorf("disallowed Vary=%q must include Origin", got)
	}
}

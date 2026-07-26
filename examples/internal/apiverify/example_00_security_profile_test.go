//go:build apiverify

package apiverify

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// 00's deliverable is the contrast between two OPs that differ by one
// option. The same authorization request — a confidential client, no
// code_challenge — is admitted by the OP that declares no profile and
// refused by the one that declares profile.Baseline. Asserting both
// halves is the point: a smoke that only checked the refusal would
// still pass if the profile stopped being conditional and every OP
// started demanding PKCE.
func TestExample00SecurityProfile(t *testing.T) {
	const (
		unprofiled = "http://127.0.0.1:8080"
		baseline   = "http://127.0.0.1:8081"
	)
	authz := url.Values{
		"client_id":     {"profile-demo-rp"},
		"response_type": {"code"},
		"redirect_uri":  {"http://localhost:5173/cb"},
		"scope":         {"openid"},
		"state":         {"apiverify-00"},
	}.Encode()

	p := buildAndStart(t, "../../00-security-profile")
	defer p.kill()

	pollHTTP(t, p, unprofiled+"/.well-known/openid-configuration", 20*time.Second)
	pollHTTP(t, p, baseline+"/.well-known/openid-configuration", 20*time.Second)

	// No profile: OIDC Core 1.0 admits the request, so the OP moves the
	// browser on to its own login prompt rather than bouncing it back.
	admitted := authorizeLocation(t, unprofiled+"/oidc/auth?"+authz)
	if strings.Contains(admitted, "error=") {
		t.Fatalf("unprofiled OP rejected a non-PKCE confidential request: Location=%s", admitted)
	}
	if !strings.Contains(admitted, "/oidc/interaction") {
		t.Fatalf("unprofiled OP Location=%s, want the login prompt", admitted)
	}

	// profile.Baseline: the same request is refused redirect-safely,
	// with the state echoed back per RFC 6749 §4.1.2.1.
	refused := authorizeLocation(t, baseline+"/oidc/auth?"+authz)
	if !strings.Contains(refused, "error=invalid_request") {
		t.Fatalf("baseline OP Location=%s, want error=invalid_request", refused)
	}
	if !strings.Contains(refused, "code_challenge") {
		t.Fatalf("baseline OP Location=%s, want the description to name code_challenge", refused)
	}
	if !strings.Contains(refused, "state=apiverify-00") {
		t.Fatalf("baseline OP Location=%s, want the state preserved", refused)
	}

	// Both OPs record their resolved posture at construction. The demo
	// exists so an operator can read it, so assert it reached stdout.
	logs := p.readLog()
	for _, want := range []string{
		`"event":"startup.profile"`,
		`"pkce_required":false`,
		`"pkce_required":true`,
		`"profiles":["baseline"]`,
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("startup audit output missing %s:\n%s", want, logs)
		}
	}
}

// authorizeLocation issues a single non-following GET against an
// /authorize URL and returns the Location header. Both outcomes the
// test distinguishes are 302s; only the target differs.
func authorizeLocation(t *testing.T, rawURL string) string {
	t.Helper()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		t.Fatalf("build /authorize request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s: status=%d, want 302", rawURL, resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

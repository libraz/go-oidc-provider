package registrationendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// registeredRedirectURI is the callback the client below registers
// through Dynamic Client Registration. Every variant the test drives is
// derived from it, so a matcher that over-matches on the host authority,
// the path, or the scheme has somewhere to fail.
const registeredRedirectURI = "https://rp.test.invalid/callback"

// TestDCR_RegisteredRedirectURIIsMatchedByteExactly pins the property
// that a dynamically registered client is matched exactly as strictly as
// a statically configured one: registration records a literal URI, never
// a pattern, and the authorization endpoint compares against that literal
// byte for byte.
//
// The distinction matters because registration is the one surface where
// an attacker-controlled party supplies the allowlist entry itself. When
// the registered value is treated as a pattern — or when the matcher
// tolerates authority-level variation — a party who may register a client
// at all can register something that looks like the victim's callback and
// have codes delivered elsewhere. Recording the URI verbatim and matching
// it verbatim removes the gap between what was registered and what is
// honoured, so there is no pattern for a crafted URI to exploit.
//
// Tracks: CVE-2026-32235 (Backstage auth-backend) — a redirect_uri that
// satisfied the configured allowlist pattern still resolved to an
// attacker-controlled host under Dynamic Client Registration, delivering
// the authorization code to the attacker.
func TestDCR_RegisteredRedirectURIIsMatchedByteExactly(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	resp := f.post(t, map[string]any{
		"redirect_uris": []string{registeredRedirectURI},
	}, iat)
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status=%d want 201", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	clientID, _ := body["client_id"].(string)
	if clientID == "" {
		t.Fatalf("registration response carries no client_id: %v", body)
	}
	// The response MUST echo the URI unchanged. A registration that
	// normalises, expands, or otherwise rewrites the value would leave
	// the client believing one thing and the matcher enforcing another.
	registered, _ := body["redirect_uris"].([]any)
	if len(registered) != 1 || registered[0] != registeredRedirectURI {
		t.Fatalf("registration rewrote redirect_uris: got %v want [%q]", registered, registeredRedirectURI)
	}

	variants := []struct {
		name string
		uri  string
	}{
		{"host suffix", "https://rp.test.invalid.attacker.example/callback"},
		{"host prefix", "https://attacker.rp.test.invalid/callback"},
		{"host as userinfo", "https://rp.test.invalid@attacker.example/callback"},
		{"host as userinfo, repeated at", "https://rp.test.invalid@@attacker.example/callback"},
		{"host case folded", "https://RP.TEST.INVALID/callback"},
		{"attacker host, registered value in query", "https://attacker.example/callback?next=" + url.QueryEscape(registeredRedirectURI)},
		{"path traversal", "https://rp.test.invalid/callback/../../evil"},
		{"path traversal, semicolon segment", "https://rp.test.invalid/callback/..;/evil"},
		{"path suffix", "https://rp.test.invalid/callback.evil"},
		{"explicit default port", "https://rp.test.invalid:443/callback"},
		{"alternate port", "https://rp.test.invalid:8443/callback"},
		{"scheme downgrade", "http://rp.test.invalid/callback"},
		{"query appended", "https://rp.test.invalid/callback?evil=1"},
		{"fragment appended", "https://rp.test.invalid/callback#evil"},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			assertAuthorizeRefusesRedirect(t, f, clientID, v.uri)
		})
	}
}

// assertAuthorizeRefusesRedirect drives GET /authorize with an
// unregistered redirect_uri and requires the OP to answer without
// redirecting anywhere. RFC 6749 §4.1.2.1 is explicit that a request
// whose redirect_uri does not match a registration MUST NOT be answered
// by redirecting to it: doing so would hand the error — and, on a
// matcher bug, the code — to whoever supplied the URI.
func assertAuthorizeRefusesRedirect(t *testing.T, f *dcrFixture, clientID, redirectURI string) {
	t.Helper()

	values := url.Values{
		"client_id":     {clientID},
		"response_type": {"code"},
		"redirect_uri":  {redirectURI},
		"scope":         {"openid"},
		"state":         {"state-exact-match"},
		"nonce":         {"nonce-exact-match"},
	}
	client := f.prov.HTTPClient(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		f.prov.Server.URL+"/oidc/auth?"+values.Encode(),
		http.NoBody,
	)
	if err != nil {
		t.Fatalf("build /authorize: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		loc, locErr := resp.Location()
		if locErr != nil {
			t.Fatalf("/authorize returned %d with an unreadable Location: %v", resp.StatusCode, locErr)
		}
		t.Fatalf("/authorize redirected to %s for unregistered redirect_uri %q; the registered value is %q",
			loc.String(), redirectURI, registeredRedirectURI)
	}
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("/authorize returned 200 for unregistered redirect_uri %q; the request must be refused", redirectURI)
	}
}

// TestDCR_RejectsRedirectURIShapesThatBlurTheMatch pins the registration
// half of the same property. Exact matching is only meaningful when the
// registered value has one unambiguous reading, so registration refuses
// the shapes that do not: a fragment (which a user agent strips before
// the request ever reaches the OP, so the stored value could never be
// matched), and a relative reference (which has no authority to match at
// all).
func TestDCR_RejectsRedirectURIShapesThatBlurTheMatch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		uri  string
	}{
		{"fragment", "https://rp.test.invalid/callback#frag"},
		{"empty fragment", "https://rp.test.invalid/callback#"},
		{"relative reference", "/callback"},
		{"scheme relative", "//rp.test.invalid/callback"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, op.RegistrationOption{})
			_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})
			resp := f.post(t, map[string]any{"redirect_uris": []string{tc.uri}}, iat)
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusCreated {
				t.Fatalf("registration accepted redirect_uri %q; the value cannot be matched exactly", tc.uri)
			}
			body := decodeBody(t, resp)
			if got, _ := body["error"].(string); got != "invalid_redirect_uri" {
				t.Errorf("error=%q want invalid_redirect_uri for redirect_uri %q (body=%v)", got, tc.uri, body)
			}
		})
	}
}

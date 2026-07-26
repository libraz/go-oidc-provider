// Test file exercises unexported validateRedirectURI helper directly.
//
//nolint:testpackage // exercises unexported helpers
package registrationendpoint

import (
	"errors"
	"strings"
	"testing"
)

// TestValidateRedirectURIs_DefaultIPOnly fixes the safe-by-default
// posture: with allowLocalhostLoopback=false the validator admits the
// IP literals 127.0.0.1 and [::1] over plain http but rejects the
// textual "localhost" host. The matrix doubles as a regression guard
// against accidentally re-opening the public-http surface or the
// pre-default localhost admission.
func TestValidateRedirectURIs_DefaultIPOnly(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"https-public", "https://rp.example.com/cb", false},
		{"https-with-port", "https://rp.example.com:8443/cb", false},
		{"http-localhost", "http://localhost/cb", true},
		{"http-localhost-port", "http://localhost:8080/cb", true},
		{"http-localhost-mixed-case", "http://LocalHost/cb", true},
		{"http-loopback-v4", "http://127.0.0.1/cb", false},
		{"http-loopback-v4-port", "http://127.0.0.1:53682/cb", false},
		{"http-loopback-v6", "http://[::1]/cb", false},
		{"http-loopback-v6-port", "http://[::1]:8080/cb", false},
		{"http-public", "http://rp.example.com/cb", true},
		{"http-private-ip", "http://10.0.0.1/cb", true},
		{"http-link-local", "http://169.254.169.254/cb", true},
		{"http-loopback-v4-block", "http://127.0.0.2/cb", true},
		{"with-fragment", "https://rp.example.com/cb#x", true},
		{"relative", "/cb", true},
		{"empty", "", true},
		{"unknown-scheme", "myapp://rp.example.com/cb", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateRedirectURIs([]string{tc.uri}, "web", false, false)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateRedirectURIs(%q, false) = nil, want error", tc.uri)
				}
				var ve *validationError
				if !errors.As(err, &ve) {
					t.Errorf("error %v is not *validationError", err)
				}
				if ve != nil && ve.code != codeInvalidRedirectURI {
					t.Errorf("error code = %q, want %q", ve.code, codeInvalidRedirectURI)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateRedirectURIs(%q, false) unexpected error: %v", tc.uri, err)
			}
		})
	}
}

// TestValidateRedirectURIs_OptInLocalhost confirms that with
// allowLocalhostLoopback=true the textual "localhost" host (case-
// insensitive) joins the IP literals on the admit list. The IP literal
// rules and the rejection of every non-loopback http target are
// unchanged — the opt-in only widens the §7.3 carve-out, it does not
// loosen any other gate.
func TestValidateRedirectURIs_OptInLocalhost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"http-localhost", "http://localhost/cb", false},
		{"http-localhost-port", "http://localhost:8080/cb", false},
		{"http-localhost-mixed-case", "http://LocalHost/cb", false},
		{"http-loopback-v4", "http://127.0.0.1/cb", false},
		{"http-loopback-v6", "http://[::1]/cb", false},
		{"http-public", "http://rp.example.com/cb", true},
		{"http-private-ip", "http://10.0.0.1/cb", true},
		{"http-loopback-v4-block", "http://127.0.0.2/cb", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateRedirectURIs([]string{tc.uri}, "web", false, true)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateRedirectURIs(%q, true) = nil, want error", tc.uri)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateRedirectURIs(%q, true) unexpected error: %v", tc.uri, err)
			}
		})
	}
}

// TestValidateRedirectURIs_DefaultRejectsLocalhostMessageHints
// confirms the default-mode rejection message points the operator at
// the opt-in option name so a misconfigured DCR client emits a
// remediation hint rather than a flat "rejected" diagnostic.
func TestValidateRedirectURIs_DefaultRejectsLocalhostMessageHints(t *testing.T) {
	t.Parallel()

	err := validateRedirectURIs([]string{"http://localhost:8080/cb"}, "web", false, false)
	if err == nil {
		t.Fatal("expected error in default mode")
	}
	if !strings.Contains(err.Error(), "WithAllowLocalhostLoopback") {
		t.Errorf("error message %q should name the opt-in option for operator remediation", err.Error())
	}
}

// TestValidateRedirectURIs_ErrorMessageMentionsLoopback confirms the
// rejection message names the RFC carve-out so an embedder reading the
// log knows why a non-loopback http URI was refused.
func TestValidateRedirectURIs_ErrorMessageMentionsLoopback(t *testing.T) {
	t.Parallel()

	err := validateRedirectURIs([]string{"http://rp.example.com/cb"}, "web", false, false)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("error message %q should mention loopback for operator clarity", err.Error())
	}
}

// TestValidateRedirectURIs_NativeApplicationType covers the
// application_type=native carve-outs: the
// loopback "localhost" textual host is admitted unconditionally
// (no AllowLocalhostLoopback gate, per OIDC Registration §2), https
// targets are accepted (RFC 8252 §7.2 claimed https), reverse-DNS
// custom URI schemes are accepted (RFC 8252 §7.1), and non-reverse-DNS
// or web-reserved schemes are rejected with a remediation hint.
func TestValidateRedirectURIs_NativeApplicationType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"https", "https://app.example.com/cb", false},
		{"http-loopback-v4", "http://127.0.0.1:53682/cb", false},
		{"http-loopback-v6", "http://[::1]:53682/cb", false},
		{"http-localhost-no-flag", "http://localhost:53682/cb", false},
		{"http-public", "http://rp.example.com/cb", true},
		{"custom-reverse-dns", "com.example.app:/cb", false},
		{"custom-reverse-dns-with-host", "com.example.app://callback/cb", false},
		{"custom-no-dot", "myapp:/cb", true},
		{"web-reserved-ftp", "ftp://example.com/cb", true},
		{"with-fragment", "https://app.example.com/cb#x", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateRedirectURIs([]string{tc.uri}, "native", false, false)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateRedirectURIs(%q, native) = nil, want error", tc.uri)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateRedirectURIs(%q, native) unexpected error: %v", tc.uri, err)
			}
		})
	}
}

// TestValidateRedirectURIs_WebImplicitForbidsLoopbackHost covers OIDC
// Registration §2: web clients using the implicit grant must not
// register a loopback host as redirect_uri. The check is independent
// of the AllowLocalhostLoopback gate because the spec text is about
// the implicit-flow risk surface, not the http-vs-https surface.
func TestValidateRedirectURIs_WebImplicitForbidsLoopbackHost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"https-public-implicit", "https://app.example.com/cb", false},
		{"https-127-loopback-implicit", "https://127.0.0.1/cb", true},
		{"https-localhost-implicit", "https://localhost/cb", true},
		{"https-ipv6-loopback-implicit", "https://[::1]/cb", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateRedirectURIs([]string{tc.uri}, "web", true, false)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateRedirectURIs(%q, web, implicit) = nil, want error", tc.uri)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateRedirectURIs(%q, web, implicit) unexpected error: %v", tc.uri, err)
			}
		})
	}
}

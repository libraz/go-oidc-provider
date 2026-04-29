// Test file exercises unexported validateRedirectURI helper directly.
//
//nolint:testpackage // exercises unexported helpers
package registrationendpoint

import (
	"errors"
	"strings"
	"testing"
)

// TestValidateRedirectURIs_LoopbackOnly fixes the RFC 8252 §7.3 carve-
// out for the http scheme: loopback redirect URIs are admitted, every
// other http target is rejected. The matrix doubles as a regression
// guard against accidentally re-opening the public-http surface that
// older revisions of this validator allowed.
func TestValidateRedirectURIs_LoopbackOnly(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"https-public", "https://rp.example.com/cb", false},
		{"https-with-port", "https://rp.example.com:8443/cb", false},
		{"http-localhost", "http://localhost/cb", false},
		{"http-localhost-port", "http://localhost:8080/cb", false},
		{"http-localhost-mixed-case", "http://LocalHost/cb", false},
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
			err := validateRedirectURIs([]string{tc.uri})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateRedirectURIs(%q) = nil, want error", tc.uri)
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
				t.Fatalf("validateRedirectURIs(%q) unexpected error: %v", tc.uri, err)
			}
		})
	}
}

// TestValidateRedirectURIs_ErrorMessageMentionsLoopback confirms the
// rejection message names the RFC reference so an embedder reading the
// log knows why a non-loopback http URI was refused.
func TestValidateRedirectURIs_ErrorMessageMentionsLoopback(t *testing.T) {
	t.Parallel()

	err := validateRedirectURIs([]string{"http://rp.example.com/cb"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("error message %q should mention loopback for operator clarity", err.Error())
	}
}

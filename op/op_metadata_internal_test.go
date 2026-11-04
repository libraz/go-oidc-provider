package op

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/registrationendpoint"
)

// TestFromInternalMetadata_ProjectsIntrospectionSignedResponseAlg keeps the
// public ValidateMetadata hook aligned with the internal registration shape.
// A missing projection would let the endpoint persist a requested response
// algorithm while an embedder's policy hook silently saw the zero value.
func TestFromInternalMetadata_ProjectsIntrospectionSignedResponseAlg(t *testing.T) {
	t.Parallel()

	got := fromInternalMetadata(registrationendpoint.ClientMetadata{
		IntrospectionSignedResponseAlg: "ES256",
	})
	if got.IntrospectionSignedResponseAlg != "ES256" {
		t.Fatalf("IntrospectionSignedResponseAlg=%q, want ES256", got.IntrospectionSignedResponseAlg)
	}
}

// TestFromInternalMetadata_ProjectsTLSClientAuthMatchers keeps the five
// RFC 8705 §2.1.2 matchers visible to the ValidateMetadata hook, so a policy
// can see what a tls_client_auth registration asked for.
func TestFromInternalMetadata_ProjectsTLSClientAuthMatchers(t *testing.T) {
	t.Parallel()

	got := fromInternalMetadata(registrationendpoint.ClientMetadata{
		TLSClientAuthSubjectDN: "CN=rp",
		TLSClientAuthSANDNS:    "rp.example",
		TLSClientAuthSANURI:    "https://rp.example/id",
		TLSClientAuthSANIP:     "192.0.2.1",
		TLSClientAuthSANEmail:  "rp@example.test",
	})
	want := ClientMetadata{
		TLSClientAuthSubjectDN: "CN=rp",
		TLSClientAuthSANDNS:    "rp.example",
		TLSClientAuthSANURI:    "https://rp.example/id",
		TLSClientAuthSANIP:     "192.0.2.1",
		TLSClientAuthSANEmail:  "rp@example.test",
	}
	if got.TLSClientAuthSubjectDN != want.TLSClientAuthSubjectDN ||
		got.TLSClientAuthSANDNS != want.TLSClientAuthSANDNS ||
		got.TLSClientAuthSANURI != want.TLSClientAuthSANURI ||
		got.TLSClientAuthSANIP != want.TLSClientAuthSANIP ||
		got.TLSClientAuthSANEmail != want.TLSClientAuthSANEmail {
		t.Fatalf("matchers = %q %q %q %q %q, want %q %q %q %q %q",
			got.TLSClientAuthSubjectDN, got.TLSClientAuthSANDNS, got.TLSClientAuthSANURI, got.TLSClientAuthSANIP, got.TLSClientAuthSANEmail,
			want.TLSClientAuthSubjectDN, want.TLSClientAuthSANDNS, want.TLSClientAuthSANURI, want.TLSClientAuthSANIP, want.TLSClientAuthSANEmail)
	}
}

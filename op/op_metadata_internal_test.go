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

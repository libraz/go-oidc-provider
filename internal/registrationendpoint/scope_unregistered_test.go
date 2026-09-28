package registrationendpoint_test

// Spec: RFC 7591 §2 ("scope" — a space-delimited list the server MAY
// restrict).

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestRegister_RejectsScopeNotInRegistry pins that dynamic client
// registration rejects a "scope" value naming a scope the OP's scope
// registry does not know, rather than silently admitting an unknown
// value into the client's registered scope set
// (validateRequestedScopes, internal/registrationendpoint/metadata_validate.go).
//
// Tracks: CVE-2026-61466 — dynamic client registration accepted a
// self-asserted scope the registrant had no authority to claim,
// letting the request itself widen what the client would later be
// allowed to request tokens for.
func TestRegister_RejectsScopeNotInRegistry(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{Open: true})

	body := minimalMetadata()
	body["scope"] = "openid definitely-not-registered"
	resp := f.post(t, body, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_client_metadata" {
		t.Errorf("error=%v want invalid_client_metadata", got["error"])
	}
	desc, _ := got["error_description"].(string)
	if !strings.Contains(desc, "definitely-not-registered") {
		t.Errorf("error_description=%q must name the unregistered scope", desc)
	}
}

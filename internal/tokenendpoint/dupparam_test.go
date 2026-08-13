package tokenendpoint_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestHandler_DuplicateAuthorizationDetailsRejected pins RFC 6749 §3.1
// over the RFC 9396 request parameter: a /token request carrying
// "authorization_details" twice is rejected with 400 invalid_request
// rather than resolved to one of the two payloads.
//
// The request is otherwise fully valid — RAR is enabled, the client
// authenticates, the scope is registered, and each payload passes the
// registered validator on its own — so the only ground for rejection is
// the repetition. That is what separates this from the generic
// duplicate matrix: when the gate does not cover the parameter the
// request succeeds with 200 and the OP silently grants whichever
// occurrence its own parser happened to read, while an upstream proxy
// or WAF may have inspected the other one.
func TestHandler_DuplicateAuthorizationDetailsRejected(t *testing.T) {
	t.Parallel()

	f := newClientCredsFixture(t, paymentAuthorizationDetailsOption())
	client, secret := clientCredsClient(t, f.prov, []string{"payments"})

	form := clientCredsForm("payments")
	form.Add("authorization_details", `[{"type":"payment","amount":"100"}]`)
	form.Add("authorization_details", `[{"type":"payment","amount":"999999"}]`)
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
	if desc, _ := body["error_description"].(string); !strings.Contains(desc, "authorization_details") {
		t.Errorf("error_description=%q want it to name authorization_details", desc)
	}
	if _, ok := body["access_token"]; ok {
		t.Error("response carries an access_token; the duplicate parameter was resolved instead of rejected")
	}
}

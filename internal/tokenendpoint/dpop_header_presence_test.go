package tokenendpoint_test

// RFC 9449 §4.1 allows exactly one DPoP proof per request, and the
// verifier refuses a request that carries more. The endpoint's own
// presence test has to agree with that rule: if it decides "no proof"
// from the first header value alone, a request whose first "DPoP" value
// is empty and whose second carries a real proof never reaches the
// verifier and is answered with an unbound bearer token instead.
//
// client_credentials is the branch with nothing to catch that
// downstream: the binding is established for the first time here, so no
// pre-existing cnf, refresh-chain jkt, or dpop_jkt commitment can fault
// the mismatch afterwards.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// postProofValues submits a /token request carrying one "DPoP" header
// value per entry in proofs, so a test can reproduce the multi-value
// header shape RFC 9449 §4.1 forbids.
func postProofValues(
	t testing.TB,
	f *fixture,
	form url.Values,
	clientID, secret string,
	proofs ...string,
) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	for _, proof := range proofs {
		req.Header.Add("DPoP", proof)
	}
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	return resp
}

// TestClientCredentials_EmptyLeadingDPoPValueDoesNotDowngradeToBearer
// is the control's opposite number: the identical request with a single
// proof value mints a DPoP-bound token
// ([TestClientCredentials_DPoPBound]), so admitting this one would hand
// the client an unbound bearer access token under a request it
// sender-constrained.
func TestClientCredentials_EmptyLeadingDPoPValueDoesNotDowngradeToBearer(t *testing.T) {
	t.Parallel()

	f := dpopFixture(t)
	client, secret := clientCredsDPoPClient(t, f.prov)
	key := newDPoPKey(t)
	proof := makeDPoPProof(t, key, "POST", f.endpoint, f.clock.now, "jti-cc-empty-leading", "")

	resp := postProofValues(t, f, clientCredsForm("read"), client.ID, secret, "", proof)
	defer resp.Body.Close()

	body := decodeJSON(t, resp)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status=200 token_type=%v; the proof was skipped and the token is unbound", body["token_type"])
	}
	if _, has := body["access_token"]; has {
		t.Error("access_token issued; a request whose proof was not verified must not receive one")
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
	if body["error_description"] != "DPoP proof malformed" {
		t.Errorf("error_description=%v want %q", body["error_description"], "DPoP proof malformed")
	}
}

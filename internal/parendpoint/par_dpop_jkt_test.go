package parendpoint_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// committedJKT is a syntactically valid RFC 7638 thumbprint. The tests
// below never derive a token from it, so its provenance does not
// matter — only that the parameter is present and well-formed.
const committedJKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

// newDPoPEnabledFixture mirrors [newFixture] with the DPoP feature
// switched on, so the two can be compared field for field on the one
// axis under test.
func newDPoPEnabledFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.PAR),
			op.WithFeature(feature.DPoP),
		),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/par",
		clock:    clock,
	}
}

// TestPAR_RejectsDPoPJKTWhenDPoPDisabled pins the RFC 9449 §10.1
// commitment contract at the endpoint that can still act on it. An OP
// without DPoP cannot bind the issued token to the committed key nor
// demand proof of possession at /token, so storing the commitment and
// answering 201 would hand the client a request_uri whose only possible
// outcome is invalid_grant several steps later.
func TestPAR_RejectsDPoPJKTWhenDPoPDisabled(t *testing.T) {
	t.Parallel()

	f := newFixture(t) // PAR only: no DPoP verifier is wired.
	client, secret := f.confidentialClient(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
	form.Set("dpop_jkt", committedJKT)

	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 for dpop_jkt with DPoP disabled", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
}

// TestPAR_AcceptsRequestWithoutDPoPJKTWhenDPoPDisabled is the control
// for the test above: the rejection must be attributable to the
// parameter and nothing else about the request.
func TestPAR_AcceptsRequestWithoutDPoPJKTWhenDPoPDisabled(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])

	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body := decodeJSON(t, resp)
		t.Fatalf("status=%d want 201 (body=%v)", resp.StatusCode, body)
	}
}

// TestPAR_AcceptsDPoPJKTWithoutProofWhenDPoPEnabled keeps the gate from
// over-reaching. RFC 9449 §10.1 lets a client commit to a key at the
// authorization request without presenting a proof at that request, so
// with the feature enabled the bare parameter must still be honoured.
func TestPAR_AcceptsDPoPJKTWithoutProofWhenDPoPEnabled(t *testing.T) {
	t.Parallel()

	f := newDPoPEnabledFixture(t)
	client, secret := f.confidentialClient(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
	form.Set("dpop_jkt", committedJKT)

	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body := decodeJSON(t, resp)
		t.Fatalf("status=%d want 201 (body=%v)", resp.StatusCode, body)
	}
}

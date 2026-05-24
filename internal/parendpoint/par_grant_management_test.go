package parendpoint_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// newGMFixture builds a PAR fixture whose OP has the Grant Management draft
// enabled with the create / replace actions (create / replace are
// authorize-time actions; query is endpoint-only). The PAR endpoint must
// validate grant_management_action / grant_id at push time so a request_uri
// is never issued for a request /authorize would reject.
func newGMFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.PAR),
			op.WithGrantManagement([]op.GrantManagementAction{
				op.GrantActionCreate,
				op.GrantActionReplace,
				op.GrantActionQuery,
			}, false),
		),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/par",
		clock:    clock,
	}
}

// gmForm extends the happy-path authorize form with the grant management
// parameters under test.
func gmForm(clientID, redirectURI string, set map[string]string) url.Values {
	v := goodAuthorizeForm(clientID, redirectURI)
	for k, val := range set {
		v.Set(k, val)
	}
	return v
}

// TestHandler_GrantManagement_RejectsEndpointOnlyAction pins that an
// endpoint-only action ("query") presented at the authorization /
// PAR boundary is rejected at push with 400 invalid_request — query /
// revoke are grant-management-endpoint operations, not authorize actions.
func TestHandler_GrantManagement_RejectsEndpointOnlyAction(t *testing.T) {
	t.Parallel()

	f := newGMFixture(t)
	client, secret := f.confidentialClient(t)
	form := gmForm(client.ID, client.RedirectURIs[0], map[string]string{
		"grant_management_action": "query",
	})
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertPARInvalidRequest(t, resp)
}

// TestHandler_GrantManagement_RejectsUnknownAction pins that an action
// outside the defined set ("bogus") is rejected at push.
func TestHandler_GrantManagement_RejectsUnknownAction(t *testing.T) {
	t.Parallel()

	f := newGMFixture(t)
	client, secret := f.confidentialClient(t)
	form := gmForm(client.ID, client.RedirectURIs[0], map[string]string{
		"grant_management_action": "bogus",
	})
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertPARInvalidRequest(t, resp)
}

// TestHandler_GrantManagement_CreateWithGrantIDRejected pins the
// create-with-grant_id rule: a "create" action MUST NOT carry a grant_id.
func TestHandler_GrantManagement_CreateWithGrantIDRejected(t *testing.T) {
	t.Parallel()

	f := newGMFixture(t)
	client, secret := f.confidentialClient(t)
	form := gmForm(client.ID, client.RedirectURIs[0], map[string]string{
		"grant_management_action": "create",
		"grant_id":                "g-123",
	})
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertPARInvalidRequest(t, resp)
}

// TestHandler_GrantManagement_ReplaceWithoutGrantIDRejected pins the
// replace-needs-grant_id rule.
func TestHandler_GrantManagement_ReplaceWithoutGrantIDRejected(t *testing.T) {
	t.Parallel()

	f := newGMFixture(t)
	client, secret := f.confidentialClient(t)
	form := gmForm(client.ID, client.RedirectURIs[0], map[string]string{
		"grant_management_action": "replace",
		// grant_id intentionally omitted.
	})
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertPARInvalidRequest(t, resp)
}

// TestHandler_GrantManagement_ValidCreateAccepted is the negative control:
// a valid "create" action in the configured set is pushed successfully
// (201 with a request_uri).
func TestHandler_GrantManagement_ValidCreateAccepted(t *testing.T) {
	t.Parallel()

	f := newGMFixture(t)
	client, secret := f.confidentialClient(t)
	form := gmForm(client.ID, client.RedirectURIs[0], map[string]string{
		"grant_management_action": "create",
	})
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body := decodeJSON(t, resp)
		t.Fatalf("status=%d want 201; body=%v", resp.StatusCode, body)
	}
	body := decodeJSON(t, resp)
	if uri, _ := body["request_uri"].(string); uri == "" {
		t.Errorf("request_uri missing from accepted GM push: %v", body)
	}
}

// assertPARInvalidRequest fails the test unless resp is a 400 carrying the
// RFC 6749 §5.2 invalid_request JSON envelope (the PAR endpoint never
// redirects; per RFC 9126 §2.3 a rejection is always a JSON envelope).
func assertPARInvalidRequest(tb testing.TB, resp *http.Response) {
	tb.Helper()
	if resp.StatusCode != http.StatusBadRequest {
		body := decodeJSON(tb, resp)
		tb.Fatalf("status=%d want 400; body=%v", resp.StatusCode, body)
	}
	body := decodeJSON(tb, resp)
	if body["error"] != "invalid_request" {
		tb.Errorf("error=%v want invalid_request", body["error"])
	}
}

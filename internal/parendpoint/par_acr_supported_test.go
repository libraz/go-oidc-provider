package parendpoint_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// The contexts the operator below enrolled, and the one a client names
// without being entitled to.
const (
	parAdvertisedACR   = "urn:example:aal2"
	parUnadvertisedACR = "urn:example:aal3"
)

// newACRSupportedFixture builds a /par fixture whose OP publishes a
// two-entry acr_values_supported list, plus the confidential client the
// rows push with.
func newACRSupportedFixture(tb testing.TB) (*fixture, *store.Client, string) {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.PAR),
			op.WithACRValuesSupported("urn:example:aal1", parAdvertisedACR),
		),
	)
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/par", clock: clock}
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      "client-acr-par",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
	})
	return f, client, secret
}

// TestPushedRequest_UnadvertisedACRRejected covers the push-time half of
// the allowlist. RFC 9126 has the AS validate the authorization
// parameters when the request_uri is issued, so a value /authorize will
// refuse must be refused here: minting a request_uri for it spends the
// client's one-time reference on a request that cannot proceed.
func TestPushedRequest_UnadvertisedACRRejected(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name  string
		field string
		value string
	}{
		{name: "acr_values parameter", field: "acr_values", value: parUnadvertisedACR},
		{
			name:  "claims parameter",
			field: "claims",
			value: `{"id_token":{"acr":{"essential":true,"values":["` + parUnadvertisedACR + `"]}}}`,
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			f, client, secret := newACRSupportedFixture(t)
			form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
			form.Set(row.field, row.value)
			resp := f.post(t, form, client.ID, secret)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status=%d want 400", resp.StatusCode)
			}
			body := decodeJSON(t, resp)
			if got, _ := body["error"].(string); got != "invalid_request" {
				t.Errorf("error=%q want invalid_request (body=%v)", got, body)
			}
			if uri, _ := body["request_uri"].(string); uri != "" {
				t.Errorf("a request_uri was minted for an unadvertised acr: %q", uri)
			}
		})
	}
}

// TestPushedRequest_AdvertisedACRAccepted is the control: the gate
// refuses what the operator did not enrol and nothing else.
func TestPushedRequest_AdvertisedACRAccepted(t *testing.T) {
	t.Parallel()

	f, client, secret := newACRSupportedFixture(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
	form.Set("acr_values", parAdvertisedACR)
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	body := decodeJSON(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d want 201 (body=%v)", resp.StatusCode, body)
	}
	if uri, _ := body["request_uri"].(string); uri == "" {
		t.Errorf("request_uri missing from the success envelope: %v", body)
	}
}

// TestPushedRequest_NoAdvertisementAdmitsAnyACR pins the compatibility
// posture: an OP that published no acr_values_supported constrains
// nothing at /par either.
func TestPushedRequest_NoAdvertisementAdmitsAnyACR(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
	form.Set("acr_values", parUnadvertisedACR)
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d want 201 (body=%v)", resp.StatusCode, decodeJSON(t, resp))
	}
}

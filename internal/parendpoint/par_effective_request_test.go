package parendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestPARAuthorizeParity_ClientRegistrationShapesTheVerdict drives a
// request whose verdict depends on the client's registration rather than
// on the wire parameters: the DefaultACRValues backfill, and the
// authorization_code / response_type registration. The pushed and the
// inline request must reach the same verdict with the same wording, so
// /par never mints a request_uri that /authorize then refuses.
func TestPARAuthorizeParity_ClientRegistrationShapesTheVerdict(t *testing.T) {
	t.Parallel()

	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	base := func(id string) *store.Client {
		return &store.Client{
			ID:                      id,
			SecretHash:              hash,
			TokenEndpointAuthMethod: "client_secret_basic",
			RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			Scopes:                  []string{"openid", "profile", "email"},
		}
	}

	rows := []struct {
		name     string
		mutate   func(*store.Client)
		wantCode string
		wantDesc string
	}{
		{
			name:     "default acr outside acr_values_supported",
			mutate:   func(c *store.Client) { c.DefaultACRValues = []string{parUnadvertisedACR} },
			wantCode: "invalid_request",
			wantDesc: "acr_values entry " + parUnadvertisedACR + " is not advertised in acr_values_supported",
		},
		{
			name:   "default acr inside acr_values_supported",
			mutate: func(c *store.Client) { c.DefaultACRValues = []string{parAdvertisedACR} },
		},
		{
			name:     "client not registered for authorization_code",
			mutate:   func(c *store.Client) { c.GrantTypes = []string{"client_credentials"} },
			wantCode: "unauthorized_client",
			wantDesc: "client is not authorized for the authorization_code grant",
		},
		{
			name:     "client not registered for response_type code",
			mutate:   func(c *store.Client) { c.ResponseTypes = nil },
			wantCode: "unauthorized_client",
			wantDesc: "client is not authorized for this response_type",
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			clock := fixedClock{now: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)}
			prov := testkit.NewProvider(t,
				testkit.WithClock(clock),
				testkit.WithOptions(
					op.WithFeature(feature.PAR),
					op.WithACRValuesSupported("urn:example:aal1", parAdvertisedACR),
				),
			)
			f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/par", clock: clock}
			client := base("client-effective-par")
			row.mutate(client)
			if err := prov.Store.RegisterClient(context.Background(), client); err != nil {
				t.Fatalf("RegisterClient: %v", err)
			}
			form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])

			parCode, parDesc, uri := pushOutcome(t, f, form, client.ID, secret)
			authCode, authDesc := inlineAuthorizeOutcome(t, f, form)

			if parCode != authCode || parDesc != authDesc {
				t.Fatalf("/par answered (%q, %q) but /authorize (%q, %q); the gates must agree",
					parCode, parDesc, authCode, authDesc)
			}
			if parCode != row.wantCode || parDesc != row.wantDesc {
				t.Errorf("both endpoints answered (%q, %q), want (%q, %q)",
					parCode, parDesc, row.wantCode, row.wantDesc)
			}
			if row.wantCode != "" && uri != "" {
				t.Errorf("a request_uri was minted for a request /authorize refuses: %q", uri)
			}
		})
	}
}

// pushOutcome pushes form at /par and returns the error code and
// description, both empty on a 201, alongside any minted request_uri.
func pushOutcome(tb testing.TB, f *fixture, form url.Values, clientID, secret string) (string, string, string) {
	tb.Helper()
	resp := f.post(tb, form, clientID, secret)
	defer resp.Body.Close()
	body := decodeJSON(tb, resp)
	if resp.StatusCode == http.StatusCreated {
		uri, _ := body["request_uri"].(string)
		return "", "", uri
	}
	code, _ := body["error"].(string)
	desc, _ := body["error_description"].(string)
	uri, _ := body["request_uri"].(string)
	return code, desc, uri
}

// inlineAuthorizeOutcome submits form inline at /authorize and returns
// the error code and description it redirected with, both empty when the
// request was admitted to an interaction.
func inlineAuthorizeOutcome(tb testing.TB, f *fixture, form url.Values) (string, string) {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		f.prov.Server.URL+"/oidc/auth?"+form.Encode(), http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest /authorize: %v", err)
	}
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("Do /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		tb.Fatalf("/authorize status=%d want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		tb.Fatalf("/authorize 302 without Location: %v", err)
	}
	q := loc.Query()
	return q.Get("error"), q.Get("error_description")
}

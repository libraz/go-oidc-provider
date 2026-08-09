package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
)

// postFormWithQuery issues a token-endpoint POST whose form body is
// body and whose URL carries query. It exists so a test can present the
// very same credential through either channel and compare the outcome.
func postFormWithQuery(tb testing.TB, f *fixture, query, body url.Values) *http.Response {
	tb.Helper()
	target := f.endpoint
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		target,
		strings.NewReader(body.Encode()),
	)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}

// TestTokenEndpoint_RejectsQueryStringClientAssertion pins the channel
// separation the credential parser enforces: the token endpoint takes
// its credentials from the form body only. A client_assertion appended
// to the URL is not authentication material there, because query
// strings survive in proxy logs, access logs, and Referer headers
// (RFC 9700 §2.4) — the request fails with invalid_client even though
// the very same assertion authenticates when carried in the body.
//
// The positive control shares one assertion with the negative case: a
// rejected request must not consume the assertion's jti, so the body
// channel still accepts it afterwards. That also proves the rejection
// comes from the channel and not from a spent or malformed credential.
func TestTokenEndpoint_RejectsQueryStringClientAssertion(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	c := registerPKJWTClient(t, f, "client-pkjwt-query-channel")
	f.seedGrant(t, &store.Grant{
		ID: "grant-query-channel", Subject: "user-1", ClientID: c.id,
		Scope: []string{"openid", "offline_access"},
	})
	for _, id := range []string{"rt-query-channel-1", "rt-query-channel-2"} {
		f.seedRefreshToken(t, &store.RefreshToken{
			ID:       id,
			ClientID: c.id,
			Subject:  "user-1",
			GrantID:  "grant-query-channel",
			Scope:    []string{"openid", "offline_access"},
		})
	}
	assertion := signClientAssertion(t, f, c, "ca-query-channel")

	query := url.Values{}
	query.Set("client_id", c.id)
	query.Set("client_assertion", assertion)
	query.Set("client_assertion_type", clientauth.AssertionType)

	resp := postFormWithQuery(t, f, query, refreshForm("rt-query-channel-1", ""))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("query-borne assertion status=%d want 401, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp)["error"]; got != "invalid_client" {
		t.Errorf("error=%v want invalid_client", got)
	}

	body := refreshForm("rt-query-channel-2", "")
	body.Set("client_id", c.id)
	body.Set("client_assertion", assertion)
	body.Set("client_assertion_type", clientauth.AssertionType)
	control := postFormWithQuery(t, f, nil, body)
	defer control.Body.Close()
	if control.StatusCode != http.StatusOK {
		t.Fatalf("body-borne assertion status=%d want 200, body=%v", control.StatusCode, decodeJSON(t, control))
	}
}

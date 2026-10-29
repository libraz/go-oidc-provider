package tokenendpoint_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestJWTAccessToken_CarriesTheCodesAuthentication redeems a code issued
// under a password-only authentication after a later MFA authorization
// re-stamped the grant, then refreshes it. The JWT access token of both
// responses must report the code's acr and amr, as the opaque row and its
// introspection response do, so a resource server's step-up check reads
// the same authentication whichever format the deployment issues.
func TestJWTAccessToken_CarriesTheCodesAuthentication(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	f.seedGrant(t, &store.Grant{
		ID: "grant-at-acr", Subject: "user-at-acr", ClientID: client.ID,
		Scope:    []string{"openid", "offline_access"},
		AuthTime: f.clock.now.Add(-time.Minute),
		ACR:      "urn:acr:mfa",
		AMR:      []string{"pwd", "otp"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID: "code-at-acr", ClientID: client.ID, Subject: "user-at-acr",
		GrantID: "grant-at-acr", RedirectURI: client.RedirectURIs[0],
		Scope: []string{"openid", "offline_access"}, CodeChallenge: challenge, CodeChallengeMethod: "S256",
		AuthTime: f.clock.now, ACR: "urn:acr:pwd", AMR: []string{"pwd"},
		AuthorizationRecorded: true,
	})

	resp := f.post(t, authCodeForm("code-at-acr", client.RedirectURIs[0], verifier), client.ID, secret)
	body := decodeJSON(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status=%d body=%v", resp.StatusCode, body)
	}
	assertAccessTokenAuthentication(t, "code exchange", decodeJWTPayload(t, body["access_token"].(string)))

	refreshToken, _ := body["refresh_token"].(string)
	resp = f.post(t, refreshForm(refreshToken, ""), client.ID, secret)
	defer resp.Body.Close()
	body = decodeJSON(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d body=%v", resp.StatusCode, body)
	}
	assertAccessTokenAuthentication(t, "refresh", decodeJWTPayload(t, body["access_token"].(string)))
}

func assertAccessTokenAuthentication(tb testing.TB, surface string, claims map[string]any) {
	tb.Helper()
	if got := claims["acr"]; got != "urn:acr:pwd" {
		tb.Errorf("%s access token acr=%v want urn:acr:pwd (the code's)", surface, got)
	}
	if amr, _ := claims["amr"].([]any); len(amr) != 1 || amr[0] != "pwd" {
		tb.Errorf("%s access token amr=%v want [pwd] (the code's)", surface, claims["amr"])
	}
}

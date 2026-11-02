package scenarios_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// ssfWantInvalidTokenEverywhere sends one request carrying token to each
// SSF endpoint and fails unless every one is 401 with an invalid_token
// challenge.
func ssfWantInvalidTokenEverywhere(t *testing.T, tk *testkit.Provider, token, streamID, label string) {
	t.Helper()
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/oidc/ssf/streams?stream_id=" + streamID, ""},
		{http.MethodGet, "/oidc/ssf/status?stream_id=" + streamID, ""},
		{http.MethodPost, "/oidc/ssf/status", `{"stream_id":"` + streamID + `","status":"paused"}`},
		{http.MethodPost, "/oidc/ssf/verify", `{"stream_id":"` + streamID + `"}`},
		{http.MethodPost, "/oidc/ssf/poll/" + streamID, `{"returnImmediately":true}`},
	} {
		req, err := http.NewRequestWithContext(context.Background(), c.method, tk.Server.URL+c.path, strings.NewReader(c.body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := tk.HTTPClient(nil).Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", c.method, c.path, err)
		}
		_ = resp.Body.Close()
		challenge := resp.Header.Get("WWW-Authenticate")
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(challenge, `error="invalid_token"`) {
			t.Errorf("%s token %s %s: status=%d WWW-Authenticate=%q, want 401 invalid_token", label, c.method, c.path, resp.StatusCode, challenge)
		}
	}
}

// TestScenario_SSF_012B_RevokedAndExpiredTokensRefused pins that the SSF
// endpoints judge a receiver's token live exactly as the rest of the OP
// does: a token revoked at /revoke, or past its expiry, is refused with
// invalid_token by streams, status, verify and poll.
func TestScenario_SSF_012B_RevokedAndExpiredTokensRefused(t *testing.T) {
	t.Parallel()
	clock := newAdvanceableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	tk := newSSFProviderWith(t, true, []testkit.Option{
		testkit.WithClock(clock),
		testkit.WithOptions(scenariokit.WithClientCredentials(), op.WithSharedSignals(),
			op.WithFeature(feature.Revoke), op.WithAccessTokenTTL(10*time.Minute)),
	})
	manage := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, manage, map[string]any{})

	revoked := ssfManageToken(t, tk, ssfRxA)
	if status, _ := ssfDoJSON(t, tk, http.MethodGet, "/oidc/ssf/status?stream_id="+id, revoked, nil); status != http.StatusOK {
		t.Fatalf("live token status=%d, want 200", status)
	}
	if status := postRevoke(t, tk, revoked, ssfRxA, ssfSecret); status != http.StatusOK {
		t.Fatalf("revoke status=%d, want 200", status)
	}
	ssfWantInvalidTokenEverywhere(t, tk, revoked, id, "revoked")

	clock.Advance(11 * time.Minute)
	ssfWantInvalidTokenEverywhere(t, tk, manage, id, "expired")

	// The stream survived every refused request.
	fresh := ssfManageToken(t, tk, ssfRxA)
	if status, body := ssfDoJSON(t, tk, http.MethodGet, "/oidc/ssf/status?stream_id="+id, fresh, nil); status != http.StatusOK || body["status"] != "enabled" {
		t.Errorf("status after refused requests: %d %v, want enabled", status, body)
	}
}

// TestScenario_SSF_012C_UserDelegatedTokenRefused pins that a token a
// user delegated through the code flow is not a receiver's management
// credential, even when the client may request ssf.manage: only a
// client_credentials token reaches the SSF endpoints.
func TestScenario_SSF_012C_UserDelegatedTokenRefused(t *testing.T) {
	t.Parallel()
	tk := newSSFProvider(t)
	manage := ssfManageToken(t, tk, ssfRxA)
	id := ssfCreateStream(t, tk, manage, map[string]any{})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    ssfRxA,
		RedirectURI: ssfRedirectURI,
		Scope:       "openid ssf.manage ssf.read",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: ssfRedirectURI, Verifier: pkce.Verifier,
		ClientID: ssfRxA, ClientSecret: ssfSecret,
	})
	if tok.StatusCode != http.StatusOK || !strings.Contains(tok.Scope, "ssf.manage") {
		t.Fatalf("/token status=%d scope=%q body=%v, want a token carrying ssf.manage", tok.StatusCode, tok.Scope, tok.Raw)
	}
	ssfWantInvalidTokenEverywhere(t, tk, tok.AccessToken, id, "user-delegated")
	if status, body := ssfDoJSON(t, tk, http.MethodPatch, "/oidc/ssf/streams", tok.AccessToken,
		map[string]any{"stream_id": id, "delivery": map[string]any{"method": ssfPushMethod, "endpoint_url": "https://attacker.example/push"}}); status != http.StatusUnauthorized {
		t.Errorf("user-delegated PATCH status=%d body=%v, want 401", status, body)
	}
}

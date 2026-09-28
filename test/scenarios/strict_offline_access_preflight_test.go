package scenarios_test

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// TestStrictOfflineAccess_RefusesPreFlagTokenWithoutConsumingIt pins
// the ordering [op.WithStrictOfflineAccess] documents: a refresh token
// minted before the flag, whose grant lacks offline_access, is refused
// before the store consumes it. The record stays unconsumed and the token
// remains redeemable once the flag is lifted.
func TestStrictOfflineAccess_RefusesPreFlagTokenWithoutConsumingIt(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-strict-offline"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-strict-offline-secret"
	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	lax := testkit.NewProvider(t)
	rp := lax.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, lax, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid profile",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	issued := scenariokit.ExchangeCode(t, lax, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if issued.RefreshToken == "" {
		t.Fatalf("lax exchange minted no refresh_token: status=%d body=%v", issued.StatusCode, issued.Raw)
	}

	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	strictOP, err := op.New(
		op.WithIssuer(lax.Issuer),
		op.WithStore(lax.Store),
		op.WithKeyset(op.Keyset{lax.SigningKey}),
		op.WithCookieKeys(cookieKey),
		op.WithInteractionDriver(testkit.AutoConsentDriver{}),
		op.WithAuthenticators(testkit.SubjectAuthenticator{}),
		op.WithStrictOfflineAccess(),
	)
	if err != nil {
		t.Fatalf("strict op.New: %v", err)
	}
	strictSrv := httptest.NewServer(strictOP)
	t.Cleanup(strictSrv.Close)

	status, body := strictRefresh(t, strictSrv.URL, issued.RefreshToken, clientID, clientSecret)
	if status != http.StatusBadRequest || !strings.Contains(body, "invalid_grant") {
		t.Fatalf("strict refresh status=%d body=%s, want 400 invalid_grant", status, body)
	}
	rec, err := lax.Store.RefreshTokens().Find(context.Background(), issued.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.ConsumedAt != nil {
		t.Fatalf("strict-mode refusal consumed the refresh token at %v; it must be refused before consumption", rec.ConsumedAt)
	}
	status, body = strictRefresh(t, lax.Server.URL, issued.RefreshToken, clientID, clientSecret)
	if status != http.StatusOK {
		t.Errorf("refresh after lifting the flag status=%d body=%s, want 200", status, body)
	}
}

func strictRefresh(t *testing.T, base, refreshToken, clientID, clientSecret string) (int, string) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		base+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build refresh request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST refresh: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read refresh body: %v", err)
	}
	return resp.StatusCode, string(body)
}

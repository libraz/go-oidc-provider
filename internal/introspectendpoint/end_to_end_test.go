package introspectendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_DiscoveryAdvertisement confirms /introspect is advertised
// in discovery only when [feature.Introspect] is enabled, AND that the
// auth-methods list is published alongside the URL.
func TestEndToEnd_DiscoveryAdvertisement(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithFeature(feature.Introspect)),
	)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	doc := decodeJSON(t, resp)
	endpoint, _ := doc["introspection_endpoint"].(string)
	if !strings.HasSuffix(endpoint, "/oidc/introspect") {
		t.Errorf("introspection_endpoint=%q does not match /oidc/introspect suffix", endpoint)
	}
	methods, _ := doc["introspection_endpoint_auth_methods_supported"].([]any)
	if len(methods) == 0 {
		t.Errorf("introspection_endpoint_auth_methods_supported is empty: %v", doc)
	}
}

// TestEndToEnd_DiscoveryHidesEndpointWhenDisabled confirms /introspect is
// absent from the discovery document when the feature is off.
func TestEndToEnd_DiscoveryHidesEndpointWhenDisabled(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	doc := decodeJSON(t, resp)
	if got, ok := doc["introspection_endpoint"].(string); ok && got != "" {
		t.Errorf("introspection_endpoint=%q want absent when feature off", got)
	}
}

// TestEndToEnd_HappyPath_JWTAccessToken drives a full HTTP round trip
// against the introspection endpoint with a JWT access token.
func TestEndToEnd_HappyPath_JWTAccessToken(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.Introspect)),
	)
	const secret = "rp-introspect-secret" //nolint:gosec // G101: test fixture credential
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-introspect-jwt",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	signer := tokens.SigningKey{KeyID: tk.SigningKey.KeyID, Signer: tk.SigningKey.Signer}
	tok, err := tokens.SignAccessToken(signer, tokens.AccessTokenClaims{
		Issuer:    tk.Issuer,
		Subject:   "user-e2e",
		Audience:  []string{tk.Issuer},
		ClientID:  rp.ID,
		IssuedAt:  clock.now.Unix(),
		ExpiresAt: clock.now.Add(time.Hour).Unix(),
		JTI:       "at-e2e",
		Scope:     []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	form := url.Values{"token": {tok}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Errorf("active=%v want true; body=%v", body["active"], body)
	}
	if body["sub"] != "user-e2e" {
		t.Errorf("sub=%v want user-e2e", body["sub"])
	}
}

// TestEndToEnd_HappyPath_RefreshToken drives a full HTTP round trip
// against the introspection endpoint with an opaque refresh token.
func TestEndToEnd_HappyPath_RefreshToken(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.Introspect)),
	)
	const secret = "rp-introspect-rt-secret" //nolint:gosec // G101: test fixture credential
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-introspect-rt",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	rec := &store.RefreshToken{
		ID:        "rt-e2e-1",
		ClientID:  rp.ID,
		Subject:   "user-rt-e2e",
		Scope:     []string{"openid", "email"},
		ExpiresAt: clock.now.Add(24 * time.Hour),
		CreatedAt: clock.now,
	}
	if err := tk.Store.RefreshTokens().Save(context.Background(), rec); err != nil {
		t.Fatalf("RefreshTokens.Save: %v", err)
	}

	form := url.Values{"token": {rec.ID}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Errorf("active=%v want true; body=%v", body["active"], body)
	}
	if body["sub"] != "user-rt-e2e" {
		t.Errorf("sub=%v want user-rt-e2e", body["sub"])
	}
}

// TestEndToEnd_FeatureDisabledNoRoute confirms that without the
// [feature.Introspect] flag the route is absent (404) — discovery
// already gates the advertisement on the same flag, but the end-to-
// end test pins that the OP cannot quietly serve the endpoint while
// claiming it is disabled.
func TestEndToEnd_FeatureDisabledNoRoute(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	form := url.Values{"token": {"anything"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d want 404 when feature is off", resp.StatusCode)
	}
}

// TestEndToEnd_InactiveForExpiredJWT pins the inactive shape for a
// JWT past expiry — RFC 7662 §2.2 demands the response carry only
// "active": false in that case.
func TestEndToEnd_InactiveForExpiredJWT(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.Introspect)),
	)
	const secret = "rp-expired-secret" //nolint:gosec // G101: test fixture credential
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-introspect-expired",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	signer := tokens.SigningKey{KeyID: tk.SigningKey.KeyID, Signer: tk.SigningKey.Signer}
	tok, err := tokens.SignAccessToken(signer, tokens.AccessTokenClaims{
		Issuer:    tk.Issuer,
		Subject:   "user-expired",
		Audience:  []string{tk.Issuer},
		ClientID:  rp.ID,
		IssuedAt:  clock.now.Add(-2 * time.Hour).Unix(),
		ExpiresAt: clock.now.Add(-time.Hour).Unix(),
		JTI:       "at-expired",
		Scope:     []string{"openid"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	form := url.Values{"token": {tok}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if len(body) != 1 {
		t.Errorf("inactive response has %d members; want exactly 1; body=%v", len(body), body)
	}
	if active, _ := body["active"].(bool); active {
		t.Errorf("active=true in inactive response; body=%v", body)
	}
}

// TestEndToEnd_InactiveForUnknownRefreshToken pins the inactive
// shape for an opaque token the store does not recognise. The
// response shape MUST be identical to the expired-JWT case so an
// attacker cannot tell the two apart.
func TestEndToEnd_InactiveForUnknownRefreshToken(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithFeature(feature.Introspect)),
	)
	const secret = "rp-unknown-secret" //nolint:gosec // G101: test fixture credential
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-introspect-unknown",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{"token": {"never-issued"}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if len(body) != 1 {
		t.Errorf("inactive response has %d members; want exactly 1; body=%v", len(body), body)
	}
	if active, _ := body["active"].(bool); active {
		t.Errorf("active=true in inactive response; body=%v", body)
	}
}

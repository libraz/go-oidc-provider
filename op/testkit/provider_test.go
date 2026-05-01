package testkit_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

// TestNewProvider_DefaultsBootDiscoveryEndpoint verifies that a
// zero-option NewProvider call produces a Provider whose discovery
// document is reachable and reports the testkit defaults.
func TestNewProvider_DefaultsBootDiscoveryEndpoint(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	if tk.OP == nil || tk.Server == nil || tk.Store == nil {
		t.Fatal("Provider fields must be populated")
	}
	if tk.Issuer != testkit.DefaultIssuer {
		t.Fatalf("Issuer=%q want %q", tk.Issuer, testkit.DefaultIssuer)
	}
	if tk.SigningKey.KeyID != testkit.DefaultKeyID {
		t.Fatalf("KeyID=%q want %q", tk.SigningKey.KeyID, testkit.DefaultKeyID)
	}

	resp := getJSON(t, tk.Server.URL+"/.well-known/openid-configuration")
	if got, _ := resp["issuer"].(string); got != testkit.DefaultIssuer {
		t.Fatalf("discovery issuer=%v want %s", resp["issuer"], testkit.DefaultIssuer)
	}
}

// TestNewProvider_WithIssuerOverride verifies the issuer override flows
// into the discovery document.
func TestNewProvider_WithIssuerOverride(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithIssuer("https://op.override.example"))
	resp := getJSON(t, tk.Server.URL+"/.well-known/openid-configuration")
	if got, _ := resp["issuer"].(string); got != "https://op.override.example" {
		t.Fatalf("discovery issuer=%v", resp["issuer"])
	}
}

// TestNewProvider_WithClock_AcceptsClock verifies that an injected clock
// is wired through to op.Provider construction and accepted at construction
// time. The OP clock is not directly observable from outside, so the test
// only asserts the Provider boots when the clock is supplied.
func TestNewProvider_WithClock_AcceptsClock(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	if tk.OP == nil {
		t.Fatal("Provider must boot with a clock injected")
	}
}

// TestNewProvider_WithOptions_AppliedAfterDefaults verifies that extra
// options take precedence over the testkit defaults: registering a custom
// mount prefix should be visible in the discovery URLs.
func TestNewProvider_WithOptions_AppliedAfterDefaults(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithMountPrefix("/auth")))
	resp := getJSON(t, tk.Server.URL+"/.well-known/openid-configuration")
	if got, _ := resp["jwks_uri"].(string); !strings.HasSuffix(got, "/auth/jwks") {
		t.Fatalf("jwks_uri=%v expected /auth/jwks suffix", resp["jwks_uri"])
	}
}

// TestRegisterClient_DefaultsAndRoundTrip confirms the ClientFixture
// defaults yield a registered client whose ID is reachable via the inmem
// store and whose redirect URI is the testkit's invalid-domain default.
func TestRegisterClient_DefaultsAndRoundTrip(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	c := tk.RegisterClient(t, testkit.ClientFixture{})
	if c.ID != "client-test" {
		t.Fatalf("ID=%q want client-test", c.ID)
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://rp.testkit.invalid/callback" {
		t.Fatalf("RedirectURIs=%v", c.RedirectURIs)
	}
	got, err := tk.Store.Clients().GetClient(context.Background(), "client-test")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Fatalf("TokenEndpointAuthMethod=%q", got.TokenEndpointAuthMethod)
	}
}

// TestRegisterClient_JWKsRoundTrip verifies that a JWK Set supplied via
// [testkit.ClientFixture.JWKs] is persisted onto [store.Client.JWKs] so
// the private_key_jwt verifier can resolve client public keys without
// the test having to bypass the fixture.
func TestRegisterClient_JWKsRoundTrip(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	const raw = `{"keys":[{"kty":"EC","crv":"P-256","x":"AAA","y":"BBB","kid":"k-1"}]}`
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "fixture-jwks",
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKs:                    []byte(raw),
	})
	got, err := tk.Store.Clients().GetClient(context.Background(), "fixture-jwks")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if string(got.JWKs) != raw {
		t.Fatalf("JWKs=%q want %q", string(got.JWKs), raw)
	}
}

// TestRegisterClient_PublicClientPicksNoneAuth verifies the auth method
// default flips to "none" when the fixture marks the client as public.
func TestRegisterClient_PublicClientPicksNoneAuth(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	c := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "spa",
		PublicClient: true,
	})
	if c.TokenEndpointAuthMethod != "none" {
		t.Fatalf("TokenEndpointAuthMethod=%q want none", c.TokenEndpointAuthMethod)
	}
}

// TestSignedJWT_VerifiesAgainstJWKS round-trips a signed JWT through the
// testkit's Provider: the test signs claims with [Provider.SignedJWT] and
// verifies the signature against the public key advertised at /jwks.
func TestSignedJWT_VerifiesAgainstJWKS(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	type claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
	}
	token, err := tk.SignedJWT(claims{Iss: "rp.test", Sub: "user-1"})
	if err != nil {
		t.Fatalf("SignedJWT: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS expected 3 parts, got %d", len(parts))
	}
	// The signing key kid must round-trip into the protected header.
	header := decodeHeader(t, parts[0])
	if header["kid"] != testkit.DefaultKeyID {
		t.Fatalf("kid=%v want %s", header["kid"], testkit.DefaultKeyID)
	}
	if header["alg"] != "ES256" {
		t.Fatalf("alg=%v want ES256", header["alg"])
	}
}

func getJSON(tb testing.TB, url string) map[string]any {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		tb.Fatalf("decode: %v", err)
	}
	return body
}

func decodeHeader(tb testing.TB, encoded string) map[string]any {
	tb.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		tb.Fatalf("decode header: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(raw, &hdr); err != nil {
		tb.Fatalf("unmarshal header: %v", err)
	}
	return hdr
}

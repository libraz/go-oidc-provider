package scenarios_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// These two benchmarks exist to give any claim about token-endpoint
// throughput a denominator. They bracket the real range: the same
// endpoint, once with a hashed client secret in the path and once
// without.
//
// Measured on an Apple M5 Max, in-process over loopback:
//
//   - client_credentials, client_secret_basic — 89 ms per request,
//     81% of CPU in golang.org/x/crypto/argon2. The default secret
//     verifier is Argon2id at 64 MiB / t=3, and it runs on every
//     request, so a confidential client authenticating by secret
//     bounds the endpoint at roughly 11 requests per second per core.
//   - refresh_token, public client — 98 µs per request. No password
//     hashing anywhere in it; the time is syscalls, the scheduler and
//     GC, with ecdsa.Sign at 1.3%.
//
// The gap is three orders of magnitude and it is entirely the KDF.
// Anything proposing to make the token endpoint faster should be
// measured against the second number, because the first one is not
// measuring this library.
func BenchmarkTokenEndpointClientCredentials(b *testing.B) {
	const clientID = "rp-bench"
	const clientSecret = "rp-bench-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		b.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(b)
	tk.RegisterClient(b, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"api"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
	})

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}.Encode()
	client := tk.HTTPClient(nil)

	b.ResetTimer()
	for range b.N {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			tk.Server.URL+"/oidc/token", strings.NewReader(form))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, clientSecret)
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("status=%d", resp.StatusCode)
		}
	}
}

// BenchmarkTokenEndpointClientCredentialsHighEntropy is the same
// request as [BenchmarkTokenEndpointClientCredentials] against an OP
// running [op.WithHighEntropyClientSecrets], and it is what that
// option is for.
//
// Measured on the same host, in-process over loopback, -benchtime=2000x
// -count=3: 67–73 µs per request against 89 ms. The client_credentials
// path stops being a KDF benchmark — it now comes in under the
// refresh-token exchange below (102–105 µs), which is the right
// ordering, since that one rotates a token and writes to the store
// while this one only checks a credential and signs.
//
// Nothing about the security of the exchange changed. The secret is
// 256 bits from crypto/rand either way, and no attacker searches that
// space at any per-guess cost; what the 89 ms was buying was
// resistance to guessing a secret nobody has to guess.
//
// It also serves as the end-to-end proof that a client provisioned
// through [op.NewClientSecret] actually authenticates — the benchmark
// fails the run on any status other than 200, so a stored encoding the
// token endpoint could not read would surface here rather than as a
// number nobody checked.
func BenchmarkTokenEndpointClientCredentialsHighEntropy(b *testing.B) {
	const clientID = "rp-bench-highentropy"

	clientSecret, hash, err := op.NewClientSecret()
	if err != nil {
		b.Fatalf("NewClientSecret: %v", err)
	}
	tk := testkit.NewProvider(b, testkit.WithOptions(op.WithHighEntropyClientSecrets()))
	tk.RegisterClient(b, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"api"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
	})

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}.Encode()
	client := tk.HTTPClient(nil)

	b.ResetTimer()
	for range b.N {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			tk.Server.URL+"/oidc/token", strings.NewReader(form))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, clientSecret)
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("status=%d", resp.StatusCode)
		}
	}
}

func BenchmarkTokenEndpointRefreshPublicClient(b *testing.B) {
	const clientID = "rp-bench-public"
	const callback = "https://rp.example.com/cb"

	tk := testkit.NewProvider(b)
	tk.RegisterClient(b, testkit.ClientFixture{
		ID:                      clientID,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "offline_access"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(b, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		Scope:       "openid offline_access",
		PKCE:        pkce,
	})
	first := scenariokit.ExchangeCode(b, tk, scenariokit.ExchangeCodeRequest{
		Code:        flow.Code,
		RedirectURI: callback,
		Verifier:    pkce.Verifier,
		ClientID:    clientID,
		Extra:       url.Values{"client_id": {clientID}},
	})
	if first.StatusCode != http.StatusOK || first.RefreshToken == "" {
		b.Fatalf("setup: status=%d raw=%v", first.StatusCode, first.Raw)
	}

	client := tk.HTTPClient(nil)
	token := first.RefreshToken

	b.ResetTimer()
	for range b.N {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {token},
			"client_id":     {clientID},
		}.Encode()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			tk.Server.URL+"/oidc/token", strings.NewReader(form))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("status=%d body=%s", resp.StatusCode, body)
		}
		var env struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			b.Fatal(err)
		}
		if env.RefreshToken != "" {
			token = env.RefreshToken
		}
	}
}

package op_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const jwksURIClientID = "uri-client"

func TestPrivateKeyJWTClient_JWKSURI_ExclusiveWithJWKS(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		seed op.PrivateKeyJWTClient
		want string
	}{
		{"both", op.PrivateKeyJWTClient{
			ID: "both-client", JWKS: validStaticJWKS(t), JWKSURI: "https://rp.example.com/jwks.json",
			RedirectURIs: []string{"https://app.example.com/cb"},
		}, "both are set"},
		{"neither", op.PrivateKeyJWTClient{
			ID: "neither-client", RedirectURIs: []string{"https://app.example.com/cb"},
		}, "neither is set"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := op.New(append(validBaseOptsWithInmem(t), op.WithStaticClients(tc.seed))...)
			if err == nil {
				t.Fatal("op.New accepted the seed")
			}
			assertErrorMentions(t, err, tc.seed.ID, "JWKS", "JWKSURI", tc.want)
		})
	}
}

func TestPrivateKeyJWTClient_JWKSURI_MustBeHTTPS(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t), op.WithStaticClients(op.PrivateKeyJWTClient{
		ID: "http-client", JWKSURI: "http://rp.example.com/jwks.json",
		RedirectURIs: []string{"https://app.example.com/cb"},
	}))...)
	if err == nil {
		t.Fatal("op.New accepted an http jwks_uri")
	}
	assertErrorMentions(t, err, "http-client", "jwks_uri")
}

func TestPrivateKeyJWTClient_JWKSURI_AuthenticatesFromServedKey(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &key.PublicKey, KeyID: "served", Algorithm: "ES256", Use: "sig",
	}}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(srv.Close)

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithAllowPrivateNetwork(op.OutboundJWKS),
		op.WithJWKSHTTPTransport(srv.Client().Transport),
		op.WithStaticClients(op.PrivateKeyJWTClient{
			ID:           jwksURIClientID,
			JWKSURI:      srv.URL + "/jwks.json",
			RedirectURIs: []string{"https://rp.testkit.invalid/callback"},
			Scopes:       []string{"openid"},
		}),
	))

	post := func(signWith *ecdsa.PrivateKey) (int, string) {
		t.Helper()
		signer, err := josev4.NewSigner(
			josev4.SigningKey{Algorithm: josev4.ES256, Key: josev4.JSONWebKey{Key: signWith, KeyID: "served", Algorithm: "ES256", Use: "sig"}},
			(&josev4.SignerOptions{}).WithType("JWT"),
		)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		now := time.Now()
		payload, _ := json.Marshal(map[string]any{
			"iss": jwksURIClientID, "sub": jwksURIClientID, "aud": tk.Issuer + "/oidc/token",
			"jti": "jti-" + now.Format(time.RFC3339Nano), "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		})
		jws, err := signer.Sign(payload)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		assertion, err := jws.CompactSerialize()
		if err != nil {
			t.Fatalf("CompactSerialize: %v", err)
		}
		form := url.Values{
			"grant_type":            {"authorization_code"},
			"code":                  {"never-issued"},
			"redirect_uri":          {"https://rp.testkit.invalid/callback"},
			"client_assertion":      {assertion},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := tk.HTTPClient(nil).Do(req)
		if err != nil {
			t.Fatalf("POST /token: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// Authentication passed, so the fake code is what fails.
	if status, body := post(key); status != http.StatusBadRequest || !strings.Contains(body, "invalid_grant") {
		t.Fatalf("assertion signed by the served key: status=%d body=%s, want 400 invalid_grant", status, body)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if status, body := post(other); status != http.StatusUnauthorized || !strings.Contains(body, "invalid_client") {
		t.Fatalf("assertion signed by another key: status=%d body=%s, want 401 invalid_client", status, body)
	}
}

func TestPrivateKeyJWTClient_JWKSURI_DriftDetection(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	seed := func(uri string) op.PrivateKeyJWTClient {
		return op.PrivateKeyJWTClient{
			ID: jwksURIClientID, JWKSURI: uri,
			RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid"},
		}
	}
	sync := func(uri string) op.StaticClientSyncAction {
		t.Helper()
		res, err := op.SyncStaticClients(context.Background(), st, seed(uri))
		if err != nil {
			t.Fatalf("SyncStaticClients: %v", err)
		}
		return res[0].Action
	}
	if got := sync("https://rp.example.com/a.json"); got != op.StaticClientInserted {
		t.Fatalf("first sync = %q, want inserted", got)
	}
	stored, err := st.GetClient(context.Background(), jwksURIClientID)
	if err != nil || stored.JWKsURI != "https://rp.example.com/a.json" {
		t.Fatalf("stored JWKsURI = %q (err %v)", stored.JWKsURI, err)
	}
	if got := sync("https://rp.example.com/a.json"); got != op.StaticClientUnchanged {
		t.Fatalf("identical sync = %q, want unchanged", got)
	}
	if got := sync("https://rp.example.com/b.json"); got != op.StaticClientUpdated {
		t.Fatalf("changed JWKSURI sync = %q, want updated", got)
	}

	// Startup reconciliation refuses a changed jwks_uri and names the field.
	_, err = op.New(append(validBaseOptsWithStore(t, st), op.WithStaticClients(seed("https://rp.example.com/c.json")))...)
	if err == nil {
		t.Fatal("op.New accepted a seed whose JWKSURI differs from the stored record")
	}
	assertErrorMentions(t, err, "JWKsURI", "op.SyncStaticClients")
}

func TestStaticClient_ProfileRejection_NamesProfileAndSeedType(t *testing.T) {
	t.Parallel()

	fapi := []op.Option{op.WithProfile(profile.FAPI2Baseline), op.WithFeature(feature.DPoP)}
	cases := []struct {
		name string
		seed op.ClientSeed
		want []string
	}{
		{"client_secret_basic", op.ConfidentialClient{ //nolint:gosec // G101: test-fixture client secret, never a real credential.
			ID: "secret-client", Secret: "seeded-client-secret-0123456789-abcdef",
			RedirectURIs: []string{"https://app.example.com/cb"},
		}, []string{
			"client_secret_basic", "profile.FAPI2Baseline", "op.PrivateKeyJWTClient",
			"op.TLSClientAuthClient", "WithFeature(feature.MTLS)",
		}},
		{"tls_client_auth", op.ConfidentialClient{ //nolint:gosec // G101: test-fixture client secret, never a real credential.
			ID: "mtls-client", Secret: "seeded-client-secret-0123456789-abcdef",
			AuthMethod:   op.AuthTLSClientAuth,
			RedirectURIs: []string{"https://app.example.com/cb"},
		}, []string{"tls_client_auth", "op.TLSClientAuthClient", "op.SelfSignedTLSClientAuthClient", "WithFeature(feature.MTLS)"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := append(validBaseOptsWithInmem(t), fapi...)
			_, err := op.New(append(opts, op.WithStaticClients(tc.seed))...)
			if err == nil {
				t.Fatal("op.New accepted the seed")
			}
			assertErrorMentions(t, err, tc.want...)
		})
	}
}

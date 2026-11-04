//go:build example

// Example 36 puts an OP and a protected API into an application that
// already owns an http.ServeMux. The OP lives under a non-default mount
// prefix ("/identity") and is attached route by route; the API at
// /api/orders is guarded by op/rs.
//
// Run with the example build tag:
//
//	(cd examples/36-resource-server && GOWORK=off go run -tags example .)
//
// On start the process acts as its own machine client: it requests tokens
// from the OP, calls the API, prints the orders JSON, and prints the three
// refusals (no token, missing scope, wrong audience) with their status and
// WWW-Authenticate challenge. The server then keeps running for manual use.
//
// Manual verification:
//
//  1. Discovery lives under /.well-known whatever the prefix is, and the
//     other endpoints sit under /identity:
//
//     curl -s http://127.0.0.1:8080/.well-known/openid-configuration | jq .token_endpoint
//
//  2. The application's own routes keep working beside the OP:
//
//     curl -i http://127.0.0.1:8080/healthz
//     curl -i http://127.0.0.1:8080/no-such-page   # the app's 404, not the OP's
//
//  3. Request a token for the API (resource) with the orders:read scope:
//
//     TOKEN=$(curl -s -u orders-client:orders-demo-secret-4f9k-36-resource-server \
//     -d 'grant_type=client_credentials&scope=orders:read' \
//     --data-urlencode 'resource=http://127.0.0.1:8080/api' \
//     http://127.0.0.1:8080/identity/token | jq -r .access_token)
//     curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/orders
//
//     Expect 200 and the orders JSON.
//
//  4. No token: expect 401 and both a Bearer and a DPoP challenge in
//     WWW-Authenticate, neither carrying an error attribute:
//
//     curl -i http://127.0.0.1:8080/api/orders
//
//  5. Token without the scope (orders:write only): expect 403 and
//     error="insufficient_scope":
//
//     W=$(curl -s -u orders-client:orders-demo-secret-4f9k-36-resource-server \
//     -d 'grant_type=client_credentials&scope=orders:write' \
//     --data-urlencode 'resource=http://127.0.0.1:8080/api' \
//     http://127.0.0.1:8080/identity/token | jq -r .access_token)
//     curl -i -H "Authorization: Bearer $W" http://127.0.0.1:8080/api/orders
//
//  6. Token for another audience (no resource, so aud is the issuer):
//     expect 401 and error="invalid_token":
//
//     O=$(curl -s -u orders-client:orders-demo-secret-4f9k-36-resource-server \
//     -d 'grant_type=client_credentials&scope=orders:read' \
//     http://127.0.0.1:8080/identity/token | jq -r .access_token)
//     curl -i -H "Authorization: Bearer $O" http://127.0.0.1:8080/api/orders
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; production loads a persistent keyset from a vault / KMS.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress. The
//     verifier's AllowPrivateNetwork admits the loopback http issuer only for
//     this demo; a deployed resource server fetches https endpoints.
//   - Client secret: demo literal; issue and store a high-entropy secret.
package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/rs"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr = ":8080"
	issuer = "http://127.0.0.1" + opAddr
	// apiResource is the API's identifier: the RFC 8707 resource a client
	// asks for, and the audience the verifier requires.
	apiResource = issuer + "/api"

	clientID     = "orders-client"
	clientSecret = "orders-demo-secret-4f9k-36-resource-server"
)

func main() {
	keys := devkeys.MustEphemeral("resource-server-1")

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithMountPrefix("/identity"),
		op.WithGrants(grant.ClientCredentials),
		op.WithScope(op.PublicScope("orders:read", "Read orders")),
		op.WithScope(op.PublicScope("orders:write", "Change orders")),
		// Declares the API as a resource server: it is published as
		// protected-resource metadata, and the OP issues tokens for it.
		op.WithProtectedResources(op.ProtectedResource{
			Resource:        apiResource,
			ScopesSupported: []string{"orders:read", "orders:write"},
		}),
		op.WithStaticClients(op.ConfidentialClient{
			ID:         clientID,
			Secret:     clientSecret,
			AuthMethod: op.AuthClientSecretBasic,
			GrantTypes: []string{"client_credentials"},
			Scopes:     []string{"orders:read", "orders:write"},
			// Only resources listed here may be requested by this client.
			Resources: []string{apiResource},
		}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	verifier, err := rs.New(rs.Config{
		Issuer:   issuer,
		Audience: apiResource,
		// Loopback http issuer, demo only.
		AllowPrivateNetwork: true,
	})
	if err != nil {
		log.Fatalf("rs.New: %v", err)
	}

	// The application's router, with routes of its own.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "orders app\n")
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})

	// Mount the OP pattern by pattern. Routing "/" to the provider would
	// make it answer every unmatched path; registering only its own
	// patterns (discovery under /.well-known and the endpoints under
	// /identity) leaves unknown paths to the application's own 404.
	for _, pattern := range provider.Routes() {
		mux.Handle(pattern, provider)
	}

	requireOrdersRead := verifier.Middleware(rs.RequireScope("orders:read"))
	mux.Handle("/api/orders", requireOrdersRead(http.HandlerFunc(listOrders)))

	go demoClient()

	serve.Demo("resource-server example", opAddr, issuer)
	if err := serve.Listen(opAddr, mux, provider); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// listOrders runs only for a verified token carrying orders:read.
func listOrders(w http.ResponseWriter, r *http.Request) {
	tok, ok := rs.FromContext(r.Context())
	if !ok {
		http.Error(w, "no verified token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client": tok.ClientID,
		"scopes": tok.Scopes,
		"orders": []map[string]any{
			{"id": "o-1001", "total": 4200},
			{"id": "o-1002", "total": 1800},
		},
	})
}

// demoClient is the machine client: it fetches tokens, calls the API and
// prints the success and the three refusals.
func demoClient() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := serve.WaitForIssuer(ctx, issuer); err != nil {
		log.Printf("demo client: %v", err)
		return
	}

	good := mustToken(ctx, apiResource, "orders:read")
	log.Printf("GET /api/orders with a valid token:")
	show(ctx, good)

	log.Printf("GET /api/orders without a token:")
	show(ctx, "")

	log.Printf("GET /api/orders with a token lacking orders:read:")
	show(ctx, mustToken(ctx, apiResource, "orders:write"))

	log.Printf("GET /api/orders with a token for another audience (no resource):")
	show(ctx, mustToken(ctx, "", "orders:read"))
}

// mustToken requests a client_credentials token; an empty resource omits the
// parameter, which makes the OP address the token to itself.
func mustToken(ctx context.Context, resource, scope string) string {
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}
	if resource != "" {
		form.Set("resource", resource)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/identity/token", strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatalf("token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("token request: %v", err)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	decodeErr := json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()
	if decodeErr != nil || out.AccessToken == "" {
		log.Fatalf("token response (%d) has no access_token: %v", resp.StatusCode, decodeErr)
	}
	return out.AccessToken
}

// show calls the API (with a bearer token when given) and prints the status,
// the challenge and the body.
func show(ctx context.Context, token string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/api/orders", nil)
	if err != nil {
		log.Fatalf("api request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("api request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	log.Printf("  status: %d", resp.StatusCode)
	if c := resp.Header.Get("WWW-Authenticate"); c != "" {
		log.Printf("  WWW-Authenticate: %s", c)
	}
	if len(body) > 0 {
		log.Printf("  body: %s", strings.TrimSpace(string(body)))
	}
}

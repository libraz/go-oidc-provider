//go:build example

// Example 60 demonstrates the public/internal scope split. Scopes
// flagged Public appear in the discovery
// document's `scopes_supported` and on the consent prompt; scopes
// flagged internal are accepted at /authorize but never advertised
// and never rendered for user approval.
//
// Run with the example build tag:
//
//	(cd examples/60-scopes-public-private && GOWORK=off go run -tags example .)
//
// Then inspect:
//
//	curl http://127.0.0.1:8080/.well-known/openid-configuration | jq .scopes_supported
//
// The "openid", "profile", "billing.read", and the other OIDC
// standard scopes appear; the "internal:audit" scope is registered
// but absent from the discovery document. RPs that ask for
// "internal:audit" still receive it because the OP knows about it —
// the visibility flag only governs surface advertisement and consent
// rendering.
//
// The OIDC standard scopes (openid, profile, email, address, phone,
// offline_access) are auto-registered with built-in defaults, so this
// example only registers the scopes that need a custom title or that
// are not part of the standard set.
//
// To see the visibility flag on the consent screen rather than in
// discovery, sign in as "demo" / "demo-password" through an
// authorization request from the registered "demo-rp" client. The
// client is allowed all four scopes; the consent prompt renders only
// the public ones, and "internal:audit" is granted without ever being
// shown.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo username / password are hard-coded, and one [op.PrimaryPassword] step stands in for the whole login flow; production embedders enrol users through their own management plane and compose their own factors.
//   - Scope catalogue: persist alongside the embedder's other configuration rather than reseeding from source on every boot.
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/opkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr = ":8080"
	issuer = "http://127.0.0.1" + opAddr

	demoUsername = "demo"
	demoPassword = "demo-password"
	demoSubject  = "demo-user"
)

func main() {
	keys := devkeys.MustEphemeral("scopes-1")

	memStore := inmem.New()
	if err := seedUser(memStore); err != nil {
		log.Fatalf("seed demo user: %v", err)
	}

	// Public scopes appear in discovery and on the consent prompt.
	// Internal scopes are accepted at /authorize but never advertised.
	// "openid" and the other OIDC standard scopes are auto-registered
	// — embedders only call op.WithScope when they want to override
	// the built-in entry (typically to add a translated title).
	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(memStore),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// Admit "localhost" as a redirect_uri host alongside 127.0.0.1.
		op.WithAllowLocalhostLoopback(),
		// Consent is where the visibility flag does its second job, and
		// consent only happens after a login. One password step is the
		// smallest flow that gets an authorization request that far.
		op.WithLoginFlow(opkit.DefaultLoginFlow(memStore.UserPasswords())),
		op.WithScope(op.PublicScope("profile", "Access your basic profile")),
		op.WithScope(op.PublicScope("billing.read", "Read your billing data")),
		op.WithScope(op.InternalScope("internal:audit")),
		// The client is allowed the internal scope alongside the public
		// ones: visibility governs advertisement and consent rendering,
		// not whether a registration may carry the scope.
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-rp",
			RedirectURIs: []string{"http://localhost:5173/callback"},
			Scopes:       []string{"openid", "profile", "billing.read", "internal:audit"},
		}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Printf("scopes example listening on %s (issuer %s)", opAddr, issuer)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)
	if err := serve.Listen(opAddr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// seedUser materialises the demo subject the consent prompt is rendered
// for. In a real deployment the user record comes from the embedder's
// identity backend.
func seedUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}, demoUsername, hash)
	return nil
}

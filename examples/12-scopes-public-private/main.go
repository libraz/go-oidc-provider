//go:build example

// Example 12 demonstrates the public/internal scope split documented
// in ADR 0004. Scopes flagged Public appear in the discovery
// document's `scopes_supported` and on the consent prompt; scopes
// flagged internal are accepted at /authorize but never advertised
// and never rendered for user approval.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/12-scopes-public-private
//
// Then inspect:
//
//	curl http://localhost:8080/.well-known/openid-configuration | jq .scopes_supported
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
// PRODUCTION CAVEATS: this example uses ephemeral keys, a public HTTP
// listener, and an in-memory store. Production embedders read keys
// from a vault / KMS and persist scope catalogues alongside their
// other configuration.
package main

import (
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("scopes-1")

	// Public scopes appear in discovery and on the consent prompt.
	// Internal scopes are accepted at /authorize but never advertised.
	// "openid" and the other OIDC standard scopes are auto-registered
	// — embedders only call op.WithScope when they want to override
	// the built-in entry (typically to add a translated title).
	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
		op.WithScope(op.PublicScope("profile", "Access your basic profile")),
		op.WithScope(op.PublicScope("billing.read", "Read your billing data")),
		op.WithScope(op.InternalScope("internal:audit")),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("scopes example listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

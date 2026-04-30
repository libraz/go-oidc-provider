//go:build example

// Example minimal shows the smallest embedder boilerplate that
// constructs an OpenID Connect Provider, mounts it on an
// [http.ServeMux], and starts a listener.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/minimal
//
// The example uses ephemeral signing and cookie keys generated at
// startup so it can run without configuration. A production embedder
// reads the key material from a vault / KMS, persists records in a
// real backend, and registers at least one [op.Authenticator].
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
package main

import (
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("minimal-1")

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	// The Provider is a plain http.Handler; embedders mount it under
	// any prefix their router supports. The default mount path
	// (/oidc) is used here.
	mux := http.NewServeMux()
	mux.Handle("/", provider)

	serve.Demo("minimal OP", ":8080", "https://op.example.com")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

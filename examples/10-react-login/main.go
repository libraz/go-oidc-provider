//go:build example

// Example 10 demonstrates [op.WithReactUI]: the OP delegates the
// login / consent / logout screens to a SPA at the configured mount
// paths. The library still serves the OAuth + OIDC endpoints, but
// the interactive screens become the embedder's responsibility —
// the SPA reads the prompt state via the orchestrator's JSON API
// and POSTs submissions back through it.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/10-react-login
//
// The example expects a SPA build at ./web/dist (any HTML file
// works; the example only checks the directory exists). Pointing
// StaticDir at a non-existent path causes [op.New] to fail at
// construction so a misconfigured deployment surfaces immediately.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys and an
// in-memory store. WithReactUI is an experimental option — the
// JSON state surface is still stabilising, so a SPA written
// today may need adjustments when the orchestrator's prompt API
// hardens.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"
	"os"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		log.Fatalf("generate cookie key: %v", err)
	}

	const staticDir = "./web/dist"
	if _, err := os.Stat(staticDir); err != nil {
		log.Fatalf("StaticDir %s missing — build the SPA first or override with -spa-dir", staticDir)
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(op.Keyset{{KeyID: "react-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithReactUI(op.ReactUI{
			LoginMount:   "/login",
			ConsentMount: "/consent",
			LogoutMount:  "/logout",
			StaticDir:    staticDir,
		}),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("react-login example listening on :8080 (SPA at /login, /consent, /logout)")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

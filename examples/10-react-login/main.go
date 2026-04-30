//go:build example

// Example 10 demonstrates [op.WithSPAUI]: the OP delegates the
// login / consent / logout screens to a SPA at the configured mount
// paths. The seam is framework-neutral — the example wires up a
// React build, but Vue, Svelte, Angular, and any other SPA stack
// drop in the same way. The library serves the OAuth + OIDC
// endpoints AND the SPA shell + JSON state surface; embedders only
// supply the bundled assets.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/10-react-login
//
// The example expects a SPA build at ./web/dist. Pointing
// StaticDir at a non-existent path causes [op.New] to fail at
// construction so a misconfigured deployment surfaces immediately.
//
// SPA bundle requirements (Vite shown; other bundlers follow the
// same pattern):
//
//   - Build with `base: '/login/'` so HTML asset references resolve
//     under LoginMount.
//   - Place hashed assets under ./web/dist/assets/ — the OP serves
//     this subtree at LoginMount/assets/{path...}.
//   - Read the interaction UID from `location.pathname.split('/').pop()`
//     on shell load.
//   - Fetch prompt state from `/login/state/{uid}` (GET) and POST
//     submissions to the same path; the OP enforces CSRF via a
//     cookie + X-CSRF-Token header pair.
//
// Routes the OP mounts under [op.SPAUI.LoginMount] (here "/login"):
//
//	GET    /login/{uid}             → SPA shell (./web/dist/index.html)
//	GET    /login/{uid}/...         → 404 (only the literal {uid} path)
//	GET    /login/state/{uid}       → prompt JSON
//	POST   /login/state/{uid}       → submission
//	DELETE /login/state/{uid}       → cancel
//	GET    /login/assets/{path...}  → ./web/dist/assets/{path...}
//
// Static asset hardening: the OP refuses dotfiles (.env, .git/...),
// directory listings, and symlinks pointing outside StaticDir, so a
// committed secret or workspace symlink in ./web/dist cannot reach
// the wire.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - WithSPAUI: ConsentMount and LogoutMount are accepted at
//     validation time but their dedicated bundle routes are still
//     in flight; today the LoginMount bundle drives consent and
//     RP-Initiated Logout confirmation alongside the login screen.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	keys := devkeys.MustEphemeral("react-1")

	const staticDir = "./web/dist"
	if _, err := os.Stat(staticDir); err != nil {
		log.Fatalf("StaticDir %s missing — build the SPA first or override with -spa-dir", staticDir)
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKey(keys.CookieKey),
		op.WithSPAUI(op.SPAUI{
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
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

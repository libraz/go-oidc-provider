//go:build example

// Example 15 demonstrates locale negotiation for the OP's interaction
// prompt envelope. The OP picks the rendered language from a five-
// layer priority chain — PreferredLocaleStore → ui_locales request
// parameter → __Host-oidc_locale cookie → Accept-Language header →
// default locale — and stamps the result onto every prompt as
// `locale`, alongside `ui_locales_hint` (RP raw list) and
// `locales_available` (registered tags). SPAs read the envelope on
// /oidc/interaction/{uid} and set <html lang> / pick bundles.
//
// Run with the example build tag:
//
//	(cd examples/15-i18n-locale && GOWORK=off go run -tags example .)
//
// Startup runs an in-process self-verify probe that drives every row
// of the priority chain through an httptest server and prints a
// PASS / FAIL summary. The listener then comes up on :8080 so
// embedders can curl the discovery and authorize endpoints manually:
//
//	curl -s 'http://localhost:8080/.well-known/openid-configuration' \
//	  | jq .ui_locales_supported
//	# returns ["en","ja","fr"] — seed en + ja + the registered fr.
//
//	# Drive ui_locales=ja and read the resolved locale from the
//	# interaction prompt envelope:
//	curl -sL --cookie-jar j.txt --cookie j.txt \
//	  'http://localhost:8080/oidc/auth?client_id=demo-rp&response_type=code&redirect_uri=http://127.0.0.1:5173/callback&scope=openid&state=s&nonce=n&code_challenge=...&code_challenge_method=S256&ui_locales=ja' \
//	  | jq -r '.locale'
//
// The OP ships seed bundles for English (en) and Japanese (ja); this
// example registers a French bundle on top and switches the default
// to French. To override an existing message, register a bundle for
// the same locale — the later registration wins per key.
//
// The codebase is split by role across this directory:
//
//   - main.go  — entrypoint, package godoc, public listener.
//   - op.go    — OP-side wiring: buildProvider, the French
//     [op.LocaleBundle], and the seed end-user.
//   - probe.go — self-verify probe that drives every row of the
//     locale priority chain through an httptest server.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Self-verify probe: useful for the example, NOT for production.
//     Real deployments verify locale resolution through their CI
//     scenario suite (test/scenarios/i18n_test.go).
//   - Locale bundles: load from a versioned message catalogue
//     (JSON / TOML / Fluent) at startup so translators can ship
//     without recompiling the OP binary.
package main

import (
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/serve"
)

const (
	demoClientID    = "demo-rp"
	demoRedirectURI = "http://127.0.0.1:5173/callback"
	// pkceVerifier is the canonical PKCE verifier used by the
	// self-verify probe. The challenge is the SHA-256 base64url
	// digest of this string.
	pkceVerifier = "i18n-example-verifier-i18n-example-verifier-i18n-example"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	provider, err := buildProvider()
	if err != nil {
		return err
	}

	if err := selfVerifyLocaleChain(provider); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("registered locales: en, ja (seed) + fr (custom); default = fr")
	log.Println("self-verify probe PASSED — listening on :8080")
	log.Println("hit /.well-known/openid-configuration and read ui_locales_supported to verify discovery")
	return serve.Listen(":8080", mux)
}

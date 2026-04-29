//go:build example

// Example 16 demonstrates locale negotiation for the built-in
// consent / login UI. The OP picks the rendered language from a
// priority chain — ui_locales request parameter → existing locale
// cookie → Accept-Language header → default locale — and falls back
// to the registered default when no signal matches.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/16-i18n-locale
//
// Then drive the priority chain manually:
//
//	# Default locale (no signal): the OP renders consent in French
//	# because we set fr as default below.
//	curl -s 'http://localhost:8080/.well-known/openid-configuration' \
//	  | jq .ui_locales_supported
//
//	# Honour ui_locales=ja on the authorize URL — picks Japanese
//	# even when Accept-Language says es.
//	open 'http://localhost:8080/oidc/authorize?client_id=demo&response_type=code&redirect_uri=http://localhost:5173/callback&scope=openid&state=s&code_challenge=...&code_challenge_method=S256&ui_locales=ja'
//
// The OP ships seed bundles for English (en) and Japanese (ja); this
// example registers a French bundle on top and switches the default
// to French. To override an existing message, register a bundle for
// the same locale — the later registration wins.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys, an in-memory
// store, and a public HTTP listener. Real deployments load bundles
// from a versioned message catalogue (JSON / TOML / Fluent) at
// startup so translators can ship without recompiling the OP binary.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// frenchMessages is a minimal French bundle covering the consent and
// login surfaces. A real catalogue covers every key the seed bundles
// declare; missing keys fall back to the default locale's bundle.
var frenchMessages = map[string]string{
	"consent.title":          "Autoriser {client_name}",
	"consent.subtitle":       "{client_name} souhaite accéder à :",
	"consent.button.allow":   "Autoriser",
	"consent.button.deny":    "Annuler",
	"login.title":            "Connexion",
	"login.identifier.label": "E-mail ou nom d'utilisateur",
	"login.password.label":   "Mot de passe",
	"login.button.submit":    "Se connecter",
}

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		log.Fatalf("generate cookie key: %v", err)
	}

	french, err := op.LocaleBundleFromMap("fr", frenchMessages)
	if err != nil {
		log.Fatalf("LocaleBundleFromMap(fr): %v", err)
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(op.Keyset{{KeyID: "i18n-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		// Register the French bundle on top of the seed en / ja
		// bundles, then make French the fallback when no signal in
		// the priority chain matches a registered locale.
		op.WithLocale(french),
		op.WithDefaultLocale("fr"),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "demo",
				RedirectURIs: []string{"http://localhost:5173/callback"},
				Scopes:       []string{"openid", "profile"},
			},
		),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("i18n example listening on :8080")
	log.Println("registered locales: en, ja (seed) + fr (custom); default = fr")
	log.Println("hit /.well-known/openid-configuration and read ui_locales_supported to verify")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

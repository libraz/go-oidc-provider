//go:build example

// op.go — OP-side wiring for example 16-i18n-locale.
//
// This file holds the [op.New] construction, the French
// [op.LocaleBundle] layered on top of the seed en / ja bundles, and
// the seed end-user the [op.LoginFlow] needs so the password prompt
// can render during the self-verify probe. It is the half a real
// embedder lifts into production: bundle registration, default-locale
// selection, and client provisioning. Production embedders replace
// inmem.New with their own Storage and load bundles from a versioned
// message catalogue (JSON / TOML / Fluent) so translators ship
// without recompiling the OP binary.

package main

import (
	"context"
	"fmt"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// frenchMessages is a minimal French bundle covering the consent and
// login surfaces. The seed catalogue does not ship a French entry, so
// keys this map omits fall back to the configured default locale's
// bundle (here "fr" itself, then "en" through the resolver chain).
// For overrides on a seeded locale (en / ja) the bundle merges on top
// of the seed at key granularity — embedders only supply the keys
// they want to change.
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

func buildProvider() (*op.Provider, error) {
	keys := devkeys.MustEphemeral("i18n-1")

	french, err := op.LocaleBundleFromMap("fr", frenchMessages)
	if err != nil {
		return nil, fmt.Errorf("LocaleBundleFromMap(fr): %w", err)
	}

	st := inmem.New()
	if err := seedDemoUser(st); err != nil {
		return nil, fmt.Errorf("seed demo user: %w", err)
	}

	provider, err := op.New(
		op.WithIssuer("http://127.0.0.1:8080"),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		}),
		// JSONDriver is selected so the self-verify probe and any
		// SPA fetch see a JSON envelope. Embedders that ship a
		// server-rendered UI replace this with their own
		// [interaction.Driver]; the locale field rides on the
		// [interaction.Prompt] regardless of driver shape.
		op.WithInteractionDriver(interaction.JSONDriver{}),
		// Register the French bundle on top of the seed en / ja
		// bundles, then make French the fallback when no signal in
		// the priority chain matches a registered locale.
		op.WithLocale(french),
		op.WithDefaultLocale("fr"),
		op.WithStaticClients(
			op.PublicClient{
				ID:           demoClientID,
				RedirectURIs: []string{demoRedirectURI},
				Scopes:       []string{"openid", "profile"},
			},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("op.New: %w", err)
	}
	return provider, nil
}

// seedDemoUser plants a single demo user so the LoginFlow can render
// its password prompt during the self-verify probe. The password is
// never submitted; the probe terminates after reading the prompt
// envelope, but an empty user store would short-circuit the flow.
func seedDemoUser(st *inmem.Store) error {
	hash, err := op.HashPassword("demo")
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: "demo-user",
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}, "demo", hash)
	return nil
}

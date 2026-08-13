//go:build example

// Example 19 is the OP with no UI configuration at all. It sets no
// [op.WithInteractionDriver], no [op.WithChooserUI], no
// [op.WithConsentUI] and no [op.WithSPAUI], so every screen a user
// meets — the password prompt, the consent screen and the
// prompt=select_account account chooser — is rendered by the built-in
// [interaction.HTMLDriver] that [op.New] falls back to.
//
// That fallback is the library's headline claim: an OP that works from
// a browser without the embedder writing or wiring a single template.
// Every other UI example deliberately replaces part of it — 11 the
// consent screen, 12 the chooser template, 13 and 16 the whole driver,
// 10 and 17 the SPA — so this one exists to exercise what an embedder
// gets when they replace nothing.
//
// Run with the example build tag:
//
//	(cd examples/19-default-ui && GOWORK=off go run -tags example .)
//
// Two demo accounts are seeded with passwords so the chooser has more
// than one row to render: alice / alice-password and bob /
// bob-password.
//
// Browser walkthrough:
//
//  1. GET /oidc/auth?... → the built-in password page. Sign in as
//     alice; the consent screen follows, and approving it returns the
//     browser to the RP's redirect_uri with an authorization code.
//  2. GET /oidc/auth?...&prompt=select_account → the built-in chooser
//     page lists alice and renders a "use another account" link.
//  3. Follow that link → sign in as bob. The link carries the
//     OP-private marker the authorize endpoint matches against the
//     active session, so bob joins alice's chooser group instead of
//     replacing her. A bare prompt=login carries no such marker and
//     replaces the current account.
//  4. GET /oidc/auth?...&prompt=select_account → the chooser lists
//     both accounts, each pickable.
//
// Nothing above required a template, a stylesheet or a front-end
// build. An embedder who wants to own any of those screens starts from
// example 11, 12, 13 or 10 and replaces exactly the one they care
// about; the orchestrator-side flow is identical either way.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Login flow: one [op.PrimaryPassword] step over the demo user seed. Production embedders compose their own primary factor and MFA rules; the default UI is unaffected by that choice.
//   - User seed: the demo usernames / passwords are hard-coded; production embedders enrol users through their own management plane.
//   - Built-in pages: the bundled driver renders unstyled, script-free HTML. It is a working surface, not a branded one — an embedder shipping to end users replaces it rather than restyling it in place.
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
)

func main() {
	keys := devkeys.MustEphemeral("default-ui-1")

	memStore := inmem.New()
	if err := seedAccounts(memStore); err != nil {
		log.Fatalf("seed demo accounts: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(memStore),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// A primary factor is what turns a browser into an account the
		// chooser can list; without it /authorize has no interaction to
		// hand the user to.
		op.WithLoginFlow(opkit.DefaultLoginFlow(memStore.UserPasswords())),
		// No driver option appears anywhere in this call. That absence
		// is the example: op.New resolves the interaction driver to
		// interaction.HTMLDriver, and the login, consent and chooser
		// screens all render from the library's own markup.
		op.WithStaticClients(
			op.ConfidentialClient{
				ID:           "demo-rp",
				Secret:       "default-ui-demo-secret-rotate-me",
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{"http://127.0.0.1:8081/callback"},
				Scopes:       []string{"openid", "profile", "email"},
			},
		),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Printf("default-ui example listening on %s (issuer %s, built-in HTML screens, no driver configured)", opAddr, issuer)
	log.Println("flow: sign in as alice → /authorize?prompt=select_account → follow the add-account link as bob → /authorize?prompt=select_account")
	log.Println("demo users: alice/alice-password, bob/bob-password")
	if err := serve.Listen(opAddr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// seedAccounts materialises the two demo subjects the chooser
// enumerates. In a real deployment the user records come from the
// embedder's identity backend.
//
// The chooser reads SessionID / Subject / AuthTime off the live
// SessionStore at render time and resolves each row's display name from
// the "name" claim on the matching User record, falling back to the
// subject when the record carries none. The password credential is what
// lets a browser reach a session in the first place.
func seedAccounts(st *inmem.Store) error {
	for _, acct := range []struct {
		subject  string
		name     string
		password string
	}{
		{"alice", "Alice Example", "alice-password"},
		{"bob", "Bob Example", "bob-password"},
	} {
		hash, err := op.HashPassword(acct.password)
		if err != nil {
			return err
		}
		st.PutUserWithPassword(context.Background(), &store.User{
			Subject: acct.subject,
			Claims: map[string]any{
				"sub":   acct.subject,
				"name":  acct.name,
				"email": acct.subject + "@example.com",
			},
		}, acct.subject, hash)
	}
	return nil
}

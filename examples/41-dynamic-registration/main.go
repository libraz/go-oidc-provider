//go:build example

// Example 41-dynamic-registration demonstrates RFC 7591 / RFC 7592 /
// OpenID Connect Dynamic Client Registration end-to-end. The OP
// mounts the registration endpoint, issues an Initial Access Token
// (IAT) at startup, and the paired RP uses the IAT to register
// itself, then drives an Authorization Code + PKCE round-trip with
// the dynamically-issued client_id.
//
// Run with the example build tag:
//
//	(cd examples/41-dynamic-registration && GOWORK=off go run -tags example .)
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with WithDynamicRegistration enabled, IAT
//     issued at boot.
//   - :9090 — the RP from examples/internal/rpkit. It calls
//     rpkit.RegisterClient with the IAT, then mounts a CodeFlow
//     handler against the dynamically-issued client_id.
//
// Manual verification:
//
//  1. The startup log prints the dynamic client_id and the
//     registration_access_token (RAT). Both are demo-only output;
//     production code routes them through the secret manager.
//  2. Open http://127.0.0.1:9090/ — you see the RP landing page.
//  3. Click "Log in via the OP" — Authorization Code + PKCE round-
//     trip runs against the dynamically-registered client.
//  4. Sign in as username "demo" / password "demo" and approve.
//  5. /me renders the verified ID Token claims; the "aud" claim
//     matches the dynamic client_id.
//
// To exercise the management API (RFC 7592), use the RAT printed at
// startup. The registration endpoint sits under the default /oidc
// mount prefix, so the management URL is /oidc/register/{client_id} —
// the startup log prints it verbatim as registration_client_uri.
// Replace ${RAT} and ${CID} with the printed values:
//
//	curl -s "http://127.0.0.1:8080/oidc/register/${CID}" \
//	  -H "Authorization: Bearer ${RAT}" | jq
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - IAT bearer secret: returned by IssueInitialAccessToken exactly once with no recovery path. Production code MUST hand it through an out-of-band channel and MUST NOT log, audit-emit, or persist it anywhere besides the credential store. The example's startup log is DEMO-ONLY — remove it before adapting to production.
//   - RAT secret: same handling as the IAT — single emission, no recovery, not for log streams.
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr      = ":8080"
	rpAddr      = ":9090"
	issuer      = "http://127.0.0.1" + opAddr
	rpBase      = "http://127.0.0.1" + rpAddr
	redirectURI = rpBase + "/callback"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	keys := devkeys.MustEphemeral("dcr-1")

	st := inmem.New()
	if err := seedUser(st); err != nil {
		return err
	}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		op.WithDynamicRegistration(op.RegistrationOption{
			Open:    false,
			IATTTL:  1 * time.Hour,
			IATUses: 5,
			OnClientDeleted: func(_ context.Context, clientID string) error {
				log.Printf("registration deleted: %s — embedder cascade goes here", clientID)
				return nil
			},
		}),
	)
	if err != nil {
		return err
	}

	iat, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{
		Tag: "example-41-startup",
	})
	if err != nil {
		return err
	}

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)
	opErrCh := make(chan error, 1)
	go func() {
		log.Printf("OP listening on %s (issuer %s, dynamic_registration enabled)", opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := serve.WaitForIssuer(ctx, issuer); err != nil {
		return err
	}

	// Drive RFC 7591 §3.1: the RP self-registers with the IAT and
	// requests token_endpoint_auth_method=none so the issued client
	// is public (PKCE-only). Confidential clients omit the field
	// and consume the client_secret the OP returns.
	dcr, err := rpkit.RegisterClient(context.Background(), rpkit.DCROptions{
		Issuer:             issuer,
		InitialAccessToken: iat.Value,
		Metadata: map[string]any{
			"client_name":                "demo-rp (dynamic)",
			"redirect_uris":              []string{redirectURI},
			"grant_types":                []string{"authorization_code", "refresh_token"},
			"response_types":             []string{"code"},
			"token_endpoint_auth_method": "none",
			"scope":                      "openid profile",
		},
	})
	if err != nil {
		return err
	}
	log.Printf("dynamic registration OK: client_id=%s", dcr.ClientID)
	log.Printf("registration_access_token (RAT) [DEMO-ONLY, do not log in production]: %s", dcr.RegistrationAccessToken)
	log.Printf("registration_client_uri: %s", dcr.RegistrationClientURI)

	rp, err := rpkit.New(context.Background(), rpkit.Options{
		Issuer:      issuer,
		ClientID:    dcr.ClientID,
		RedirectURL: redirectURI,
		Scopes:      []string{"openid", "profile"},
	})
	if err != nil {
		return err
	}

	rpMux := http.NewServeMux()
	rpMux.Handle("/", rp.Handler())
	log.Printf("RP listening on %s — open %s/", rpAddr, rpBase)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)

	rpErrCh := make(chan error, 1)
	go func() { rpErrCh <- serve.Listen(rpAddr, rpMux) }()

	select {
	case err := <-opErrCh:
		return err
	case err := <-rpErrCh:
		return err
	}
}

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

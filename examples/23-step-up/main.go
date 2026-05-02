//go:build example

// Example 23 demonstrates RFC 9470 Authentication Context Class
// step-up. The RP first authenticates the user with password
// (basic ACR), then triggers a fresh /authorize call with
// acr_values=urn:mace:incommon:iap:silver. The OP's LoginFlow
// rule schedules a TOTP factor on top of the existing session,
// the user enters their authenticator code, and the RP receives
// a new ID Token whose "acr" claim is silver.
//
// Run with the example build tag, from this directory so
// ./web/static resolves:
//
//	cd examples/23-step-up && go run -tags example .
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with the SPA bundle at /login.
//   - :9090 — the RP, exposing /, /login, /step-up, /callback, /me.
//
// Operator setup:
//
//  1. Start the demo. The startup logs print the otpauth:// URI,
//     a base32 manual-entry secret, and a terminal QR code for
//     the seeded "demo" user.
//  2. Scan the QR (or paste the secret) into your authenticator
//     app of choice (Google Authenticator, 1Password, Authy,
//     Microsoft Authenticator, etc.). The authenticator now
//     produces 6-digit codes for "demo@example.com".
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — the RP landing page.
//  2. Click "Log in via the OP". The browser is redirected to
//     /authorize and the SPA password screen renders. Sign in as
//     "demo" / "demo".
//  3. Approve consent. The RP's /me page renders the verified
//     ID Token claims as JSON; "acr" reflects the password-only
//     authentication level the OP assigned.
//  4. Navigate to http://127.0.0.1:9090/step-up. The RP issues a
//     fresh /authorize with acr_values=urn:mace:incommon:iap:silver
//     and prompt=login. The OP schedules a TOTP step on top of
//     the existing session.
//  5. The SPA renders the password prompt again (prompt=login),
//     then the TOTP prompt. Enter the 6-digit code from your
//     authenticator app.
//  6. The browser ends back at /me with
//     "acr": "urn:mace:incommon:iap:silver" in the JSON.
//
// Restart the process whenever the round-trip stalls; ephemeral
// keys mean every restart invalidates every in-flight session,
// and the seeded TOTP secret regenerates on each restart, so
// re-scan the QR after each restart.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - TOTP encryption key: 32 bytes (AES-256-GCM at rest); supply
//     it from a vault / KMS so secrets survive process restart.
//   - ACR string: opaque to the library — the embedder picks the
//     value and is responsible for the meaning. Common conventions
//     are urn:mace:incommon:iap:silver / iap:bronze (InCommon
//     Federation) or AAL1 / AAL2 / AAL3 (NIST SP 800-63B).
//   - Demo seed: seedkit confirms TOTP at process start, skipping
//     the round-trip "user types code back" enrolment step a
//     production registration screen runs.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/seedkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/totpkit"
)

const (
	opAddr      = ":8080"
	rpAddr      = ":9090"
	issuer      = "http://127.0.0.1" + opAddr
	rpBase      = "http://127.0.0.1" + rpAddr
	clientID    = "demo-rp"
	redirectURI = rpBase + "/callback"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"
	demoEmail    = "demo@example.com"

	staticDir = "./web/static"
	silverACR = "urn:mace:incommon:iap:silver"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if _, err := os.Stat(staticDir); err != nil {
		return errors.New("StaticDir " + staticDir + " missing — run from the example directory so ./web/static resolves")
	}

	keys := devkeys.MustEphemeral("step-up-1")

	codec, err := totpkit.NewCodec(keys.TOTPKey)
	if err != nil {
		return err
	}

	st := inmem.New()

	ctx := context.Background()
	seed, err := seedkit.Seed(ctx, st, seedkit.SeedOptions{
		Subject:  demoSubject,
		Username: demoUsername,
		Password: demoPassword,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": demoEmail,
		},
		TOTP: &seedkit.SeedTOTP{
			Codec:   codec,
			Issuer:  "go-oidc-provider demo",
			Account: demoEmail,
			Now:     time.Now(), //nolint:forbidigo // example boots once at startup; embedders pass their own clock.
		},
	})
	if err != nil {
		return err
	}

	printSeedBanner(seed)

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		Rules: []op.Rule{
			op.RuleACR(silverACR, op.StepTOTP{
				Store:         st.TOTPs(),
				EncryptionKey: keys.TOTPKey,
			}),
		},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		op.WithSPAUI(op.SPAUI{
			LoginMount: "/login",
			StaticDir:  staticDir,
		}),
		op.WithStaticClients(op.PublicClient{
			ID:           clientID,
			RedirectURIs: []string{redirectURI},
			Scopes:       []string{"openid", "profile", "email"},
		}),
	)
	if err != nil {
		return err
	}

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)

	opErrCh := make(chan error, 1)
	go func() {
		log.Printf("OP listening on %s (issuer %s, SPA at /login)", opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := waitForIssuer(waitCtx, issuer); err != nil {
		return err
	}

	rp, err := rpkit.New(ctx, rpkit.Options{
		Issuer:      issuer,
		ClientID:    clientID,
		RedirectURL: redirectURI,
		Scopes:      []string{"openid", "profile", "email"},
	})
	if err != nil {
		return err
	}

	rpMux := http.NewServeMux()
	rpMux.Handle("/", rp.Handler())
	rpMux.HandleFunc("/step-up", rp.StepUpHandler(silverACR))

	log.Printf("RP listening on %s — open %s/", rpAddr, rpBase)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)
	log.Printf("step-up trigger: %s/step-up (acr_values=%s)", rpBase, silverACR)

	rpErrCh := make(chan error, 1)
	go func() { rpErrCh <- serve.Listen(rpAddr, rpMux) }()

	select {
	case err := <-opErrCh:
		return err
	case err := <-rpErrCh:
		return err
	}
}

// printSeedBanner emits the operator-facing TOTP enrolment block:
// the otpauth:// URI, the base32 manual-entry secret, and the
// terminal QR code the seedkit helper pre-rendered. The block is
// the only way the operator learns the secret, since the demo
// regenerates it on every restart.
func printSeedBanner(seed *seedkit.SeedResult) {
	if seed == nil {
		return
	}
	log.Println("──────────── TOTP enrolment for demo user ────────────")
	log.Printf("otpauth URI : %s", seed.OTPAuthURI)
	log.Printf("base32 seed : %s", seed.SecretBase32)
	log.Println("scan the QR below in an authenticator app:")
	log.Println("\n" + seed.QRTerm)
	log.Println("──────────────────────────────────────────────────────")
}

// waitForIssuer polls iss + "/.well-known/openid-configuration"
// until it returns 200 or ctx is cancelled. The example boots the
// OP and the RP in the same process, so the RP's OIDC discovery
// runs as soon as the OP listener is ready.
func waitForIssuer(ctx context.Context, iss string) error {
	url := iss + "/.well-known/openid-configuration"
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("waitForIssuer: timeout polling " + url)
		case <-tick.C:
		}
	}
}

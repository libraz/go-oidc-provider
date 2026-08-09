//go:build example

// Example 20 demonstrates a [op.LoginFlow] that always requires
// password + RFC 6238 TOTP at login. The Primary step is
// [op.PrimaryPassword]; a single rule with [op.RuleAlways] schedules
// [op.StepTOTP] as the second factor. The orchestrator drives both
// prompts in sequence; a successful TOTP submission emits the
// authorization code with amr=["mfa","otp","pwd"].
//
// This is the canonical "two-factor login" demo. Compare with
// examples/23-step-up, which keeps the password-only happy path and
// only schedules TOTP when the RP later asks for a higher ACR.
//
// Run with the example build tag, from this directory so the
// shared SPA bundle resolves:
//
//	cd examples/20-mfa-totp && GOWORK=off go run -tags example .
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with the SPA bundle at /login.
//   - :9090 — the RP, exposing /, /login, /callback, /me.
//
// Operator setup:
//
//  1. Start the demo. The startup logs print the otpauth:// URI,
//     a base32 manual-entry secret, and a terminal QR code for the
//     seeded "demo" user.
//  2. Scan the QR (or paste the secret) into your authenticator app
//     of choice (Google Authenticator, 1Password, Authy, Microsoft
//     Authenticator, etc.). The authenticator now produces 6-digit
//     codes for "demo@example.com".
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — the RP landing page.
//  2. Click "Log in via the OP". The browser is redirected to
//     /authorize and the SPA password screen renders. Sign in as
//     "demo" / "demo".
//  3. The SPA renders the TOTP prompt next; enter the 6-digit code
//     from your authenticator app.
//  4. Approve consent. The browser ends back at /me with the
//     verified ID Token claims as JSON, including
//     "amr": ["mfa","otp","pwd"].
//
// Restart the process whenever the round-trip stalls; ephemeral
// keys mean every restart invalidates every in-flight session, and
// the seeded TOTP secret regenerates on each restart, so re-scan
// the QR after each restart.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - TOTP encryption key: 32 bytes (AES-256-GCM at rest); supply
//     it from a vault / KMS so secrets survive process restart.
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
	"github.com/libraz/go-oidc-provider/examples/internal/opkit"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/seedkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/examples/internal/webui"
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

	staticDir = webui.StaticDir
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if _, err := os.Stat(staticDir); err != nil {
		return errors.New("StaticDir " + staticDir + " missing — run from the example directory so the shared SPA bundle resolves")
	}

	keys := devkeys.MustEphemeral("mfa-1")

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

	flow := opkit.WithTOTP(
		opkit.DefaultLoginFlow(st.UserPasswords()),
		st.TOTPs(),
		keys.TOTPKey,
	)

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
	if err := serve.WaitForIssuer(waitCtx, issuer); err != nil {
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

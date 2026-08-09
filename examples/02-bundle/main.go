//go:build example

// Example 02 is the comprehensive "this is what a real OP wiring
// looks like" example. It composes every option a typical embedder
// reaches for: a [op.LoginFlow] with password + always-on TOTP +
// after-N-failures captcha, typed client seeds, a scope catalogue,
// the JSON slog logger, and tightened token TTLs. It pairs the OP
// with an in-process RP so the wiring can be exercised end-to-end
// from a browser instead of read as a static file.
//
// Run with the example build tag, from this directory so the
// shared SPA bundle resolves:
//
//	cd examples/02-bundle && GOWORK=off go run -tags example .
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with the SPA bundle at /login.
//   - :9090 — the RP, exposing /, /login, /callback, /me.
//
// The seeded "demo" user clicks through the chain pwd → TOTP → /me.
// [op.WithFirstPartyClients] marks the demo RP as first-party, so the
// OP creates the consent grant on the user's behalf and skips the
// consent screen on every subsequent /authorize round-trip;
// [op.AuditConsentGrantedFirstParty] fires in the audit stream so SOC
// tooling can correlate the auto-grant with the code mint. Example 40
// ([examples/40-first-party-skip-consent]) covers the option in
// isolation. The captcha rule ([op.RuleAfterFailedAttempts]) is wired
// but only fires after five consecutive password failures in the same
// session, so the happy path does not see it.
//
// Operator setup:
//
//  1. Start the demo. The startup logs print the otpauth:// URI,
//     a base32 manual-entry secret, and a terminal QR code for the
//     seeded "demo" user.
//  2. Scan the QR (or paste the secret) into your authenticator app
//     of choice. The authenticator now produces 6-digit codes for
//     "demo@example.com".
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — the RP landing page.
//  2. Click "Log in via the OP". Sign in as "demo" / "demo".
//  3. Enter the 6-digit TOTP code from your authenticator app.
//  4. The browser ends back at /me with the verified ID Token
//     claims as JSON, including "amr": ["mfa","otp","pwd"].
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - TOTP encryption key: 32 bytes (AES-256-GCM at rest); supply
//     it from a vault / KMS so secrets survive process restart.
//   - Trusted proxies: configure WithTrustedProxies against the
//     deployment's actual edge.
//   - CaptchaVerifier: the "always passes" verifier is deliberately
//     vacuous — never ship that. Wire Cloudflare Turnstile /
//     hCaptcha / reCAPTCHA in production.
//   - WithFirstPartyClients auto-approves consent for the listed
//     clients; reserve it for clients the OP operator owns.
package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
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
	clientID    = "first-party-spa"
	redirectURI = rpBase + "/callback"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"
	demoEmail    = "demo@example.com"

	staticDir = webui.StaticDir
)

// alwaysOKCaptcha is the stub verifier paired with
// [op.RuleAfterFailedAttempts]. A production deployment swaps it for
// Cloudflare Turnstile / hCaptcha / reCAPTCHA.
type alwaysOKCaptcha struct{}

func (alwaysOKCaptcha) Verify(_ context.Context, _ op.CaptchaInput) error { return nil }

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if _, err := os.Stat(staticDir); err != nil {
		return errors.New("StaticDir " + staticDir + " missing — run from the example directory so the shared SPA bundle resolves")
	}

	keys := devkeys.MustEphemeral("bundle-1")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

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
			// Always require TOTP. Production deployments often
			// gate this on RuleACR or RuleRisk instead so users
			// without a TOTP enrolment can still sign in.
			op.RuleAlways(op.StepTOTP{
				Store:         st.TOTPs(),
				EncryptionKey: keys.TOTPKey,
			}),
			// Captcha after 5 failed attempts in this session.
			op.RuleAfterFailedAttempts(5, op.StepCaptcha{
				Verifier: alwaysOKCaptcha{},
			}),
		},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLogger(logger),
		op.WithLoginFlow(flow),
		op.WithSPAUI(op.SPAUI{
			LoginMount: "/login",
			StaticDir:  staticDir,
		}),
		op.WithStaticClients(
			op.PublicClient{
				ID:           clientID,
				RedirectURIs: []string{redirectURI},
				Scopes:       []string{"openid", "profile", "email"},
			},
			op.ConfidentialClient{
				ID:           "backend-service",
				Secret:       "bundle-demo-secret-rotate-me",
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{"https://backend.example.com/callback"},
				Scopes:       []string{"openid", "profile"},
			},
		),
		op.WithFirstPartyClients(clientID),
		// Token lifetimes. Defaults are 5m (access) / 30d (refresh);
		// the values below tighten access tokens and shorten refresh
		// tokens for a higher-touch session. WithProfile(FAPI2*) caps
		// access at 10m (FAPI 2.0 §3.1.9); refresh has no profile cap.
		// Refresh tokens are issued only when the granted scope
		// includes "openid" AND the client GrantTypes contains
		// "refresh_token" — see [op.ScopeNameOfflineAccess] godoc for
		// the rationale.
		op.WithAccessTokenTTL(2*time.Minute),
		op.WithRefreshTokenTTL(7*24*time.Hour),
		// OIDC standard scopes (openid, profile, email, address, phone,
		// offline_access) are auto-registered with library defaults; the
		// calls below override the built-in entries only to attach
		// custom titles for the consent prompt.
		op.WithScope(op.PublicScope("profile", "Access your profile")),
		op.WithScope(op.PublicScope("email", "Read your email address")),
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
	log.Printf("captcha trips after 5 wrong password attempts; the stub verifier always passes")

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

//go:build example

// Example 22 demonstrates [op.RuleAfterFailedAttempts]: a captcha
// challenge that gates the login chain only after the user has
// fumbled the password N times in a row. This is the canonical
// shape for "make brute-force expensive without inconveniencing
// honest users".
//
// Run with the example build tag, from this directory so
// ./web/static resolves:
//
//	cd examples/22-login-captcha && go run -tags example .
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with the SPA bundle at /login.
//   - :9090 — the RP, exposing /, /login, /callback, /me.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — the RP landing page.
//  2. Click "Log in via the OP" and submit username "demo" with a
//     wrong password three times in a row. The third failure
//     trips [op.RuleAfterFailedAttempts]; the orchestrator emits a
//     captcha prompt before re-prompting for the password.
//  3. Type any non-empty value into the captcha token field and
//     submit. The stub verifier accepts; the next prompt is the
//     password screen, this time with the correct password.
//  4. Approve consent. The browser ends back at /me.
//
// A production deployment swaps the stub verifier for an upstream
// provider (Cloudflare Turnstile / hCaptcha / reCAPTCHA) and the
// hand-rolled SPA snippet for the provider's client widget; the
// orchestrator-side wiring is unchanged.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - CaptchaVerifier: the "any non-empty token passes" verifier is deliberately vacuous — never ship that. A real verifier MUST (a) call the upstream provider with the embedder's secret and (b) collapse upstream rejection codes onto one generic error so the SPA cannot enumerate provider-side rejection reasons.
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
)

// stubCaptchaVerifier accepts any non-empty token. A real deployment
// wires Cloudflare Turnstile / hCaptcha / reCAPTCHA here.
type stubCaptchaVerifier struct{}

func (stubCaptchaVerifier) Verify(_ context.Context, in op.CaptchaInput) error {
	if in.Token == "" {
		return errors.New("captcha token missing")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if _, err := os.Stat(staticDir); err != nil {
		return errors.New("StaticDir " + staticDir + " missing — run from the example directory so ./web/static resolves")
	}

	keys := devkeys.MustEphemeral("captcha-1")

	st := inmem.New()

	ctx := context.Background()
	if _, err := seedkit.Seed(ctx, st, seedkit.SeedOptions{
		Subject:  demoSubject,
		Username: demoUsername,
		Password: demoPassword,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": demoEmail,
		},
	}); err != nil {
		return err
	}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		Rules: []op.Rule{
			// Inject a captcha after 3 consecutive password
			// failures. The orchestrator clears the counter on
			// the next successful attempt.
			op.RuleAfterFailedAttempts(3, op.StepCaptcha{
				Verifier: stubCaptchaVerifier{},
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

	log.Printf("RP listening on %s — open %s/", rpAddr, rpBase)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)
	log.Printf("captcha trips after 3 wrong password attempts; any non-empty token passes the stub")

	rpErrCh := make(chan error, 1)
	go func() { rpErrCh <- serve.Listen(rpAddr, rpMux) }()

	select {
	case err := <-opErrCh:
		return err
	case err := <-rpErrCh:
		return err
	}
}

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

//go:build example

// Example 28 covers the two second factors that need no hardware and
// no authenticator app: a code mailed to the user, and a printed sheet
// of recovery codes for when the mail does not arrive.
//
// They belong in one example because they are the same story told
// twice. Both are possession factors with a delivery channel the OP
// does not control, both are single-use, and the recovery sheet exists
// precisely because the mailed code has a failure mode — an inbox the
// user cannot reach — that no amount of retry logic fixes.
//
// # The flow
//
// Password is the primary step. A single [op.RuleAlways] schedules
// [op.StepEmailOTP], so every login asks for a mailed code. The
// recovery sheet is what happens when that code cannot arrive, and
// deciding that is not something a rule predicate can see: the only
// signal the OP gets is that the user keeps failing the factor it
// offered. An [op.Decider] reads the failure count and requires the
// recovery step instead, and the step is declared as a rule with a
// predicate that never fires so the Decider has a kind to name.
//
// What the library deliberately does not offer is a seam for the user
// to pick a different factor. The flow decides; the user's only input
// is whether they can answer what they were asked. A deployment that
// wants an explicit "I never got the e-mail" button builds it in its
// own UI and drives it through a Decider like this one.
//
// # What the library will not do for you
//
// **Delivery is yours.** [op.EmailDelivery] has one method and the
// library never opens an SMTP connection. This example prints the code
// to the log, which is the correct shape for a demo and a
// credential-disclosure bug in anything else. A real implementation
// hands the code to a provider and returns its error verbatim; the
// orchestrator collapses that into a generic "delivery failed" prompt
// so a failing provider cannot become a user-enumeration oracle.
//
// **The destination address is checked against the bound claim.** The
// step matches the submitted address against the subject's stored
// "email" claim in constant time, and only dispatches on a match. That
// is why [op.StepEmailOTP] needs a [store.UserStore]: without it the
// prompt would mail a code to whatever the caller typed.
//
// **Enrolment is yours too, and recovery codes need it.** A recovery
// code the user has never seen is not a factor. [op/recoverykit]
// mints a batch; this example prints one at startup because there is
// no account page to print it on. A real deployment issues the sheet
// from an authenticated account screen, shows it exactly once, and
// never logs it.
//
// # Running
//
//	cd examples/28-email-otp-recovery && go run -tags example .
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with the SPA bundle at /login.
//   - :9090 — the RP, exposing /, /login, /callback, /me.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ and click "Log in via the OP".
//  2. Sign in as demo / demo.
//  3. The SPA asks for an e-mail address. Enter demo@example.com —
//     the address bound to the seeded user. Anything else looks
//     identical and mails nothing.
//  4. Read the 6-digit code from the OP's log output and submit it.
//  5. Approve consent; /me shows the ID Token with
//     "amr": ["mfa","otp","pwd"].
//
// To exercise the recovery path instead, choose the recovery-code
// prompt at step 3 and paste one of the codes printed in the startup
// banner. Each code works once.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite. Both the OTP records and the recovery batch must survive a restart, or every enrolled sheet is void.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Delivery: the logging sender is a demo. Printing a one-time code to stdout is a credential disclosure anywhere else.
//   - Recovery sheet: printed to the log here because the example has no account page. Show it once, on an authenticated screen, and never persist the plaintext.
//   - SendLatencyPad: left at the library default. It is the timing-oracle defence that makes the matched and unmatched address branches indistinguishable; do not disable it outside tests.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/seedkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/recoverykit"
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

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if _, err := os.Stat(staticDir); err != nil {
		return errors.New("StaticDir " + staticDir + " missing — run from the example directory so ./web/static resolves")
	}

	keys := devkeys.MustEphemeral("email-otp-recovery-1")
	st := inmem.New()
	ctx := context.Background()

	if _, err := seedkit.Seed(ctx, st, seedkit.SeedOptions{
		Subject:  demoSubject,
		Username: demoUsername,
		Password: demoPassword,
		Claims: map[string]any{
			"name": "Demo User",
			// StepEmailOTP resolves the destination from this claim
			// and refuses to mail anywhere else.
			"email": demoEmail,
		},
	}); err != nil {
		return err
	}

	// Enrolment. A recovery batch the user has never been shown is not
	// a factor, so the example mints one and prints it — the one place
	// a plaintext recovery code is allowed to appear.
	batch, err := recoverykit.Replace(ctx, st.RecoveryCodes(), demoSubject)
	if err != nil {
		return err
	}
	printRecoveryBanner(batch.Codes)

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		Rules: []op.Rule{
			// The recovery step is declared here even though no
			// condition in this table selects it. A Decider requires a
			// step by kind and can only name one the flow declared, so
			// a step the Decider alone decides to run still has to
			// appear — with a predicate that never fires. That is not a
			// workaround: it is what keeps every factor this login can
			// demand readable off the LoginFlow.
			op.RuleWhen(
				func(op.LoginContext) bool { return false },
				op.StepRecoveryCode{Store: st.RecoveryCodes()},
			),
			op.RuleAlways(op.StepEmailOTP{
				Store:  st.EmailOTPs(),
				Sender: loggingSender{},
				Users:  st.Users(),
			}),
		},
		// The fallback is a policy decision, not a menu item. There is
		// no seam for "the user says the mail never arrived" — the
		// flow decides which factor runs, and the user's only signal is
		// that they keep failing the one they were given. Here two
		// failed codes is taken as "the inbox is unreachable" and the
		// recovery sheet is required instead. A deployment that wants
		// the user to choose explicitly builds that choice into its own
		// UI and drives it through a Decider like this one.
		Decider: fallbackToRecovery{after: 2},
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
	log.Printf("demo user: username=%q password=%q email=%q", demoUsername, demoPassword, demoEmail)

	rpErrCh := make(chan error, 1)
	go func() { rpErrCh <- serve.Listen(rpAddr, rpMux) }()

	select {
	case err := <-opErrCh:
		return err
	case err := <-rpErrCh:
		return err
	}
}

// fallbackToRecovery swaps the mailed code for the recovery sheet once
// the login has burned through `after` failed attempts. The
// orchestrator consults the Decider before the rule table on every
// pass, so returning Require short-circuits the RuleAlways that would
// otherwise keep asking for a code the user cannot receive.
//
// Returning Pass is the ordinary answer: it hands the decision back to
// the rules.
//
// The third answer is the one that is easy to leave out. Requiring a
// step that has already completed is not an error — the orchestrator
// declines to run it twice and falls through to the rules, where
// RuleAlways would demand the mailed code all over again. The failure
// count that opened the fallback never goes back down, so this Decider
// is asked the same question on every later pass and has to end the
// login itself. Allow does that: the password already ran as Primary,
// so a recovery code accepted on top of it is the second factor, and
// there is nothing further to ask for.
type fallbackToRecovery struct {
	after int
}

func (f fallbackToRecovery) Decide(_ context.Context, lc op.LoginContext) op.Decision { //nolint:ireturn // op.Decision is a sealed sum type; returning it is the Decider contract.
	if lc.FailedAttempts < f.after {
		return op.Pass{}
	}
	if slices.Contains(lc.CompletedSteps, op.StepKindRecoveryCode) {
		return op.Allow{}
	}
	return op.Require{Kind: op.StepKindRecoveryCode}
}

// loggingSender is the demo [op.EmailDelivery]: it prints the code
// where the operator can read it. A real implementation calls an
// e-mail provider and returns whatever the provider returned — the
// orchestrator collapses every failure onto one generic prompt, so
// forwarding provider detail here cannot leak it to the user, but it
// also cannot help the user, and a code on stdout is a credential in
// the log.
type loggingSender struct{}

func (loggingSender) Send(_ context.Context, address, code string) error {
	log.Printf("──── e-mail OTP ────  to=%s  code=%s", address, code)
	return nil
}

// printRecoveryBanner surfaces the display-once recovery sheet. The
// example has no account page to render it on, which is the only
// reason this exists; a deployment shows the sheet on an
// authenticated screen and never writes it anywhere.
func printRecoveryBanner(codes []string) {
	log.Println("──────────── recovery codes for the demo user ────────────")
	log.Println("each code works once; regenerating the batch voids all of them")
	for _, c := range codes {
		log.Printf("  %s", c)
	}
	log.Println("──────────────────────────────────────────────────────────")
}

// waitForIssuer polls the discovery document until it answers 200 or
// ctx is cancelled. The OP and the RP boot in one process, so the RP's
// discovery call runs as soon as the OP listener is ready.
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

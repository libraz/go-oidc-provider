//go:build example

// Example 21 demonstrates [op.RiskAssessor]-driven step-up. A
// [op.RuleRisk] schedules a follow-on factor when the score crosses
// the threshold the rule names; lower scores fall through to the
// password-only happy path.
//
// The browser-friendly variant grades on [op.RiskInput.ACRValues],
// so a fixed Chrome User-Agent can exercise all three paths via
// three landing-page buttons that each request a different
// acr_values string. Real assessors look at IP geolocation, device
// fingerprint, velocity counters, and similar signals.
//
// Run with the example build tag, from this directory so
// ./web/static resolves:
//
//	cd examples/21-risk-based-mfa && go run -tags example .
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with the SPA bundle at /login.
//   - :9090 — the RP, exposing /, /login-low, /login-medium,
//     /login-high, /callback, /me.
//
// Manual verification (open http://127.0.0.1:9090/):
//
//  1. "Log in (low risk)" — acr_values is empty; assessor returns
//     [op.RiskScoreLow]; password-only happy path.
//  2. "Log in (medium risk)" — acr_values=demo:medium; assessor
//     returns [op.RiskScoreMedium]; password + captcha.
//  3. "Log in (high risk)" — acr_values=demo:high; assessor returns
//     [op.RiskScoreHigh]; password + captcha + TOTP. Both rules
//     match on High because each [op.RuleRisk] fires whenever the
//     score crosses its threshold; the SPA prompts run in rule
//     order (TOTP first, then captcha).
//
// The "demo:medium" / "demo:high" strings are illustrative — pick
// real ACR values appropriate for your assurance framework
// (urn:mace:incommon:iap:bronze / silver / gold, AAL1 / AAL2 / AAL3,
// etc.). The assessor is library-agnostic: any string the RP can
// request will reach it.
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
//   - Risk assessor: ACR-string heuristic is illustrative — real
//     assessors call fraud-detection services (Cloudflare Bot
//     Management, Castle, Sift, Stripe Radar) and aggregate
//     multiple signals. Do not gate authentication on a single
//     RP-supplied parameter in production.
//   - Demo seed: seedkit confirms TOTP at process start, skipping
//     the round-trip "user types code back" enrolment step a
//     production registration screen runs.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/opkit"
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

	staticDir   = "./web/static"
	mediumACR   = "demo:medium"
	highACR     = "demo:high"
	lowRiskHint = "low risk"
)

// acrRiskAssessor maps the original /authorize request's acr_values
// to a risk score. The RP's three landing-page buttons request the
// three values; the assessor turns each request into a different
// challenge, demonstrating the [op.RiskOutcome.Score] seam without
// depending on the inbound User-Agent string.
type acrRiskAssessor struct{}

func (acrRiskAssessor) Assess(_ context.Context, in op.RiskInput) (op.RiskOutcome, error) {
	switch {
	case slices.Contains(in.ACRValues, highACR):
		return op.RiskOutcome{
			Decision: op.RiskRequire,
			Reason:   "demo.acr=" + highACR,
		}, nil
	case slices.Contains(in.ACRValues, mediumACR):
		return op.RiskOutcome{
			Decision: op.RiskRequire,
			Score:    op.RiskScoreMedium,
			Reason:   "demo.acr=" + mediumACR,
		}, nil
	default:
		return op.RiskOutcome{Decision: op.RiskAllow}, nil
	}
}

// stubCaptchaVerifier accepts any non-empty token. A production
// deployment wires Cloudflare Turnstile / hCaptcha / reCAPTCHA here.
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

	keys := devkeys.MustEphemeral("risk-1")

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

	flow := opkit.DefaultLoginFlow(st.UserPasswords())
	flow.Risk = acrRiskAssessor{}
	flow = opkit.WithMFARules(flow,
		// TOTP fires when the assessor scores RiskScoreHigh or above.
		// Rule order matters: TOTP wins on High because it appears
		// first.
		op.RuleRisk(op.RiskScoreHigh, op.StepTOTP{
			Store:         st.TOTPs(),
			EncryptionKey: keys.TOTPKey,
		}),
		// Captcha fires from RiskScoreMedium upward. The Medium
		// branch hits this rule because TOTP gates on High.
		op.RuleRisk(op.RiskScoreMedium, op.StepCaptcha{
			Verifier: stubCaptchaVerifier{},
		}),
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
	rpMux.HandleFunc("/", landingHandler())
	rpMux.HandleFunc("/login-low", rp.StepUpHandler(""))
	rpMux.HandleFunc("/login-medium", rp.StepUpHandler(mediumACR))
	rpMux.HandleFunc("/login-high", rp.StepUpHandler(highACR))
	// Delegate the rest (login / callback / me / static) to rpkit.
	rpMux.Handle("/login", rp.Handler())
	rpMux.Handle("/callback", rp.Handler())
	rpMux.Handle("/me", rp.Handler())

	log.Printf("RP listening on %s — open %s/", rpAddr, rpBase)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)
	log.Printf("paths: /login-low (password) | /login-medium (+captcha) | /login-high (+captcha +TOTP)")

	rpErrCh := make(chan error, 1)
	go func() { rpErrCh <- serve.Listen(rpAddr, rpMux) }()

	select {
	case err := <-opErrCh:
		return err
	case err := <-rpErrCh:
		return err
	}
}

// landingHandler renders three buttons — one per risk path. The
// buttons trigger /login-low | /login-medium | /login-high, which
// rpkit's StepUpHandler turns into /authorize calls with the
// corresponding acr_values value.
func landingHandler() http.HandlerFunc {
	const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>risk-based MFA demo</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 40em; margin: 4em auto; padding: 0 1em; }
h1 { font-size: 1.4em; }
ul { padding: 0; list-style: none; }
li { margin: .8em 0; }
a.btn { display: inline-block; padding: .6em 1em; background: #2563eb; color: #fff; text-decoration: none; border-radius: 4px; }
a.btn.medium { background: #d97706; }
a.btn.high { background: #b91c1c; }
small { color: #6b7280; }
</style></head>
<body>
<h1>Risk-based step-up demo</h1>
<p>Each button issues an OAuth /authorize with a different <code>acr_values</code> string. The OP's RiskAssessor maps the value to a risk score, which decides whether the LoginFlow inserts a captcha or TOTP step.</p>
<ul>
<li><a class="btn" href="/login-low">Log in (low risk — password only)</a></li>
<li><a class="btn medium" href="/login-medium">Log in (medium risk — captcha + password)</a></li>
<li><a class="btn high" href="/login-high">Log in (high risk — TOTP + captcha + password)</a></li>
</ul>
<p><a href="/me">Show last verified ID Token claims</a></p>
<small>Issuer: ` + issuer + ` · Client: ` + clientID + `</small>
</body></html>`
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, page)
	}
}

// printSeedBanner emits the operator-facing TOTP enrolment block:
// the otpauth:// URI, the base32 manual-entry secret, and the
// terminal QR code the seedkit helper pre-rendered.
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

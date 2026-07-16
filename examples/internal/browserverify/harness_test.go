//go:build browserverify

// Package browserverify drives the happy-path login round-trip of a
// browser-oriented example with a headless Chrome. It is the automated
// equivalent of the manual "Browser walkthrough" block each example
// carries in its header doc: boot the example, sign in, approve
// consent, and assert the Relying Party landed on /me with the claims
// the example promises.
//
// One test file per example (example_NN_<slug>_test.go) so `ls` lines up
// with the examples/ directory and a missing browser test is visible at a
// glance. Examples that have a browser login but are not migrated yet
// carry a t.Skip stub with the reason, so the gap shows up in the test
// output too. API-only / infrastructure examples (client_credentials,
// device_code, CIBA, token-exchange, metrics, …) are deliberately absent:
// they have no browser flow to drive.
//
// Run it explicitly (it is gated behind the "browserverify" build tag
// and needs a Chrome/Chromium binary on the host):
//
//	go test -tags browserverify ./...
//
// If no Chrome binary is found the tests skip rather than fail, so a
// developer without a browser installed still gets a green tree; CI
// installs Chrome and exercises the real path.
//
// Every example binds OP :8080 and RP :9090, so the tests must NOT run
// in parallel: they would fight over the ports. Go runs the package's
// tests sequentially unless they call t.Parallel, so no test here does.
package browserverify

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

const (
	defaultRPBase   = "http://127.0.0.1:9090"
	defaultOPIssuer = "http://127.0.0.1:8080"
)

// BROWSERVERIFY_REQUIRED turns this normally developer-friendly harness into
// a release gate. In that mode a missing browser and a run with zero actual
// browser cases are failures rather than successful skips.
const browserVerifyRequiredEnv = "BROWSERVERIFY_REQUIRED"

var executedBrowserCases atomic.Int64

func browserVerifyRequired() bool { return os.Getenv(browserVerifyRequiredEnv) == "1" }

func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 && browserVerifyRequired() && executedBrowserCases.Load() == 0 {
		fmt.Fprintln(os.Stderr, "browserverify: required mode executed zero browser cases")
		code = 1
	}
	os.Exit(code)
}

type exampleSpec struct {
	dir      string
	username string
	password string
	wantSub  string
	// wantClaims are example-specific substrings that must appear in the
	// /me JSON beyond the common iss/sub — the feature the example exists
	// to demonstrate. Empty means iss/sub fully characterise the round-trip.
	wantClaims []string
	// spa selects the SPA driver (op.WithSPAUI examples) instead of the
	// default HTML interaction driver. The SPA re-renders prompts in place
	// over a JSON contract rather than navigating between server-rendered
	// pages, so its login/consent selectors differ.
	spa bool
	// totp marks an example whose login requires an RFC 6238 TOTP second
	// factor. The harness scrapes the base32 secret the example prints at
	// startup and computes the live code. Implies spa (every TOTP example
	// here uses the SPA driver). The SPA loop auto-detects captcha and
	// consent prompts, so no separate flags are needed for those.
	totp bool
	// loginLink overrides the RP landing-page selector used to start the
	// flow. Defaults to a[href="/login"]; risk-based-mfa exposes
	// per-risk links such as a[href="/login-high"].
	loginLink string
	// failPassword is how many wrong-password submissions the driver makes
	// before the correct one, to trip an after-N-failures captcha rule
	// (login-captcha). Zero means log in correctly on the first try.
	failPassword int
	// stepUp selects the two-leg step-up driver: an initial password login
	// followed by a second /step-up authorization that re-authenticates and
	// adds a TOTP factor for a higher ACR. Implies spa + totp.
	stepUp bool
}

// runRoundTrip is the whole body of a default-HTML-driver example test:
// skip if no browser, boot the example, drive login → consent → /me, and
// assert the issuer, subject, and any example-specific claims landed.
func runRoundTrip(t *testing.T, spec exampleSpec) {
	t.Helper()

	chrome := requireChrome(t)
	executedBrowserCases.Add(1)

	stop, logPath := startExample(t, spec.dir)
	defer stop()

	waitForReady(t, defaultRPBase+"/")

	// The TOTP secret is printed in the startup banner, already flushed by
	// the time the OP answers readiness.
	var totpSecret string
	if spec.totp {
		totpSecret = scrapeTOTPSecret(t, logPath)
	}

	// Driving a real Chrome occasionally drops a CDP navigation event, so
	// retry the round-trip once against the same running example. A genuine
	// regression fails both attempts; a one-off browser hiccup is absorbed,
	// keeping the gate deterministic.
	drive := func() (string, error) { return driveLogin(chrome, spec) }
	switch {
	case spec.stepUp:
		drive = func() (string, error) { return driveStepUp(chrome, spec, totpSecret) }
	case spec.spa:
		drive = func() (string, error) { return driveSPALogin(chrome, spec, totpSecret) }
	}

	var body string
	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		body, err = drive()
		if err == nil {
			break
		}
		t.Logf("attempt %d/2 failed: %v", attempt, err)
	}
	if err != nil {
		t.Fatalf("browser round-trip: %v", err)
	}

	if !strings.Contains(body, `"iss": "`+defaultOPIssuer+`"`) {
		t.Fatalf("/me body missing expected iss %q; got:\n%s", defaultOPIssuer, body)
	}
	if !strings.Contains(body, `"sub": "`+spec.wantSub+`"`) {
		t.Fatalf("/me body missing expected sub %q; got:\n%s", spec.wantSub, body)
	}
	for _, want := range spec.wantClaims {
		if !strings.Contains(body, want) {
			t.Fatalf("/me body missing expected claim %q; got:\n%s", want, body)
		}
	}
	t.Logf("round-trip OK: /me rendered iss=%s sub=%s claims=%v", defaultOPIssuer, spec.wantSub, spec.wantClaims)
}

func requireChrome(t *testing.T) string {
	t.Helper()
	if chrome := findChrome(); chrome != "" {
		return chrome
	}
	if browserVerifyRequired() {
		t.Fatalf("no Chrome/Chromium binary found (set CHROME_BIN to override); required browser verification cannot run")
	}
	t.Skip("no Chrome/Chromium binary found (set CHROME_BIN to override); skipping browser round-trip")
	return "" // unreachable; keeps the compiler aware that t.Skip returns.
}

// startExample compiles the example under the "example" build tag and
// runs the resulting single binary so teardown is a clean process kill
// (go run would fork a child the test could not reach). It returns a stop
// function the caller defers and the path of the captured stdout/stderr
// log (used to scrape the TOTP enrolment secret for MFA examples).
func startExample(t *testing.T, dir string) (func(), string) {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "example.bin")
	build := exec.Command("go", "build", "-tags", "example", "-o", bin, ".")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build example %s: %v\n%s", dir, err, out)
	}

	logFile, err := os.CreateTemp(t.TempDir(), "example-*.log")
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start example %s: %v", dir, err)
	}

	stop := func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			if data, rerr := os.ReadFile(logFile.Name()); rerr == nil {
				t.Logf("example log:\n%s", data)
			}
		}
	}
	return stop, logFile.Name()
}

// waitForReady polls url until it answers 2xx/3xx or the deadline
// passes. The example boots the OP first and the RP only after its own
// discovery succeeds, so a ready RP implies a ready OP.
func waitForReady(t *testing.T, url string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url) //nolint:noctx // short-lived readiness poll
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 400 {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s to become ready", url)
}

// newBrowserCtx launches a headless Chrome and returns a context bounded
// by a 60s deadline plus a single cancel that tears the whole stack down.
func newBrowserCtx(chrome string) (context.Context, context.CancelFunc) {
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chrome),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	ctx, cancelTimeout := context.WithTimeout(ctx, 60*time.Second)
	return ctx, func() {
		cancelTimeout()
		cancelCtx()
		cancelAlloc()
	}
}

// driveLogin runs the full browser walkthrough for the default HTML
// interaction driver and returns the visible text of the final /me page.
// It returns an error rather than failing the test so the caller can retry
// a flaky run against the same example.
func driveLogin(chrome string, spec exampleSpec) (string, error) {
	ctx, cancel := newBrowserCtx(chrome)
	defer cancel()

	// Stage 1 — password prompt. The default HTML interaction driver
	// renders username/password inputs and a single "Continue" submit.
	if err := chromedp.Run(ctx,
		chromedp.Navigate(defaultRPBase+"/"),
		chromedp.Click(`a[href="/login"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`input[name="username"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="username"]`, spec.username, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="password"]`, spec.password, chromedp.ByQuery),
		chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
	); err != nil {
		return "", fmt.Errorf("password stage: %w", err)
	}

	// Stage 2 — consent. The consent page carries a hidden
	// approved_scopes field and the same "Continue" submit button as
	// the login page (the default driver uses no distinct "Approve"
	// label), so key off the consent-only field and submit its form.
	if err := chromedp.Run(ctx,
		chromedp.WaitReady(`input[name="approved_scopes"]`, chromedp.ByQuery),
		chromedp.Submit(`input[name="approved_scopes"]`, chromedp.ByQuery),
	); err != nil {
		return "", fmt.Errorf("consent stage: %w", err)
	}

	// Stage 3 — landing on the RP's /me, which renders the verified ID
	// Token claims as indented JSON.
	if err := waitURLContains(ctx, "/me"); err != nil {
		return "", err
	}
	var body string
	if err := chromedp.Run(ctx,
		chromedp.Text("body", &body, chromedp.ByQuery, chromedp.NodeVisible),
	); err != nil {
		return "", fmt.Errorf("read /me body: %w", err)
	}
	return body, nil
}

// driveSPALogin drives an op.WithSPAUI example through one authorization
// leg. The vanilla SPA bundle renders each prompt into #prompt-form, POSTs
// submissions as JSON, and re-renders the next prompt in place — the URL
// stays on /login/{uid} until the terminal redirect. The prompt set and
// order vary by example (password, TOTP, captcha, consent, in rule order),
// so spaLoop detects whichever prompt is showing and answers it.
func driveSPALogin(chrome string, spec exampleSpec, totpSecret string) (string, error) {
	ctx, cancel := newBrowserCtx(chrome)
	defer cancel()

	loginLink := spec.loginLink
	if loginLink == "" {
		loginLink = `a[href="/login"]`
	}
	if err := chromedp.Run(ctx,
		chromedp.Navigate(defaultRPBase+"/"),
		chromedp.Click(loginLink, chromedp.ByQuery),
		chromedp.WaitVisible(`#prompt-form`, chromedp.ByQuery),
	); err != nil {
		return "", fmt.Errorf("spa start: %w", err)
	}
	return spaLoop(ctx, spec, totpSecret)
}

// driveStepUp drives the two-leg step-up example: an initial password
// login, then a second authorization at /step-up that requests a higher
// ACR with prompt=login, forcing re-authentication plus a TOTP step. Both
// legs share one browser (and its session cookies) so the second leg
// re-uses the established session; the returned body is the stepped-up /me
// whose acr claim the test asserts.
func driveStepUp(chrome string, spec exampleSpec, totpSecret string) (string, error) {
	ctx, cancel := newBrowserCtx(chrome)
	defer cancel()

	if err := chromedp.Run(ctx,
		chromedp.Navigate(defaultRPBase+"/"),
		chromedp.Click(`a[href="/login"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`#prompt-form`, chromedp.ByQuery),
	); err != nil {
		return "", fmt.Errorf("step-up leg 1 start: %w", err)
	}
	if _, err := spaLoop(ctx, spec, totpSecret); err != nil {
		return "", fmt.Errorf("step-up leg 1 (initial login): %w", err)
	}

	if err := chromedp.Run(ctx,
		chromedp.Navigate(defaultRPBase+"/step-up"),
		chromedp.WaitVisible(`#prompt-form`, chromedp.ByQuery),
	); err != nil {
		return "", fmt.Errorf("step-up leg 2 start: %w", err)
	}
	body, err := spaLoop(ctx, spec, totpSecret)
	if err != nil {
		return "", fmt.Errorf("step-up leg 2 (re-auth): %w", err)
	}
	return body, nil
}

// spaLoop answers SPA prompts until the flow lands on /me. It assumes the
// caller has navigated so that #prompt-form is visible.
func spaLoop(ctx context.Context, spec exampleSpec, totpSecret string) (string, error) {
	pwAttempts := 0
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		switch spaState(ctx) {
		case "me":
			var body string
			if err := chromedp.Run(ctx,
				chromedp.Text("body", &body, chromedp.ByQuery, chromedp.NodeVisible),
			); err != nil {
				return "", fmt.Errorf("read /me body: %w", err)
			}
			return body, nil
		case "wait":
			time.Sleep(150 * time.Millisecond)
			continue
		case "password":
			// Examples demoing a captcha-after-failures rule need wrong
			// submissions first to trip it; the correct password follows
			// once the quota is spent.
			pw := spec.password
			if pwAttempts < spec.failPassword {
				pw = "wrong-password"
			}
			pwAttempts++
			if err := chromedp.Run(ctx,
				chromedp.SendKeys(`#prompt-form input[name="username"]`, spec.username, chromedp.ByQuery),
				chromedp.SendKeys(`#prompt-form input[name="password"]`, pw, chromedp.ByQuery),
			); err != nil {
				return "", fmt.Errorf("spa password prompt: %w", err)
			}
		case "totp":
			code, err := totpCode(totpSecret, time.Now())
			if err != nil {
				return "", fmt.Errorf("spa totp prompt: %w", err)
			}
			if err := chromedp.Run(ctx,
				chromedp.SendKeys(`#prompt-form input[name="code"]`, code, chromedp.ByQuery),
			); err != nil {
				return "", fmt.Errorf("spa totp prompt: %w", err)
			}
		case "captcha":
			if err := chromedp.Run(ctx,
				chromedp.SendKeys(`#prompt-form input[name="captcha_token"]`, "browserverify-stub-token", chromedp.ByQuery),
			); err != nil {
				return "", fmt.Errorf("spa captcha prompt: %w", err)
			}
		case "consent":
			// Nothing to fill; the Approve button posts approved_scopes.
		}
		if err := spaSubmit(ctx); err != nil {
			return "", err
		}
	}
	href, body := spaDump(ctx)
	return "", fmt.Errorf("spa flow did not reach /me within deadline; at %q with body:\n%s", href, body)
}

// spaSubmit clicks the current prompt's submit button and blocks until the
// SPA has replaced it — i.e. re-rendered the next prompt or navigated away.
// Marking the button before the click keeps the wait reliable even when the
// next prompt is the same kind (a rejected password re-prompts password),
// which a state-change check could not distinguish.
func spaSubmit(ctx context.Context) error {
	var marked bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(
		`(function(){var b=document.querySelector('#prompt-form button[type="submit"]');`+
			`if(!b){return false;}b.dataset.bvClicked='1';return true;})()`, &marked)); err != nil {
		return fmt.Errorf("mark submit button: %w", err)
	}
	if !marked {
		return fmt.Errorf("no submit button in current prompt")
	}
	if err := chromedp.Run(ctx,
		chromedp.Click(`#prompt-form button[data-bv-clicked]`, chromedp.ByQuery),
	); err != nil {
		return fmt.Errorf("click submit: %w", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var present bool
		if err := chromedp.Run(ctx, chromedp.Evaluate(
			`!!document.querySelector('#prompt-form button[data-bv-clicked]')`, &present)); err != nil {
			return nil // navigated away — the marked button is gone with the document
		}
		if !present {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("prompt did not advance after submit")
}

// spaState reports which prompt the SPA is currently showing, keyed off
// the field the active prompt renders into #prompt-form. A transient
// evaluate error (the document is mid-navigation) is reported as "wait".
func spaState(ctx context.Context) string {
	const js = `(function () {
  if (location.href.indexOf('/me') >= 0) return 'me';
  var f = document.querySelector('#prompt-form');
  if (!f || f.hidden) return 'wait';
  if (f.querySelector('input[name="code"]')) return 'totp';
  if (f.querySelector('input[name="captcha_token"]')) return 'captcha';
  if (f.querySelector('ul.scopes')) return 'consent';
  if (f.querySelector('input[name="username"]') || f.querySelector('input[name="password"]')) return 'password';
  return 'wait';
})()`
	var state string
	if err := chromedp.Run(ctx, chromedp.Evaluate(js, &state)); err != nil {
		return "wait"
	}
	return state
}

// spaDump returns the current URL and visible body for a failure message.
func spaDump(ctx context.Context) (string, string) {
	var href, body string
	_ = chromedp.Run(ctx, chromedp.Evaluate(`document.location.href`, &href))
	_ = chromedp.Run(ctx, chromedp.Text("body", &body, chromedp.ByQuery, chromedp.NodeVisible))
	return href, body
}

// waitURLContains polls document.location.href until it contains want.
// On timeout it reports where the browser actually stalled (URL + visible
// text), so a stuck RP /callback — the OP issued the code but the RP's
// token exchange errored — is told apart from a genuine login failure.
func waitURLContains(ctx context.Context, want string) error {
	deadline := time.Now().Add(30 * time.Second)
	var href string
	for time.Now().Before(deadline) {
		if err := chromedp.Run(ctx, chromedp.Evaluate(
			`document.location.href`, &href,
		)); err != nil {
			return fmt.Errorf("evaluate location while waiting for %q: %w", want, err)
		}
		if strings.Contains(href, want) {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	var body string
	_ = chromedp.Run(ctx, chromedp.Text("body", &body, chromedp.ByQuery, chromedp.NodeVisible))
	return fmt.Errorf("timeout waiting for URL to contain %q; stalled at %q with body:\n%s", want, href, body)
}

// findChrome resolves a Chrome/Chromium binary: CHROME_BIN wins, then a
// short list of PATH names, then the macOS app bundle. Returns "" when
// none is found so optional test runs can skip and required runs can fail.
func findChrome() string {
	if env := os.Getenv("CHROME_BIN"); env != "" {
		if path, err := exec.LookPath(env); err == nil {
			return path
		}
		return ""
	}
	for _, name := range []string{
		"google-chrome-stable", "google-chrome", "chromium", "chromium-browser", "chrome",
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

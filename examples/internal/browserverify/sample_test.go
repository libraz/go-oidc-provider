//go:build browserverify

package browserverify

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// The reference application is the one subject here that is not a single
// self-contained binary: it runs against MySQL and Redis, so its harness
// brings up sample/compose.yaml instead of calling startExample. Everything
// after the boot is the same shape as the example tests — one Chrome, one
// linear walkthrough, assertions on what the relying party finally renders.
//
// What it covers that no numbered example does is the arc before the first
// login: an account is created through the application's own signup form, an
// authenticator is enrolled, and only then does a relying party start an
// authorization request. The subject the relying party ends up seeing is
// read off the account page rather than hardcoded, because the application
// mints an opaque one at signup.

const (
	sampleOPBase = "http://127.0.0.1:8080"
	sampleRPBase = "http://127.0.0.1:9090"

	// samplePassword clears the application's 8-character floor.
	samplePassword = "reference-app-password"

	// totpStep is the RFC 6238 window the sample's factor uses.
	totpStep = 30 * time.Second
)

// TestSampleReferenceApp drives signup → enrolment → login → consent →
// relying party against the real MySQL/Redis stack.
func TestSampleReferenceApp(t *testing.T) {
	chrome := requireChrome(t)
	compose := requireCompose(t)
	executedBrowserCases.Add(1)

	stop := startSampleStack(t, compose)
	defer stop()

	// MySQL's first boot plus the schema migration is slower than a single
	// go build, and the relying party only listens once its own discovery
	// call succeeds — so a ready RP still implies a ready OP.
	waitForReadyWithin(t, sampleRPBase+"/", 120*time.Second)

	// A run leaves no state behind (the teardown drops the volume), but a
	// developer who keeps the stack up between runs would otherwise collide
	// on the unique email column.
	email := fmt.Sprintf("member-%d@example.test", time.Now().UnixNano())

	body, err := driveSampleArc(chrome, email)
	if err != nil {
		t.Fatalf("reference application round-trip: %v", err)
	}
	// "otp" in amr is the claim that proves the enrolled factor was actually
	// demanded at login rather than skipped by the conditional rule.
	for _, want := range []string{`"iss": "` + sampleOPBase + `"`, `"otp"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("callback body missing %q; got:\n%s", want, body)
		}
	}
	t.Logf("reference application round-trip OK for %s", email)
}

// requireCompose resolves a working `docker compose`. Like requireChrome it
// skips by default and fails in required mode, so a developer without Docker
// still gets a green tree while the release gate does not silently lose the
// only case that exercises a real database.
func requireCompose(t *testing.T) string {
	t.Helper()
	docker, err := exec.LookPath("docker")
	if err == nil {
		if probeErr := exec.Command(docker, "compose", "version").Run(); probeErr == nil {
			return docker
		}
		err = fmt.Errorf("`docker compose version` failed")
	}
	if browserVerifyRequired() {
		t.Fatalf("docker compose unavailable (%v); required verification cannot run", err)
	}
	t.Skipf("docker compose unavailable (%v); skipping the reference application", err)
	return "" // unreachable; keeps the compiler aware that t.Skipf returns.
}

// startSampleStack brings the reference application's compose project up
// and returns its teardown. Removing the volume matters more here than for
// the numbered examples: the next run must start from an empty schema, or
// a members row left by a failed run changes what signup does.
func startSampleStack(t *testing.T, docker string) func() {
	t.Helper()
	return startComposeStack(t, docker, "sample/compose.yaml", "goidc-sample-verify", "app")
}

// repoRoot walks up from the test's working directory to the checkout that
// holds sample/. The harness runs from examples/internal/browserverify, but
// a fixed number of ".." would break the moment the harness moves.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "sample", "compose.yaml")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("repository root not found above the working directory")
		}
		dir = parent
	}
}

// driveSampleArc runs the whole walkthrough in one browser so the
// application's session cookie carries from signup into enrolment, while the
// OP's session is established by the login leg rather than inherited from it.
func driveSampleArc(chrome, email string) (string, error) {
	// Signup, enrolment, and a full authorization leg do not fit the 60s the
	// example cases get: the login TOTP step alone has to sit out a
	// 30-second window (see loginTOTPCode).
	ctx, cancel := newBrowserCtxWithin(chrome, 4*time.Minute)
	defer cancel()

	subject, err := signUp(ctx, email)
	if err != nil {
		return "", err
	}
	secret, enrolledAt, err := enrolTOTP(ctx)
	if err != nil {
		return "", err
	}
	body, err := signInThroughRP(ctx, email, secret, enrolledAt)
	if err != nil {
		return "", err
	}
	if !strings.Contains(body, subject) {
		return "", fmt.Errorf("relying party rendered a subject other than the account page's %q; got:\n%s", subject, body)
	}
	return body, nil
}

// signUp creates the account and returns the opaque subject the application
// minted for it, read off the account page it lands on.
func signUp(ctx context.Context, email string) (string, error) {
	var subject string
	err := chromedp.Run(ctx,
		chromedp.Navigate(sampleOPBase+"/"),
		chromedp.Click(`a[href="/signup"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`input[name="display_name"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="email"]`, email, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="display_name"]`, "Reference Member", chromedp.ByQuery),
		chromedp.SendKeys(`input[name="password"]`, samplePassword, chromedp.ByQuery),
		chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
		// The enrolment link is on the account page only, so waiting for it
		// rather than for the subject cell cannot read the previous
		// document's markup mid-navigation.
		chromedp.WaitVisible(`a[href="/account/totp"]`, chromedp.ByQuery),
		chromedp.Text(`dl.spec dd.mono-wrap`, &subject, chromedp.ByQuery, chromedp.NodeVisible),
	)
	if err != nil {
		return "", fmt.Errorf("signup: %w", err)
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return "", fmt.Errorf("signup: the account page rendered an empty subject")
	}
	// The subject must not be the email address. Deriving it from a mutable,
	// personally identifying value is the mistake the application exists not
	// to make, and a round-trip would pass just as happily either way.
	if strings.Contains(subject, "@") {
		return "", fmt.Errorf("signup: subject %q looks derived from the email address", subject)
	}
	return subject, nil
}

// enrolTOTP walks the enrolment pages and returns the shared secret together
// with the instant whose window the confirming code consumed.
func enrolTOTP(ctx context.Context) (string, time.Time, error) {
	var secret string
	if err := chromedp.Run(ctx,
		chromedp.Click(`a[href="/account/totp"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`input[name="code"]`, chromedp.ByQuery),
		chromedp.Text(`dl.spec dd.mono-wrap`, &secret, chromedp.ByQuery, chromedp.NodeVisible),
	); err != nil {
		return "", time.Time{}, fmt.Errorf("enrolment page: %w", err)
	}
	secret = strings.TrimSpace(secret)

	enrolledAt := time.Now()
	code, err := totpCode(secret, enrolledAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enrolment code: %w", err)
	}
	if err := chromedp.Run(ctx,
		chromedp.SendKeys(`input[name="code"]`, code, chromedp.ByQuery),
		chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`.flag-ok`, chromedp.ByQuery),
	); err != nil {
		return "", time.Time{}, fmt.Errorf("confirm enrolment: %w", err)
	}
	return secret, enrolledAt, nil
}

// signInThroughRP starts an authorization request at the relying party and
// answers whatever the OP asks for until the callback renders.
func signInThroughRP(ctx context.Context, email, secret string, enrolledAt time.Time) (string, error) {
	if err := chromedp.Run(ctx,
		chromedp.Navigate(sampleRPBase+"/"),
		chromedp.Click(`a[href="/login"]`, chromedp.ByQuery),
	); err != nil {
		return "", fmt.Errorf("start authorization: %w", err)
	}
	return samplePromptLoop(ctx, email, secret, enrolledAt)
}

// samplePromptLoop answers the OP's server-rendered prompts until the
// relying party's callback page appears. It detects the current prompt
// rather than assuming an order, so adding a factor to the application's
// LoginFlow does not quietly turn this into a test of a shorter path.
func samplePromptLoop(ctx context.Context, email, secret string, enrolledAt time.Time) (string, error) {
	// answered records the prompts this loop replied to. A flow that stalls
	// stalls on a page the OP rendered in response to one of them, and
	// without the trail the failure names only the deadline.
	var answered []string
	deadline := time.Now().Add(3 * time.Minute)
	waits := 0
	for time.Now().Before(deadline) {
		// A dead browser context makes every evaluation fail, which
		// samplePromptState reports as "wait" — indistinguishable from a page
		// that is merely still loading. Checking here turns that into an
		// immediate, accurate failure instead of a spin to the deadline.
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("the browser ended after %v: %w", answered, err)
		}
		state := samplePromptState(ctx)
		if state == "wait" {
			// A page with none of the expected controls is usually the OP's
			// JSON error document, which never becomes anything else. Give
			// it a few seconds to be a slow navigation, then report it.
			if waits++; waits > 40 {
				href, body := spaDump(ctx)
				return "", fmt.Errorf("stuck after answering %v; at %q with body:\n%s", answered, href, body)
			}
		} else {
			waits = 0
			answered = append(answered, state)
		}
		switch state {
		case "callback":
			var body string
			if err := chromedp.Run(ctx,
				chromedp.Text("body", &body, chromedp.ByQuery, chromedp.NodeVisible),
			); err != nil {
				return "", fmt.Errorf("read the callback body: %w", err)
			}
			return body, nil
		case "wait":
			time.Sleep(150 * time.Millisecond)
			continue
		case "password":
			if err := chromedp.Run(ctx,
				chromedp.SendKeys(`input[name="username"]`, email, chromedp.ByQuery),
				chromedp.SendKeys(`input[name="password"]`, samplePassword, chromedp.ByQuery),
				chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
			); err != nil {
				return "", fmt.Errorf("password prompt: %w", err)
			}
		case "totp":
			code, err := loginTOTPCode(secret, enrolledAt)
			if err != nil {
				return "", err
			}
			if err := chromedp.Run(ctx,
				chromedp.SendKeys(`input[name="code"]`, code, chromedp.ByQuery),
				chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
			); err != nil {
				return "", fmt.Errorf("totp prompt: %w", err)
			}
		case "consent":
			// Every scope box is checked when the page renders, so approving
			// the whole request is just a submit. Leaving them alone is what
			// makes the assertion on the callback claims meaningful.
			if err := chromedp.Run(ctx,
				chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
			); err != nil {
				return "", fmt.Errorf("consent prompt: %w", err)
			}
		}
		if err := awaitPromptChange(ctx, state); err != nil {
			return "", err
		}
	}
	href, body := spaDump(ctx)
	return "", fmt.Errorf("the flow did not reach the callback after answering %v; at %q with body:\n%s", answered, href, body)
}

// awaitPromptChange blocks until the browser shows something other than the
// prompt just answered. Each prompt is a full navigation, so without this the
// loop would re-read the outgoing document and submit the same page twice.
// A prompt that re-renders itself (a rejected credential) stalls here rather
// than being answered again with the same value, which is what makes the
// failure message point at the page that refused.
func awaitPromptChange(ctx context.Context, answered string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("the browser ended on the %s prompt: %w", answered, err)
		}
		if samplePromptState(ctx) != answered {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	href, body := spaDump(ctx)
	return fmt.Errorf("the %s prompt did not advance; at %q with body:\n%s", answered, href, body)
}

// loginTOTPCode returns a code the login step will accept.
//
// Enrolment already consumed a code and the store advances
// last_accepted_step past that window, so replaying the same window at login
// is refused — correctly, since that is the replay the counter exists to
// stop. The test therefore sits out the rest of the enrolment window instead
// of working around the guard.
func loginTOTPCode(secret string, enrolledAt time.Time) (string, error) {
	step := int64(totpStep.Seconds())
	for time.Now().Unix()/step <= enrolledAt.Unix()/step {
		time.Sleep(time.Second)
	}
	code, err := totpCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("login code: %w", err)
	}
	return code, nil
}

// samplePromptState reports which page the browser is on. The application's
// prompts are server-rendered full pages, so unlike the SPA harness the check
// keys off the document rather than a live #prompt-form container.
func samplePromptState(ctx context.Context) string {
	const js = `(function () {
  if (location.href.indexOf('/callback') >= 0) return 'callback';
  if (document.querySelector('input[name="scope"]')) return 'consent';
  if (document.querySelector('input[name="code"]')) return 'totp';
  if (document.querySelector('input[name="username"]')) return 'password';
  return 'wait';
})()`
	var state string
	if err := chromedp.Run(ctx, chromedp.Evaluate(js, &state)); err != nil {
		return "wait"
	}
	return state
}

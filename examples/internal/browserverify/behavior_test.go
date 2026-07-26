//go:build browserverify

package browserverify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// These tests cover e2e-specific perspectives that a single happy-path
// round-trip cannot: behaviour that only emerges across multiple requests
// in one real browser session. They drive 01-minimal because they exercise
// OP/library session behaviour, not example-specific features.

// htmlState reports which default-HTML-driver page the browser is on, so a
// multi-leg flow can tell an SSO-reused authorize (straight to consent or
// /me) from one that re-prompts for a password.
func htmlState(ctx context.Context) string {
	const js = `(function () {
  if (location.href.indexOf('/me') >= 0) return 'me';
  if (document.querySelector('input[name="approved_scopes"]')) return 'consent';
  if (document.querySelector('input[name="username"]')) return 'password';
  return 'wait';
})()`
	var s string
	if err := chromedp.Run(ctx, chromedp.Evaluate(js, &s)); err != nil {
		return "wait"
	}
	return s
}

// htmlLogin drives one full default-HTML-driver login (password → consent →
// /me) on an existing browser context.
func htmlLogin(ctx context.Context, spec exampleSpec) error {
	if err := chromedp.Run(ctx,
		chromedp.Navigate(defaultRPBase+"/"),
		chromedp.Click(`a[href="/login"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`input[name="username"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="username"]`, spec.username, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="password"]`, spec.password, chromedp.ByQuery),
		chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
		chromedp.WaitReady(`input[name="approved_scopes"]`, chromedp.ByQuery),
		chromedp.Submit(`input[name="approved_scopes"]`, chromedp.ByQuery),
	); err != nil {
		return err
	}
	return waitURLContains(ctx, "/me")
}

// TestBehavior01MinimalSSO verifies the OP's authentication session is
// reused: after one full login, a second authorization in the same browser
// must NOT re-prompt for a password. This is genuinely e2e — it depends on
// the real browser carrying the OP's __Host- session cookie across a fresh
// top-level navigation, which a single httptest round-trip never exercises.
func TestBehavior01MinimalSSO(t *testing.T) {
	chrome := requireChrome(t)
	executedBrowserCases.Add(1)
	spec := exampleSpec{dir: "../../01-minimal", username: "demo", password: "demo", wantSub: "demo-user"}

	stop, _ := startExample(t, spec.dir)
	defer stop()
	waitForReady(t, defaultRPBase+"/")

	ctx, cancel := newBrowserCtx(chrome)
	defer cancel()

	if err := htmlLogin(ctx, spec); err != nil {
		t.Fatalf("initial login: %v", err)
	}

	// Second authorization: leave /me, start a fresh authorize.
	if err := chromedp.Run(ctx,
		chromedp.Navigate(defaultRPBase+"/"),
		chromedp.Click(`a[href="/login"]`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("second authorize start: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		switch htmlState(ctx) {
		case "me":
			return // reused the session and reached /me without a password
		case "consent":
			// Session reused; consent may be re-shown — approve and finish.
			if err := chromedp.Run(ctx, chromedp.Submit(`input[name="approved_scopes"]`, chromedp.ByQuery)); err != nil {
				t.Fatalf("second authorize consent: %v", err)
			}
			// Submitting starts a navigation, and until it lands the
			// browser still shows the consent form. Without this wait the
			// loop reads the outgoing document and submits the same page
			// again, whose form is by then detached — which is why this
			// case used to spin to the deadline rather than fail on the
			// page that actually went wrong.
			if err := awaitHTMLStateChange(ctx, "consent"); err != nil {
				t.Fatalf("second authorize consent: %v", err)
			}
		case "password":
			t.Fatal("SSO failed: the second authorization re-prompted for a password despite an active session")
		case "wait":
			time.Sleep(150 * time.Millisecond)
		}
	}
	href, body := spaDump(ctx)
	t.Fatalf("timeout waiting for the second authorization to complete; at %q with body:\n%s", href, body)
}

// awaitHTMLStateChange blocks until the browser shows something other than
// the page just answered, so a caller cannot act twice on one document.
func awaitHTMLStateChange(ctx context.Context, answered string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if htmlState(ctx) != answered {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	href, body := spaDump(ctx)
	return fmt.Errorf("the %s page did not advance; at %q with body:\n%s", answered, href, body)
}

// TestBehavior01MinimalLogout would assert that RP-Initiated Logout
// invalidates the OP session (the next authorization re-prompts for a
// password). It is not browser-drivable against the current examples: a
// valid /end_session request needs an id_token_hint (or a registered
// post_logout_redirect_uri), and the demo RP holds the ID Token
// server-side and exposes no logout link, so the browser cannot present
// one. A bare GET /end_session?client_id=... is rejected without clearing
// the session (confirmed empirically). RP-Initiated Logout is covered at
// the unit/integration layer in internal/endsession; an e2e gate here would
// need an example that wires a post_logout_redirect_uri and a logout button.
func TestBehavior01MinimalLogout(t *testing.T) {
	t.Skip("not e2e-drivable: /end_session needs an id_token_hint the demo RP does not expose to the browser; covered by internal/endsession unit tests")
}

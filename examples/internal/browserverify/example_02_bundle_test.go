//go:build browserverify

package browserverify

import (
	"fmt"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"
)

// 02-bundle is the "everything wired" SPA: a first-party client with a
// mandatory TOTP second factor. The SPA loop drives password → TOTP →
// consent; the amr claim must carry "otp" from the TOTP step.
func TestExample02Bundle(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:        "../../02-bundle",
		username:   "demo",
		password:   "demo",
		wantSub:    "demo-user",
		wantClaims: []string{`"otp"`},
		spa:        true,
		totp:       true,
	})
}

// TestExample02BundleWrongPasswordShowsAlert submits a wrong password
// first: the bundle must render the OP's rejection notice as an alert
// above the re-rendered form, and the correct password must then carry the
// flow through TOTP and consent to /me.
func TestExample02BundleWrongPasswordShowsAlert(t *testing.T) {
	spec := exampleSpec{
		dir:        "../../02-bundle",
		username:   "demo",
		password:   "demo",
		wantSub:    "demo-user",
		wantClaims: []string{`"otp"`},
		spa:        true,
		totp:       true,
	}

	chrome := requireChrome(t)
	executedBrowserCases.Add(1)

	stop, logPath := startExample(t, spec.dir)
	defer stop()
	waitForReady(t, defaultRPBase+"/")

	totpSecret := scrapeTOTPSecret(t, logPath)
	codes := &codeScraper{logPath: logPath}

	drive := func() (string, error) {
		ctx, cancel := newBrowserCtx(chrome)
		defer cancel()

		if err := chromedp.Run(ctx,
			chromedp.Navigate(defaultRPBase+"/"),
			chromedp.Click(`a[href="/login"]`, chromedp.ByQuery),
			chromedp.WaitVisible(`#prompt-form input[name="password"]`, chromedp.ByQuery),
			chromedp.SendKeys(`#prompt-form input[name="username"]`, spec.username, chromedp.ByQuery),
			chromedp.SendKeys(`#prompt-form input[name="password"]`, "wrong-password", chromedp.ByQuery),
		); err != nil {
			return "", fmt.Errorf("wrong-password start: %w", err)
		}
		if err := spaSubmit(ctx); err != nil {
			return "", err
		}

		var alert string
		if err := chromedp.Run(ctx,
			chromedp.WaitVisible(`#prompt-form [role="alert"]`, chromedp.ByQuery),
			chromedp.Text(`#prompt-form [role="alert"]`, &alert, chromedp.ByQuery),
		); err != nil {
			href, body := spaDump(ctx)
			return "", fmt.Errorf("no alert after a wrong password: %w; at %q with body:\n%s", err, href, body)
		}
		if !strings.Contains(alert, "incorrect") {
			return "", fmt.Errorf("alert text = %q, want the rejection notice", alert)
		}

		// The correct password on the re-rendered form, then the rest of
		// the flow.
		return spaLoop(ctx, spec, totpSecret, codes)
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
	if !strings.Contains(body, `"sub": "`+spec.wantSub+`"`) {
		t.Fatalf("/me body missing expected sub %q; got:\n%s", spec.wantSub, body)
	}
	for _, want := range spec.wantClaims {
		if !strings.Contains(body, want) {
			t.Fatalf("/me body missing expected claim %q; got:\n%s", want, body)
		}
	}
}

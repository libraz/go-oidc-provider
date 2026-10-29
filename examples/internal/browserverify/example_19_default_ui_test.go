//go:build browserverify

package browserverify

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"
)

// 19-default-ui has no RP of its own: the OP serves the built-in HTML
// screens and the registered redirect_uri points nowhere. The test drives
// /authorize directly, so the walkthrough ends at the consent screen
// rather than at an RP page.
//
// A wrong password must re-render the password page with the rejection
// notice as an alert; the correct password must then reach consent.
func TestExample19DefaultUIWrongPasswordShowsAlert(t *testing.T) {
	chrome := requireChrome(t)
	executedBrowserCases.Add(1)

	stop, _ := startExample(t, "../../19-default-ui")
	defer stop()
	waitForReady(t, defaultOPIssuer+"/.well-known/openid-configuration")

	// The RFC 7636 appendix B challenge; the value only has to be a valid S256 challenge.
	authorizeURL := defaultOPIssuer + "/oidc/auth?" + url.Values{
		"client_id":             {"demo-rp"},
		"response_type":         {"code"},
		"redirect_uri":          {"http://127.0.0.1:8081/callback"},
		"scope":                 {"openid"},
		"state":                 {"bv-state"},
		"nonce":                 {"bv-nonce"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()

	drive := func() error {
		ctx, cancel := newBrowserCtx(chrome)
		defer cancel()

		if err := chromedp.Run(ctx,
			chromedp.Navigate(authorizeURL),
			chromedp.WaitVisible(`input[name="username"]`, chromedp.ByQuery),
			chromedp.SendKeys(`input[name="username"]`, "alice", chromedp.ByQuery),
			chromedp.SendKeys(`input[name="password"]`, "wrong-password", chromedp.ByQuery),
			chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
		); err != nil {
			return fmt.Errorf("wrong-password stage: %w", err)
		}

		var alert string
		if err := chromedp.Run(ctx,
			chromedp.WaitVisible(`p[role="alert"]`, chromedp.ByQuery),
			chromedp.Text(`p[role="alert"]`, &alert, chromedp.ByQuery),
		); err != nil {
			href, body := spaDump(ctx)
			return fmt.Errorf("no alert after a wrong password: %w; at %q with body:\n%s", err, href, body)
		}
		if !strings.Contains(alert, "incorrect") {
			return fmt.Errorf("alert text = %q, want the rejection notice", alert)
		}

		if err := chromedp.Run(ctx,
			chromedp.WaitVisible(`input[name="password"]`, chromedp.ByQuery),
			chromedp.SendKeys(`input[name="username"]`, "alice", chromedp.ByQuery),
			chromedp.SendKeys(`input[name="password"]`, "alice-password", chromedp.ByQuery),
			chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
			chromedp.WaitReady(`input[name="approved_scopes"]`, chromedp.ByQuery),
		); err != nil {
			href, body := spaDump(ctx)
			return fmt.Errorf("correct-password stage did not reach consent: %w; at %q with body:\n%s", err, href, body)
		}
		return nil
	}

	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		if err = drive(); err == nil {
			break
		}
		t.Logf("attempt %d/2 failed: %v", attempt, err)
	}
	if err != nil {
		t.Fatalf("browser walkthrough: %v", err)
	}
}

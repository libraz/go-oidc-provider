//go:build browserverify

package browserverify

import (
	"net/url"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"
)

// 37-custom-login-ui replaces the sign-in screen with an embedder
// template that loads a stylesheet. As with the consent template, a
// stylesheet the page's Content-Security-Policy refuses produces no
// server-side signal, so the test asks the browser what it applied, then
// signs in through the template's own form: a form that dropped
// state_ref or csrf_token would be refused and never reach consent.
func TestExample37CustomLoginUI(t *testing.T) {
	chrome := requireChrome(t)
	executedBrowserCases.Add(1)

	stop, _ := startExample(t, "../../37-custom-login-ui")
	defer stop()

	waitForReady(t, defaultOPIssuer+"/.well-known/openid-configuration")

	ctx, cancel := newBrowserCtx(chrome)
	defer cancel()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-rp"},
		"redirect_uri":          {"http://localhost:8081/callback"},
		"scope":                 {"openid profile"},
		"state":                 {"browserverify-state"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}

	const probe = `(function () {
  var rules = -1;
  try { rules = document.styleSheets.length ? document.styleSheets[0].cssRules.length : 0; } catch (e) { rules = -2; }
  return JSON.stringify({
    rules: rules,
    maxWidth: getComputedStyle(document.body).maxWidth,
    title: document.title,
    href: (document.querySelector('link[rel="stylesheet"]') || {}).href || ''
  });
})()`

	var state string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(defaultOPIssuer+"/oidc/auth?"+params.Encode()),
		chromedp.WaitVisible(`input[name="username"]`, chromedp.ByQuery),
		chromedp.Evaluate(probe, &state),
	); err != nil {
		t.Fatalf("drive login screen: %v", err)
	}

	if !strings.Contains(state, "/assets/login.css") || !strings.Contains(state, `"title":"Sign in"`) {
		t.Fatalf("login page is not the example template: %s", state)
	}
	if strings.Contains(state, `"rules":0`) || strings.Contains(state, `"rules":-`) {
		t.Errorf("the browser loaded no rules from the login stylesheet: %s", state)
	}
	if strings.Contains(state, `"maxWidth":"none"`) {
		t.Errorf("stylesheet did not take effect on the login page: %s", state)
	}

	// The built-in consent screen follows a successful sign-in; its
	// hidden approved_scopes input marks that the flow got past login.
	if err := chromedp.Run(ctx,
		chromedp.SendKeys(`input[name="username"]`, "demo", chromedp.ByQuery),
		chromedp.SendKeys(`input[name="password"]`, "demo-password", chromedp.ByQuery),
		chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
		chromedp.WaitReady(`input[name="approved_scopes"]`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("sign in through the template did not reach consent: %v", err)
	}
	t.Logf("custom login UI OK: %s", state)
}

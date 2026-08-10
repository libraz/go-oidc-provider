//go:build browserverify

package browserverify

import (
	"net/url"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"
)

// 11-custom-consent-ui replaces the consent screen with an embedder
// template that loads a stylesheet. Whether that stylesheet is applied
// is decided by the browser against the page's Content-Security-Policy,
// and a blocked one produces no server-side signal at all: the OP
// serves 200, the CSS request is either never made or discarded, and
// the page renders unstyled. A response-header assertion would pass on
// a policy that names an origin the browser still refuses; only asking
// the browser what it ended up applying distinguishes the two.
//
// The driver stops at consent rather than approving. The example's
// registered redirect_uri has no listener — reaching the consent page
// with the stylesheet in force is the whole claim.
func TestExample11CustomConsentUI(t *testing.T) {
	chrome := requireChrome(t)
	executedBrowserCases.Add(1)

	stop, _ := startExample(t, "../../11-custom-consent-ui")
	defer stop()

	waitForReady(t, defaultOPIssuer+"/.well-known/openid-configuration")

	ctx, cancel := newBrowserCtx(chrome)
	defer cancel()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-rp"},
		"redirect_uri":          {"http://localhost:8081/callback"},
		"scope":                 {"openid profile email"},
		"state":                 {"browserverify-state"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}

	// A blocked stylesheet still leaves an entry in document.styleSheets
	// — Chrome creates the object and never fills it — so counting
	// sheets proves nothing. The rule count and the computed style are
	// what distinguish "the CSS applied" from "the browser refused it".
	const probe = `(function () {
  var rules = -1;
  try { rules = document.styleSheets.length ? document.styleSheets[0].cssRules.length : 0; } catch (e) { rules = -2; }
  return JSON.stringify({
    rules: rules,
    maxWidth: getComputedStyle(document.body).maxWidth,
    href: (document.querySelector('link[rel="stylesheet"]') || {}).href || ''
  });
})()`

	var state string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(defaultOPIssuer+"/oidc/auth?"+params.Encode()),
		chromedp.WaitVisible(`input[name="username"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="username"]`, "demo", chromedp.ByQuery),
		chromedp.SendKeys(`input[name="password"]`, "demo-password", chromedp.ByQuery),
		chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
		// approved_scopes is a hidden input, so readiness — not
		// visibility — is what marks the consent page as rendered.
		chromedp.WaitReady(`input[name="approved_scopes"]`, chromedp.ByQuery),
		chromedp.Evaluate(probe, &state),
	); err != nil {
		t.Fatalf("drive consent screen: %v", err)
	}

	if !strings.Contains(state, "/assets/consent.css") {
		t.Fatalf("consent page did not reference the example stylesheet: %s", state)
	}
	if strings.Contains(state, `"rules":0`) || strings.Contains(state, `"rules":-`) {
		t.Errorf("the browser loaded no rules from the consent stylesheet: %s", state)
	}
	// The example's stylesheet sets a max-width on <body>; "none" is the
	// initial value, i.e. nothing from the sheet was applied.
	if strings.Contains(state, `"maxWidth":"none"`) {
		t.Errorf("stylesheet did not take effect on the consent page: %s", state)
	}
	t.Logf("custom consent UI OK: %s", state)
}

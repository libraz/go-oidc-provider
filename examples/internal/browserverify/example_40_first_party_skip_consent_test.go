//go:build browserverify

package browserverify

import (
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// 40-first-party-skip-consent promises that a listed first-party client
// signs the user in and reaches its redirect_uri with a code, never
// passing a consent screen. The skip is gated on the Sec-Fetch-Site
// header the browser itself computes, so only a real browser proves it:
// a typed or bookmarked address sends "none" and is deliberately
// untrusted.
//
// The example has no RP page, so the driver starts the authorization
// request from a document on the OP's own origin (the discovery
// document) with a script-initiated navigation, which Chrome labels
// same-origin. The example's redirect_uri has no listener; the driver
// observes the browser's request to it rather than a rendered page.
func TestExample40FirstPartySkipConsent(t *testing.T) {
	chrome := requireChrome(t)
	executedBrowserCases.Add(1)

	stop, _ := startExample(t, "../../40-first-party-skip-consent")
	defer stop()

	waitForReady(t, defaultOPIssuer+"/.well-known/openid-configuration")

	ctx, cancel := newBrowserCtx(chrome)
	defer cancel()

	var (
		mu        sync.Mutex
		requested []string
	)
	chromedp.ListenTarget(ctx, func(ev any) {
		if e, ok := ev.(*network.EventRequestWillBeSent); ok {
			mu.Lock()
			requested = append(requested, e.Request.URL)
			mu.Unlock()
		}
	})
	requestedCallback := func(prefix string) string {
		mu.Lock()
		defer mu.Unlock()
		for _, u := range requested {
			if strings.HasPrefix(u, prefix) {
				return u
			}
		}
		return ""
	}

	authorize := func(clientID, callback, scope string) string {
		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {callback},
			"scope":                 {scope},
			"state":                 {"browserverify-state"},
			"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
			"code_challenge_method": {"S256"},
		}
		target, err := json.Marshal(defaultOPIssuer + "/oidc/auth?" + params.Encode())
		if err != nil {
			t.Fatalf("encode authorize URL: %v", err)
		}
		return `window.location.assign(` + string(target) + `)`
	}

	const consentField = `input[name="approved_scopes"]`

	// First-party client: sign in, then straight to the redirect_uri.
	if err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(defaultOPIssuer+"/.well-known/openid-configuration"),
		chromedp.Evaluate(authorize("first-party-app", "https://app.example.com/callback", "openid profile"), nil),
		chromedp.WaitVisible(`input[name="username"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="username"]`, demoUser, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="password"]`, demoPass, chromedp.ByQuery),
		chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("sign in as first-party-app: %v", err)
	}

	var landed string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if landed = requestedCallback("https://app.example.com/callback?"); landed != "" {
			break
		}
		var consentShown bool
		// The page may already be a browser error page for the unreachable
		// redirect_uri; a failed probe means no consent page is showing.
		if err := chromedp.Run(ctx, chromedp.Evaluate(`!!document.querySelector('`+consentField+`')`, &consentShown)); err == nil && consentShown {
			t.Fatal("consent page rendered for a first-party client after sign-in")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if landed == "" {
		t.Fatal("browser never reached the first-party redirect_uri")
	}
	u, err := url.Parse(landed)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", landed, err)
	}
	if u.Query().Get("code") == "" || u.Query().Get("state") != "browserverify-state" {
		t.Fatalf("redirect lacks code or state: %s", landed)
	}

	// Control: the same navigation and sign-in for a client that is not
	// listed must stop at the consent page, so the assertion above is not
	// satisfied by every client. A fresh browser keeps the first run's
	// session and error page out of it.
	ctx2, cancel2 := newBrowserCtx(chrome)
	defer cancel2()
	chromedp.ListenTarget(ctx2, func(ev any) {
		if e, ok := ev.(*network.EventRequestWillBeSent); ok {
			mu.Lock()
			requested = append(requested, e.Request.URL)
			mu.Unlock()
		}
	})
	if err := chromedp.Run(ctx2,
		network.Enable(),
		chromedp.Navigate(defaultOPIssuer+"/.well-known/openid-configuration"),
		chromedp.Evaluate(authorize("third-party-integration", "https://partner.example.com/callback", "openid"), nil),
		chromedp.WaitVisible(`input[name="username"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="username"]`, demoUser, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="password"]`, demoPass, chromedp.ByQuery),
		chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
		chromedp.WaitReady(consentField, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("third-party-integration did not reach the consent page: %v", err)
	}
	if cb := requestedCallback("https://partner.example.com/callback"); cb != "" {
		t.Fatalf("third-party client reached its redirect_uri without consent: %s", cb)
	}
	t.Logf("first-party skip OK: %s", landed)
}

const (
	demoUser = "demo"
	demoPass = "demo"
)

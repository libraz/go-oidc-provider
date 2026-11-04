//go:build browserverify

package browserverify

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// 38-native-app has no RP web page: the client is a CLI that prints its
// authorization URL and waits on an ephemeral loopback port. The driver does
// what the user would: take the URL from the log, sign in and approve in the
// browser, and land on the client's loopback callback page. The claim worth
// proving is that the OP admitted a redirect_uri whose port differs from the
// registered one and that a secretless public client redeemed the code, so
// the driver also waits for the client's own success line in the log.
func TestExample38NativeApp(t *testing.T) {
	chrome := requireChrome(t)
	executedBrowserCases.Add(1)

	stop, logPath := startExample(t, "../../38-native-app")
	defer stop()

	waitForReady(t, defaultOPIssuer+"/.well-known/openid-configuration")
	authorizeURL := scrapeAuthorizeURL(t, logPath)

	ctx, cancel := newBrowserCtx(chrome)
	defer cancel()

	var body string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(authorizeURL),
		chromedp.WaitVisible(`input[name="username"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="username"]`, demoUser, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="password"]`, demoPass, chromedp.ByQuery),
		chromedp.Click(`button[type="submit"]`, chromedp.ByQuery),
		chromedp.WaitReady(`input[name="approved_scopes"]`, chromedp.ByQuery),
		chromedp.Submit(`input[name="approved_scopes"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`h1`, chromedp.ByQuery),
		chromedp.Text("body", &body, chromedp.ByQuery, chromedp.NodeVisible),
	); err != nil {
		t.Fatalf("browser sign-in: %v", err)
	}
	if !strings.Contains(body, "Signed in as demo-user") {
		t.Fatalf("loopback callback page missing the signed-in subject; got:\n%s", body)
	}

	const marker = "✓ native login: sub=demo-user"
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(logPath); err == nil && strings.Contains(string(data), marker) {
			t.Logf("native login OK: %s", marker)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("example never logged %q", marker)
}

// scrapeAuthorizeURL waits for the "open this URL to sign in:" line the
// client prints and returns the URL on the next line.
func scrapeAuthorizeURL(t *testing.T, logPath string) string {
	t.Helper()
	re := regexp.MustCompile(`open this URL to sign in:\n(\S+)`)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(logPath); err == nil {
			if m := re.FindStringSubmatch(string(data)); m != nil {
				return m[1]
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("example never printed an authorization URL (log %s)", logPath)
	return ""
}

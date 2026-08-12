//go:build browserverify

package browserverify

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
)

// 29-passkey is the only example whose browser half cannot be exercised by
// driving the DOM alone: both ceremonies run inside navigator.credentials,
// which needs an authenticator to answer them. Chrome ships one for exactly
// this purpose — a virtual authenticator installed over CDP — so the
// test below is the real browser walkthrough rather than a stub.
//
// It covers what internal/apiverify cannot. That harness signs the
// ceremonies in-process and posts the results itself, which proves the
// server contract but never runs the example's own JavaScript: the
// base64url ↔ ArrayBuffer decoding in enrol.js, the standard-base64
// decoding of the assertion prompt in main.js, and the user-activation
// requirement that forces the ceremony into a click handler are all
// invisible to it. Those are browser-only failure modes, and a passkey
// that only works when a Go test posts it is not a working passkey.
//
// The example binds localhost rather than the 127.0.0.1 the rest of this
// harness uses: a WebAuthn Relying Party ID must be a domain, and browsers
// reject an IP literal.
const (
	pk29OPBase = "http://localhost:8080"
	pk29RPBase = "http://localhost:9090"
)

// TestExample29Passkey runs the whole lifecycle in one browser: enrol a
// credential on the application's account page, then start an authorization
// and sign in with it.
//
// The claim asserted is "hwk". The virtual authenticator below verifies
// the user, and the library reads the RFC 8176 token off the assertion's
// real UV bit — so a run that reported "swk" would mean the flag the
// browser set was not the flag the session recorded. (apiverify drives
// the other arm, where an authenticator that only tests presence yields
// "swk".)
func TestExample29Passkey(t *testing.T) {
	chrome := requireChrome(t)
	executedBrowserCases.Add(1)

	stop, _ := startExample(t, "../../29-passkey")
	defer stop()
	waitForReadyWithin(t, pk29RPBase+"/", 30*time.Second)

	// Two ceremonies plus a full authorization leg do not fit the minute a
	// single-prompt round-trip gets.
	ctx, cancel := newBrowserCtxWithin(chrome, 3*time.Minute)
	defer cancel()

	// The authenticator has to exist before the first ceremony, and it
	// outlives the navigation from the account page to the login SPA —
	// which is the point: the credential registered on one page is the
	// credential the other has to find.
	if err := installVirtualAuthenticator(ctx); err != nil {
		t.Fatalf("install virtual authenticator: %v", err)
	}

	credentialID, err := enrolPasskeyInBrowser(ctx)
	if err != nil {
		t.Fatalf("enrolment: %v", err)
	}
	t.Logf("registered credential %s", credentialID)

	spec := exampleSpec{username: "demo", password: "demo", spa: true}
	if err := chromedp.Run(ctx,
		chromedp.Navigate(pk29RPBase+"/"),
		chromedp.Click(`a[href="/login"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`#prompt-form`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("start login: %v", err)
	}
	body, err := spaLoop(ctx, spec, "", &codeScraper{})
	if err != nil {
		t.Fatalf("passkey login: %v", err)
	}

	for _, want := range []string{
		`"iss": "` + pk29OPBase + `"`,
		`"sub": "demo-user"`,
		`"hwk"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/me body missing %q; got:\n%s", want, body)
		}
	}
	t.Logf("passkey round-trip OK: enrolled and signed in with %s", credentialID)
}

// installVirtualAuthenticator gives the browser a platform authenticator
// that answers both ceremonies without a human.
//
// It verifies the user because the example asks for verification when it
// can get it (the ceremonies are configured "preferred"), and presence is
// simulated automatically because there is no one to touch anything. A
// resident key is supported so the credential the example creates under a
// "preferred" resident-key policy is the discoverable one a real platform
// authenticator would make.
func installVirtualAuthenticator(ctx context.Context) error {
	return chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		if err := webauthn.Enable().Do(ctx); err != nil {
			return fmt.Errorf("enable the WebAuthn domain: %w", err)
		}
		if _, err := webauthn.AddVirtualAuthenticator(&webauthn.VirtualAuthenticatorOptions{
			Protocol:                    webauthn.AuthenticatorProtocolCtap2,
			Transport:                   webauthn.AuthenticatorTransportInternal,
			HasResidentKey:              true,
			HasUserVerification:         true,
			AutomaticPresenceSimulation: true,
			IsUserVerified:              true,
		}).Do(ctx); err != nil {
			return fmt.Errorf("add the virtual authenticator: %w", err)
		}
		return nil
	}))
}

// enrolPasskeyInBrowser drives the application's account page: submit the
// credentials the application already knows, let enrol.js run the
// registration ceremony, and read back the credential id it reports.
//
// The status line is the only signal the page publishes, which is also why
// it is worth asserting on — a ceremony that failed writes its reason
// there rather than throwing anywhere the test could see.
func enrolPasskeyInBrowser(ctx context.Context) (string, error) {
	if err := chromedp.Run(ctx,
		chromedp.Navigate(pk29OPBase+"/account"),
		chromedp.WaitVisible(`#enrol-form`, chromedp.ByQuery),
		chromedp.Click(`#enrol-form button[type="submit"]`, chromedp.ByQuery),
	); err != nil {
		return "", fmt.Errorf("submit the enrolment form: %w", err)
	}

	const prefix = "Registered. Credential id: "
	deadline := time.Now().Add(30 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		if err := chromedp.Run(ctx, chromedp.Evaluate(
			`(document.querySelector('#status')||{}).textContent||''`, &status,
		)); err != nil {
			return "", fmt.Errorf("read the enrolment status: %w", err)
		}
		if id, ok := strings.CutPrefix(status, prefix); ok {
			return id, nil
		}
		var failed bool
		if err := chromedp.Run(ctx, chromedp.Evaluate(
			`!!(document.querySelector('#status')||{}).dataset?.error`, &failed,
		)); err == nil && failed {
			return "", fmt.Errorf("the page reported an enrolment failure: %s", status)
		}
		time.Sleep(150 * time.Millisecond)
	}
	return "", fmt.Errorf("enrolment did not finish within the deadline; last status %q", status)
}

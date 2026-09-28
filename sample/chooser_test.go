//go:build example

package main

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// The account chooser is the one prompt this driver cannot decline to
// implement. op.New registers it on every Provider, so an authorization
// request carrying prompt=select_account reaches the driver whether or
// not the application configured multi-account sign-in — and a driver
// that errs on it turns a parameter anyone can add into a 500.
//
// The case below drives the whole path: a sign-in that puts one account
// into the chooser group, a second /authorize asking for the picker, the
// page the driver renders for it, and the pick running through to the
// relying party's redirect_uri.

const (
	chooserTestClientID = "sample-rp"
	chooserTestRedirect = "https://rp.sample.test/callback"
	chooserTestEmail    = "member@example.com"
	chooserTestName     = "Sample Member"
	chooserTestPassword = "correct-horse-battery"
)

// TestSelectAccountRendersChooserAndCompletes is the end-to-end case.
func TestSelectAccountRendersChooserAndCompletes(t *testing.T) {
	t.Parallel()

	b := newSampleBrowser(t)

	// Signing in is the precondition: the chooser lists live sessions, so
	// there is nothing to pick until this browser holds one.
	if code := b.completeFlow(b.authorizeURL()); code == "" {
		t.Fatal("the first sign-in did not reach the redirect_uri with a code")
	}

	page, done := b.interactionPage(b.authorizeURL() + "&prompt=select_account")
	if done {
		t.Fatal("prompt=select_account completed without rendering a chooser")
	}
	if !strings.Contains(page, "Choose an account") {
		t.Fatalf("prompt=select_account rendered something other than the chooser:\n%s", page)
	}
	if !strings.Contains(page, chooserTestName) {
		t.Errorf("the chooser row is not labelled with the member's name, leaving the page offering "+
			"an opaque identifier:\n%s", page)
	}
	if !strings.Contains(page, `name="session_id"`) {
		t.Fatalf("the chooser rendered no control carrying session_id, so no row can be picked:\n%s", page)
	}
	for _, key := range []string{chooserPromptType, "chooser.session_id"} {
		if strings.Contains(page, key) {
			t.Errorf("the rendered page shows the raw key %q:\n%s", key, page)
		}
	}

	// Picking a row has to carry the request to completion, not merely
	// render: a page submitting a field the orchestrator does not read
	// looks right and goes nowhere.
	if code := b.submitUntilDone(page); code == "" {
		t.Fatal("picking an account did not reach the redirect_uri with a code")
	}
}

// TestUserInfoResolvesFromTheApplicationsOwnStore pins the wiring main.go
// depends on: op.WithUserStore(members) is what makes /userinfo (and
// every ID-token claim) read from the store the login flow authenticated
// against, when that store is not the one passed to WithStore. Dropping
// the option would leave effectiveUserStore() resolving against the
// backend's own Users(), which this member's account never touches.
func TestUserInfoResolvesFromTheApplicationsOwnStore(t *testing.T) {
	t.Parallel()

	b := newSplitStoreBrowser(t)

	code := b.completeFlow(b.authorizeURL())
	if code == "" {
		t.Fatal("sign-in did not reach the redirect_uri with a code")
	}

	claims := b.userInfo(code)
	if got := claims["email"]; got != chooserTestEmail {
		t.Errorf("userinfo email = %v, want %q from the application's own store", got, chooserTestEmail)
	}
	if got := claims["name"]; got != chooserTestName {
		t.Errorf("userinfo name = %v, want %q from the application's own store", got, chooserTestName)
	}
}

// sampleBrowser drives the sample's own interaction driver against a
// provider wired the way main.go wires it, minus the datastores: the OP's
// records go to the in-memory adapter rather than MySQL and Redis.
// newSampleBrowser folds every store onto one instance, which exercises
// the driver; newSplitStoreBrowser keeps login and claims on separate
// instances, which exercises the storage split main.go actually has.
//
// The listener is TLS because the OP marks its cookies Secure and a
// cookie jar drops those over plain HTTP.
type sampleBrowser struct {
	t      *testing.T
	base   string
	client *http.Client

	// pageURL is where the most recently rendered page posts back to.
	pageURL string
	// code is the authorization code the last redirect off the OP
	// carried.
	code string

	verifier string
}

func newSampleBrowser(t *testing.T) *sampleBrowser {
	t.Helper()

	users := inmem.New()
	seedMember(t, users)
	return buildSampleBrowser(t,
		op.WithStore(users),
		op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: users.UserPasswords()}}),
	)
}

// newSplitStoreBrowser wires a provider the way main.go actually does: the
// login flow authenticates against the application's own account store,
// a separate store from the one passed to WithStore, and WithUserStore is
// what joins the two for claim reads. newSampleBrowser folds both roles
// onto a single store instead, which is why it cannot notice main.go
// dropping WithUserStore — this reproduces the split so a case can.
func newSplitStoreBrowser(t *testing.T) *sampleBrowser {
	t.Helper()

	storage := inmem.New()
	members := inmem.New()
	seedMember(t, members)
	return buildSampleBrowser(t,
		op.WithStore(storage),
		op.WithUserStore(members.Users()),
		op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: members.UserPasswords()}}),
	)
}

// seedMember puts the chooser test's member into s, keyed by both its
// subject (for claim reads) and its email (for password login).
func seedMember(t *testing.T, s *inmem.Store) {
	t.Helper()

	hash, err := op.HashPassword(chooserTestPassword)
	if err != nil {
		t.Fatalf("op.HashPassword: %v", err)
	}
	s.PutUserWithPassword(context.Background(), &store.User{
		Subject: "member-1",
		Claims:  map[string]any{"name": chooserTestName, "email": chooserTestEmail},
	}, chooserTestEmail, hash)
}

// buildSampleBrowser starts a provider on its own TLS listener and returns
// the browser driving it. storeOpts carries the store and login-flow
// wiring a case cares about; everything else — keys, driver, static
// client, cookie jar — is common setup no case has reason to vary.
func buildSampleBrowser(t *testing.T, storeOpts ...op.Option) *sampleBrowser {
	t.Helper()

	driver, err := newAppDriver()
	if err != nil {
		t.Fatalf("newAppDriver: %v", err)
	}
	keys, err := generateKeys()
	if err != nil {
		t.Fatalf("generateKeys: %v", err)
	}

	// The issuer is the listener's own address, which does not exist
	// until it is listening, so the provider is registered on the mux
	// after the server starts.
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	opts := append([]op.Option{
		op.WithIssuer(srv.URL),
		op.WithKeyset(keys.set),
		op.WithCookieKeys(keys.cookie),
		op.WithInteractionDriver(driver),
		op.WithStaticClients(op.PublicClient{
			ID:           chooserTestClientID,
			RedirectURIs: []string{chooserTestRedirect},
			Scopes:       []string{"openid", "profile", "email"},
		}),
	}, storeOpts...)
	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	mux.Handle("/", provider)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := srv.Client()
	client.Jar = jar
	// Redirects are inspected rather than followed: the last one points
	// at a redirect_uri with no listener behind it.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &sampleBrowser{t: t, base: srv.URL, client: client, verifier: oauth2.GenerateVerifier()}
}

// authorizeURL builds one authorization request against the endpoint the
// provider advertises. Each call mints a fresh state and nonce, so a
// second request is a second attempt rather than a replay.
func (b *sampleBrowser) authorizeURL() string {
	b.t.Helper()

	status, _, body := b.do(http.MethodGet, b.base+"/.well-known/openid-configuration", "", "")
	if status != http.StatusOK {
		b.t.Fatalf("discovery status = %d", status)
	}
	var doc struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		b.t.Fatalf("decode discovery: %v", err)
	}
	state, err := newOpaqueID()
	if err != nil {
		b.t.Fatalf("newOpaqueID: %v", err)
	}
	nonce, err := newOpaqueID()
	if err != nil {
		b.t.Fatalf("newOpaqueID: %v", err)
	}
	values := url.Values{
		"response_type":         {"code"},
		"client_id":             {chooserTestClientID},
		"redirect_uri":          {chooserTestRedirect},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(b.verifier)},
		"code_challenge_method": {"S256"},
	}
	return doc.AuthorizationEndpoint + "?" + values.Encode()
}

// completeFlow answers every prompt from authorizeURL onwards and returns
// the authorization code the redirect_uri received.
func (b *sampleBrowser) completeFlow(authorizeURL string) string {
	b.t.Helper()

	page, done := b.interactionPage(authorizeURL)
	if done {
		return b.code
	}
	return b.submitUntilDone(page)
}

// submitUntilDone replays the rendered page's own controls until the OP
// redirects off its host, and returns the code that redirect carried.
func (b *sampleBrowser) submitUntilDone(page string) string {
	b.t.Helper()

	for range 8 {
		target := b.pageURL
		status, header, body := b.do(http.MethodPost, target,
			"application/x-www-form-urlencoded", b.answer(page).Encode())
		switch {
		case status == http.StatusOK:
			// The endpoint answers the next prompt in the POST response
			// rather than redirecting to it, so the page changed while the
			// URL did not.
			page = body
		case status >= 300 && status < 400:
			next := header.Get("Location")
			if next == "" {
				b.t.Fatalf("POST %s returned %d with no Location", target, status)
			}
			var done bool
			if page, done = b.interactionPage(next); done {
				return b.code
			}
		default:
			b.t.Fatalf("POST %s returned %d:\n%s", target, status, body)
		}
	}
	b.t.Fatal("still being handed prompts after 8 submissions; the flow does not terminate")
	return ""
}

// interactionPage follows redirects from target until a page renders on
// the OP. It reports done=true when the OP redirected to the relying
// party's redirect_uri instead, which is how the flow ends.
func (b *sampleBrowser) interactionPage(target string) (page string, done bool) {
	b.t.Helper()

	for range 12 {
		target = b.resolve(target)
		if !strings.HasPrefix(target, b.base) {
			return "", b.finish(target)
		}
		status, header, body := b.do(http.MethodGet, target, "", "")
		switch {
		case status == http.StatusOK:
			b.pageURL = target
			return body, false
		case status >= 300 && status < 400:
			location := header.Get("Location")
			if location == "" {
				b.t.Fatalf("GET %s returned %d with no Location", target, status)
			}
			target = location
		default:
			b.t.Fatalf("GET %s returned %d:\n%s", target, status, body)
		}
	}
	b.t.Fatalf("redirect loop starting at %s", target)
	return "", false
}

// finish records the authorization code the OP handed the relying party.
// An error parameter there is the flow failing in the one place a browser
// would show nothing, so it fails the test rather than returning empty.
func (b *sampleBrowser) finish(target string) bool {
	b.t.Helper()

	u, err := url.Parse(target)
	if err != nil {
		b.t.Fatalf("parse redirect %q: %v", target, err)
	}
	if oauthErr := u.Query().Get("error"); oauthErr != "" {
		b.t.Fatalf("the OP bounced the request back to the relying party: %s (%s)",
			oauthErr, u.Query().Get("error_description"))
	}
	b.code = u.Query().Get("code")
	return true
}

// userInfo exchanges code at the token endpoint and returns the claims
// /userinfo serves for the resulting access token, so a case can check
// whose store the OP actually read rather than only that the flow reached
// a code.
func (b *sampleBrowser) userInfo(code string) map[string]any {
	b.t.Helper()

	status, _, body := b.do(http.MethodGet, b.base+"/.well-known/openid-configuration", "", "")
	if status != http.StatusOK {
		b.t.Fatalf("discovery status = %d", status)
	}
	var doc struct {
		TokenEndpoint    string `json:"token_endpoint"`
		UserInfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		b.t.Fatalf("decode discovery: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {chooserTestRedirect},
		"client_id":     {chooserTestClientID},
		"code_verifier": {b.verifier},
	}
	status, _, body = b.do(http.MethodPost, doc.TokenEndpoint,
		"application/x-www-form-urlencoded", form.Encode())
	if status != http.StatusOK {
		b.t.Fatalf("token endpoint status = %d: %s", status, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil {
		b.t.Fatalf("decode token response: %v", err)
	}

	req, err := http.NewRequestWithContext(b.t.Context(), http.MethodGet, doc.UserInfoEndpoint, nil)
	if err != nil {
		b.t.Fatalf("build userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("GET userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatalf("read userinfo response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		b.t.Fatalf("userinfo status = %d: %s", resp.StatusCode, raw)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		b.t.Fatalf("decode userinfo claims: %v", err)
	}
	return claims
}

var (
	// controlRE matches the submittable controls the sample's templates
	// emit. The chooser carries session_id on a button rather than an
	// input, so buttons are read too.
	controlRE = regexp.MustCompile(`<(?:input|button)\b[^>]*>`)
	attrRE    = regexp.MustCompile(`([a-zA-Z_-]+)="([^"]*)"`)
)

// answer turns a rendered page into the POST that answers it. Replaying
// every control the page carries — rather than naming fields per prompt —
// is what lets one helper answer the login form, the consent screen and
// the chooser alike.
func (b *sampleBrowser) answer(page string) url.Values {
	form := url.Values{}
	for _, tag := range controlRE.FindAllString(page, -1) {
		// A disabled control is not submitted by a browser. The consent
		// page disables the checkbox of a scope that cannot be declined
		// and pairs it with a hidden field carrying the same value, so
		// honouring disabled is what keeps that value from arriving twice.
		if strings.Contains(tag, " disabled") {
			continue
		}
		attrs := map[string]string{}
		for _, m := range attrRE.FindAllStringSubmatch(tag, -1) {
			attrs[m[1]] = html.UnescapeString(m[2])
		}
		name := attrs["name"]
		switch name {
		case "":
			// A control the browser would not submit either.
		case scopeCheckboxField:
			// The consent page asks scope by scope and renders every box
			// checked, so approving everything is replaying them all.
			form.Add(name, attrs["value"])
		default:
			form.Set(name, attrs["value"])
		}
	}
	if _, ok := form["username"]; ok {
		form.Set("username", chooserTestEmail)
	}
	if _, ok := form["password"]; ok {
		form.Set("password", chooserTestPassword)
	}
	return form
}

// resolve turns a possibly-relative Location into an absolute URL.
func (b *sampleBrowser) resolve(target string) string {
	b.t.Helper()

	base, err := url.Parse(b.base)
	if err != nil {
		b.t.Fatalf("parse base %q: %v", b.base, err)
	}
	ref, err := url.Parse(target)
	if err != nil {
		b.t.Fatalf("parse target %q: %v", target, err)
	}
	return base.ResolveReference(ref).String()
}

// do issues one request. The interaction endpoint pairs its double-submit
// token with an Origin check, so every request states the origin the
// pages were served from.
func (b *sampleBrowser) do(method, target, contentType, body string) (int, http.Header, string) {
	b.t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(b.t.Context(), method, target, reader)
	if err != nil {
		b.t.Fatalf("build %s %s: %v", method, target, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Origin", b.base)
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatalf("read %s %s: %v", method, target, err)
	}
	return resp.StatusCode, resp.Header, string(raw)
}

//go:build apiverify

package apiverify

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The chooser examples promise a two-account picker, and the picker is
// the only part of them a smoke test cannot reach by accident: it does
// not exist until a browser holds a session, and a second account joins
// the group only by following the chooser's own add-account link. A
// probe that stops at the login prompt therefore asserts the
// precondition and never the deliverable — which is how a default
// surface that could not render the chooser at all stayed shipped.
//
// This file drives the walkthrough each example's header doc describes,
// end to end, carrying cookies by hand because the demo listeners are
// plain HTTP and a cookiejar drops the Secure cookies the OP sets.

// exampleUser is one demo credential pair an example seeds.
type exampleUser struct {
	username string
	password string
	// subject is what the chooser must show for this account once the
	// account is in the group. The examples seed a "name" claim, so the
	// rendered label is the display name rather than the raw subject.
	label string
}

// promptSubmitter turns a rendered prompt into the next POST. The two
// chooser examples render through different drivers — 12 through the
// bundled HTML one, 13 through JSONDriver — so the hop sequence is
// shared and only the encoding differs.
type promptSubmitter interface {
	// submit builds the request body answering page. creds is the
	// account to sign in as; a prompt that is not a login (consent)
	// ignores it.
	submit(t *testing.T, page string, creds exampleUser) (contentType, body string, headers map[string]string)
	// chooserSubjects returns the account labels page lists, and
	// whether page is a chooser at all.
	chooserSubjects(page string) (labels []string, ok bool)
	// addAccountURL returns the add-account link the chooser rendered.
	addAccountURL(page string) string
}

// browser is a hand-rolled cookie-carrying client. net/http/cookiejar
// refuses to store the OP's Secure cookies over the examples' plain
// HTTP listener, so the jar is a plain map and every request replays
// whatever the OP last set.
type browser struct {
	t       *testing.T
	base    string
	cookies map[string]string
	client  *http.Client
	// pageURL is the absolute URL of the most recent 200 page, which is
	// where that page's form posts back to.
	pageURL string
}

func newBrowser(t *testing.T, baseURL string) *browser {
	t.Helper()
	return &browser{
		t:       t,
		base:    baseURL,
		cookies: map[string]string{},
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Redirects are inspected, not followed: the OP bounces
			// through its own endpoints and finally to a redirect_uri
			// with no listener behind it.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// do issues one request with the accumulated cookies attached, records
// any the response sets, and returns status, headers and body.
func (b *browser) do(method, target, contentType, body string, headers map[string]string) (int, http.Header, string) {
	b.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(b.t.Context(), method, b.resolve(target), reader)
	if err != nil {
		b.t.Fatalf("build %s %s: %v", method, target, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// The interaction endpoint enforces an Origin check alongside the
	// double-submit token, so a same-origin POST has to say so.
	req.Header.Set("Origin", b.base)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for name, value := range b.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
			continue
		}
		b.cookies[c.Name] = c.Value
	}
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(raw)
}

// resolve turns a possibly-relative Location into an absolute URL on
// the example's listener.
func (b *browser) resolve(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
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

// onOP reports whether target still points at the example's listener.
// The walkthrough ends when the OP redirects to the RP's callback,
// which has no listener behind it.
func (b *browser) onOP(target string) bool {
	base, err := url.Parse(b.base)
	if err != nil {
		return false
	}
	ref, err := url.Parse(target)
	if err != nil {
		return false
	}
	return ref.Host == "" || ref.Host == base.Host
}

// interactionPageAt follows redirects starting at target until it
// reaches a 200 page on the OP, and returns that page. A redirect off
// the OP (the RP callback) returns ok=false, which is how the driver
// recognises "the authorization completed".
func (b *browser) interactionPageAt(target string) (page string, ok bool) {
	b.t.Helper()
	for range 12 {
		if !b.onOP(target) {
			return "", false
		}
		status, header, body := b.do(http.MethodGet, target, "", "", nil)
		switch {
		case status == http.StatusOK:
			b.pageURL = b.resolve(target)
			return body, true
		case status >= 300 && status < 400:
			location := header.Get("Location")
			if location == "" {
				b.t.Fatalf("GET %s returned %d with no Location", target, status)
			}
			if oauthError(b.t, location) != "" {
				b.t.Fatalf("the OP bounced %q back to the RP: %s", oauthError(b.t, location), location)
			}
			target = location
		default:
			b.t.Fatalf("GET %s returned %d:\n%s", target, status, body)
		}
	}
	b.t.Fatalf("redirect loop starting at %s", target)
	return "", false
}

// oauthError reports the OAuth error parameter on a redirect back to
// the relying party, if any.
func oauthError(t *testing.T, location string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return u.Query().Get("error")
}

// signIn answers every interaction the OP presents — the login prompt
// and the consent screen behind it — until the authorization completes
// by redirecting off the OP.
func (b *browser) signIn(authorizeURL string, submit promptSubmitter, creds exampleUser) {
	b.t.Helper()
	page, ok := b.interactionPageAt(authorizeURL)
	if !ok {
		b.t.Fatalf("/authorize completed without presenting an interaction; %q was never signed in", creds.username)
	}
	for range 8 {
		current := b.pageURL
		contentType, body, headers := submit.submit(b.t, page, creds)
		status, header, respBody := b.do(http.MethodPost, current, contentType, body, headers)
		switch {
		case status == http.StatusOK:
			// The endpoint answers the next prompt in the POST response
			// rather than redirecting to it, so the page changed while
			// the URL did not.
			page = respBody
		case status >= 300 && status < 400:
			next := header.Get("Location")
			if next == "" {
				b.t.Fatalf("prompt submission returned %d with no Location", status)
			}
			if page, ok = b.interactionPageAt(next); !ok {
				return
			}
		default:
			b.t.Fatalf("submitting the prompt at %s returned %d:\n%s", current, status, respBody)
		}
	}
	b.t.Fatalf("still being handed interactions after 8 submissions; the flow does not terminate")
}

// runChooserAddAccountFlow boots the example and drives the walkthrough
// its header doc promises: sign in as the first account, ask for
// prompt=select_account, follow the chooser's own add-account link to
// sign in as the second, then ask again. The assertion is on the second
// chooser render — one prompt listing both accounts — because that is
// the example's headline deliverable and the only state that proves the
// add-account link did what the doc says it does.
func runChooserAddAccountFlow(t *testing.T, dir, baseURL string, params url.Values, submit promptSubmitter, first, second exampleUser) {
	t.Helper()
	p := buildAndStart(t, dir)
	defer p.kill()

	doc := pollHTTP(t, p, baseURL+"/.well-known/openid-configuration", 20*time.Second)
	authorize := discoveryEndpointPath(t, doc, "authorization_endpoint")

	b := newBrowser(t, baseURL)
	b.signIn(baseURL+authorize+"?"+params.Encode(), submit, first)

	selectAccount := cloneParams(params)
	selectAccount.Set("prompt", "select_account")
	page, ok := b.interactionPageAt(baseURL + authorize + "?" + selectAccount.Encode())
	if !ok {
		t.Fatalf("prompt=select_account completed without rendering a chooser:\n%s", p.readLog())
	}
	labels, isChooser := submit.chooserSubjects(page)
	if !isChooser {
		t.Fatalf("prompt=select_account rendered something that is not a chooser:\n%s", page)
	}
	if len(labels) != 1 {
		t.Fatalf("the first chooser lists %d account(s) %v, want exactly 1 (%q):\n%s",
			len(labels), labels, first.label, page)
	}

	addAccount := submit.addAccountURL(page)
	if addAccount == "" {
		t.Fatalf("the chooser rendered no add-account link, so the second account can never join the group:\n%s", page)
	}
	b.signIn(addAccount, submit, second)

	page, ok = b.interactionPageAt(baseURL + authorize + "?" + selectAccount.Encode())
	if !ok {
		t.Fatalf("the second prompt=select_account completed without rendering a chooser:\n%s", p.readLog())
	}
	labels, isChooser = submit.chooserSubjects(page)
	if !isChooser {
		t.Fatalf("the second prompt=select_account rendered something that is not a chooser:\n%s", page)
	}
	if len(labels) != 2 {
		t.Fatalf("after following the add-account link the chooser lists %d account(s) %v, want both %q and %q "+
			"in one prompt:\n%s", len(labels), labels, first.label, second.label, page)
	}
	for _, want := range []string{first.label, second.label} {
		if !containsLabel(labels, want) {
			t.Errorf("the chooser does not offer %q; rendered labels were %v:\n%s", want, labels, page)
		}
	}
}

// cloneParams copies v so a variant request can add prompt= without
// mutating the caller's values.
func cloneParams(v url.Values) url.Values {
	out := url.Values{}
	for key, values := range v {
		out[key] = append([]string(nil), values...)
	}
	return out
}

// containsLabel reports whether any rendered row names want. The match
// is by substring because the two examples wrap the label differently —
// 12's template renders "Continue as <name>" inside the button, the
// JSON envelope carries the name on its own — and the claim under test
// is that the account is offered, not how the row is phrased.
func containsLabel(labels []string, want string) bool {
	for _, got := range labels {
		if strings.Contains(got, want) {
			return true
		}
	}
	return false
}

// htmlSubmitter answers the bundled HTML driver's pages by replaying
// every input the form rendered, with the credential fields filled in.
// Serialising the whole form rather than naming fields per prompt is
// what lets one submitter answer both the login page and the consent
// page, whose only field is a hidden approved_scopes.
type htmlSubmitter struct{}

var (
	htmlInputRE      = regexp.MustCompile(`<input\b[^>]*>`)
	htmlAttrRE       = regexp.MustCompile(`(\w+)="([^"]*)"`)
	htmlButtonTextRE = regexp.MustCompile(`<button\b[^>]*>([^<]*)</button>`)
	htmlAnchorRE     = regexp.MustCompile(`<a\b[^>]*href="([^"]*)"`)
)

func htmlInputs(page string) map[string]string {
	out := map[string]string{}
	for _, tag := range htmlInputRE.FindAllString(page, -1) {
		attrs := map[string]string{}
		for _, m := range htmlAttrRE.FindAllStringSubmatch(tag, -1) {
			attrs[m[1]] = m[2]
		}
		if name := attrs["name"]; name != "" {
			out[name] = htmlUnescape(attrs["value"])
		}
	}
	return out
}

// htmlUnescape decodes HTML entities. The standard decoder is used
// rather than a five-entity replacer because html/template escapes URL
// attributes with numeric references too ("+" becomes "&#43;"), and an
// add-account link carrying a literal "&#43;" in its scope parameter is
// a different request than the one the chooser rendered.
func htmlUnescape(s string) string { return html.UnescapeString(s) }

func (htmlSubmitter) submit(t *testing.T, page string, creds exampleUser) (string, string, map[string]string) {
	t.Helper()
	form := url.Values{}
	for name, value := range htmlInputs(page) {
		form.Set(name, value)
	}
	if _, ok := form["username"]; ok {
		form.Set("username", creds.username)
	}
	if _, ok := form["password"]; ok {
		form.Set("password", creds.password)
	}
	if form.Get("state_ref") == "" {
		t.Fatalf("rendered page carries no state_ref to continue from:\n%s", page)
	}
	return "application/x-www-form-urlencoded", form.Encode(), nil
}

// chooserSubjects reads one label per pickable account. It anchors on
// the session_id control rather than on a fixed markup shape, because
// the two HTML chooser renders differ: the bundled driver puts the
// field on the submit button itself, while an embedder template
// (example 12's) carries it as a hidden input beside a plain button.
// Anchoring on the field and taking the next button's text reads both,
// and reads any third shape an embedder writes.
func (htmlSubmitter) chooserSubjects(page string) ([]string, bool) {
	var labels []string
	for _, index := range sessionIDFieldOffsets(page) {
		// Scan from the start of the tag the field sits in, not from the
		// field itself. In the bundled driver's markup the field IS an
		// attribute of the button, so a scan starting mid-tag looks for
		// the NEXT button and finds either the following account's or
		// none at all; starting at the tag makes the enclosing button the
		// leftmost match. An embedder template that puts the field on a
		// preceding hidden input is unaffected — no button begins at that
		// offset, so the search still lands on the one that follows.
		m := htmlButtonTextRE.FindStringSubmatch(page[enclosingTagStart(page, index):])
		if m == nil {
			continue
		}
		labels = append(labels, strings.TrimSpace(htmlUnescape(m[1])))
	}
	return labels, strings.Contains(page, sessionIDFieldMarker)
}

// enclosingTagStart returns the offset of the "<" opening the tag that
// contains index, or index itself when the page has no earlier "<".
func enclosingTagStart(page string, index int) int {
	if start := strings.LastIndex(page[:index], "<"); start >= 0 {
		return start
	}
	return index
}

const sessionIDFieldMarker = `name="session_id"`

// sessionIDFieldOffsets lists where each account's session_id control
// starts.
func sessionIDFieldOffsets(page string) []int {
	var out []int
	for offset := 0; ; {
		i := strings.Index(page[offset:], sessionIDFieldMarker)
		if i < 0 {
			return out
		}
		out = append(out, offset+i)
		offset += i + len(sessionIDFieldMarker)
	}
}

func (htmlSubmitter) addAccountURL(page string) string {
	m := htmlAnchorRE.FindStringSubmatch(page)
	if m == nil {
		return ""
	}
	return htmlUnescape(m[1])
}

// jsonSubmitter answers JSONDriver's envelopes. The CSRF token travels
// in the envelope rather than a form field, because the cookie half of
// the double-submit pair is HttpOnly.
type jsonSubmitter struct{}

type jsonPrompt struct {
	Type      string `json:"type"`
	StateRef  string `json:"state_ref"`
	CSRFToken string `json:"csrf_token"`
	Inputs    []struct {
		Name string `json:"name"`
	} `json:"inputs"`
	Data struct {
		Accounts []struct {
			Subject     string
			DisplayName string
		}
		AddAccountURL string
		Scopes        []struct{ Name string }
	} `json:"data"`
}

func decodeJSONPrompt(t *testing.T, page string) jsonPrompt {
	t.Helper()
	var prompt jsonPrompt
	if err := json.Unmarshal([]byte(page), &prompt); err != nil {
		t.Fatalf("decode prompt envelope: %v\n%s", err, page)
	}
	return prompt
}

func (jsonSubmitter) submit(t *testing.T, page string, creds exampleUser) (string, string, map[string]string) {
	t.Helper()
	prompt := decodeJSONPrompt(t, page)
	values := map[string]string{}
	for _, in := range prompt.Inputs {
		switch in.Name {
		case "username":
			values["username"] = creds.username
		case "password":
			values["password"] = creds.password
		case "approved_scopes":
			names := make([]string, 0, len(prompt.Data.Scopes))
			for _, s := range prompt.Data.Scopes {
				names = append(names, s.Name)
			}
			values["approved_scopes"] = strings.Join(names, " ")
		}
	}
	body, err := json.Marshal(map[string]any{"state_ref": prompt.StateRef, "values": values})
	if err != nil {
		t.Fatalf("marshal submission: %v", err)
	}
	return "application/json", string(body), map[string]string{"X-CSRF-Token": prompt.CSRFToken}
}

func (jsonSubmitter) chooserSubjects(page string) ([]string, bool) {
	var prompt jsonPrompt
	if err := json.Unmarshal([]byte(page), &prompt); err != nil {
		return nil, false
	}
	if prompt.Type != "interaction.chooser" {
		return nil, false
	}
	labels := make([]string, 0, len(prompt.Data.Accounts))
	for _, a := range prompt.Data.Accounts {
		label := a.DisplayName
		if label == "" {
			label = a.Subject
		}
		labels = append(labels, label)
	}
	return labels, true
}

func (jsonSubmitter) addAccountURL(page string) string {
	var prompt jsonPrompt
	if err := json.Unmarshal([]byte(page), &prompt); err != nil {
		return ""
	}
	return prompt.Data.AddAccountURL
}

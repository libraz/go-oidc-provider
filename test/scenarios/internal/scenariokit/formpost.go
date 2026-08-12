package scenariokit

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

// FormPostResponse is a captured OIDC Form Post Response Mode 1.0
// delivery. Unlike the redirect modes there is no Location header to
// parse: the OP answers with an HTML body that auto-submits a form to
// redirect_uri, so the response parameters ride in hidden inputs and
// the escaping of the interpolated values is itself part of the
// contract. Tests therefore assert on the raw bytes as well as on the
// decoded fields.
type FormPostResponse struct {
	// StatusCode is the status of the delivering response. Form post
	// delivers success and error responses alike as 200 — the body is a
	// successful delivery of an authorization response, whatever that
	// response says.
	StatusCode int

	// Header is the response header set, preserved so callers can
	// assert on Content-Security-Policy / Content-Type / Cache-Control.
	Header http.Header

	// Body is the verbatim HTML body.
	Body string
}

// RunFormPostFlow drives the same hops as [RunCodeFlow] against an
// /authorize request that selected response_mode=form_post, and
// returns the terminal HTML delivery instead of a parsed callback URL.
//
// method selects the /authorize verb: an empty value or http.MethodGet
// sends the parameters as a query string, http.MethodPost sends them as
// an application/x-www-form-urlencoded body. Both are mandatory for the
// authorization endpoint (RFC 6749 §3.1), and driving them through one
// helper is what lets a test assert the two agree.
//
// The helper stops at whatever the OP answers with. When /authorize
// itself terminates the request — a prompt=none error, for instance —
// that first response is the delivery; when the OP inserts an
// interaction, the delivery is the response to the final interaction
// hop. A non-200 status is passed through rather than failed on, so
// error-path scenarios can assert on it.
func RunFormPostFlow(tb testing.TB, p *testkit.Provider, method, subject string, params AuthorizeParams) FormPostResponse {
	tb.Helper()
	if subject == "" {
		subject = DefaultSubject
	}
	client := mustClient(tb, p)
	authResp := requestAuthorize(tb, client, p, method, params)
	defer func() { _ = authResp.Body.Close() }()
	if authResp.StatusCode != http.StatusFound {
		return captureFormPost(tb, authResp)
	}
	location, err := authResp.Location()
	if err != nil {
		tb.Fatalf("scenariokit: /authorize Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		tb.Fatalf("scenariokit: /authorize Location=%s, want /oidc/interaction/...", location.String())
	}
	final := completeInteraction(tb, client, p.Server.URL+location.Path, p.Issuer, subject)
	defer func() { _ = final.Body.Close() }()
	return captureFormPost(tb, final)
}

// FormAction returns the value of the form's action attribute exactly
// as it appears on the wire, i.e. still HTML-escaped. Callers that want
// the decoded URI run it through html.UnescapeString; the escaped form
// is what an XSS-escaping assertion needs to see.
func (f FormPostResponse) FormAction(tb testing.TB) string {
	tb.Helper()
	// The body shape is fixed by the OP's emitter (internal/jarm), so a
	// pattern match is enough and avoids pulling in an HTML parser.
	m := regexp.MustCompile(`<form method="post" action="([^"]*)">`).FindStringSubmatch(f.Body)
	if m == nil {
		tb.Fatalf("scenariokit: form action not found in body: %s", f.Body)
	}
	return m[1]
}

// Inputs returns the form's hidden inputs as decoded name/value pairs.
// Both halves are run through html.UnescapeString so the caller sees
// the parameter values the browser would submit; assertions about the
// escaping itself read [FormPostResponse.Body] directly.
func (f FormPostResponse) Inputs(tb testing.TB) url.Values {
	tb.Helper()
	matches := regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)" />`).
		FindAllStringSubmatch(f.Body, -1)
	if matches == nil {
		tb.Fatalf("scenariokit: no hidden inputs found in body: %s", f.Body)
	}
	out := url.Values{}
	for _, m := range matches {
		out.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return out
}

// requestAuthorize issues the /authorize hop with the given method,
// without following redirects.
func requestAuthorize(tb testing.TB, client *http.Client, p *testkit.Provider, method string, params AuthorizeParams) *http.Response {
	tb.Helper()
	encoded := params.Values().Encode()
	if method == "" || method == http.MethodGet {
		return mustGet(tb, client, p.Server.URL+"/oidc/auth?"+encoded)
	}
	if method != http.MethodPost {
		tb.Fatalf("scenariokit: unsupported /authorize method %q", method)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.Server.URL+"/oidc/auth", strings.NewReader(encoded))
	if err != nil {
		tb.Fatalf("scenariokit: build POST /authorize: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("scenariokit: POST /authorize: %v", err)
	}
	return resp
}

// captureFormPost drains resp into a [FormPostResponse]. Closing the
// body stays with the caller, matching the rest of the package.
func captureFormPost(tb testing.TB, resp *http.Response) FormPostResponse {
	tb.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("scenariokit: read form_post body: %v", err)
	}
	return FormPostResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       string(body),
	}
}

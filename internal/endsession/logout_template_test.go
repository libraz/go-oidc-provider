package endsession_test

import (
	"context"
	"errors"
	"html"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/endsession"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

const strictLogoutCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; sandbox allow-forms allow-same-origin"

const (
	brandedConfirmSrc = `<html lang="{{.Locale}}"><body>BRANDED-CONFIRM<h1>{{.Title}}</h1><p>{{.Body}}</p>` +
		`<form method="{{.SubmitMethod}}" action="{{.SubmitAction}}">` +
		`{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}` +
		`<button>{{.Button}}</button></form></body></html>`
	brandedSignedOutSrc = `<html lang="{{.Locale}}"><body>BRANDED-SIGNEDOUT<h1>{{.Title}}</h1><p>{{.Body}}</p></body></html>`
)

// mountVariant returns a clone of h whose handler is built from h.deps
// after mutate has adjusted them.
func mountVariant(h *harness, mutate func(*endsession.Deps)) *harness {
	deps := h.deps
	mutate(&deps)
	mux := http.NewServeMux()
	mux.Handle(h.endSessionPath, endsession.Handler(deps))
	clone := *h
	clone.deps = deps
	clone.handler = mux
	return &clone
}

func brandedHarness(t *testing.T, csp string) *harness {
	t.Helper()
	confirm := template.Must(template.New("confirm").Parse(brandedConfirmSrc))
	signedOut := template.Must(template.New("signedout").Parse(brandedSignedOutSrc))
	return mountVariant(newHarness(t), func(d *endsession.Deps) {
		d.ConfirmTemplate = confirm
		d.SignedOutTemplate = signedOut
		d.LogoutCSP = csp
	})
}

var hiddenInputRE = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)

func TestLogoutTemplate_ConfirmRoundTrip(t *testing.T) {
	t.Parallel()

	h := brandedHarness(t, "")
	sessionCookie, sessionID := h.issueSession(t)
	getResp := h.doGET(t, url.Values{
		"client_id":                {h.clientID},
		"post_logout_redirect_uri": {h.postLogoutURI},
		"state":                    {"st-1"},
	}, sessionCookie)
	body := readBody(t, getResp)
	if getResp.StatusCode != http.StatusOK || !strings.Contains(body, "BRANDED-CONFIRM") {
		t.Fatalf("status=%d, template not rendered: %s", getResp.StatusCode, body)
	}
	token := readConfirmCookie(getResp)
	if token == "" {
		t.Fatal("confirmation cookie not set")
	}

	form := url.Values{}
	matches := hiddenInputRE.FindAllStringSubmatch(body, -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		form.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
		names = append(names, m[1])
	}
	if len(names) == 0 || names[0] != "logout_csrf" {
		t.Fatalf("Fields = %v, want logout_csrf first", names)
	}
	if form.Get("logout_csrf") != token {
		t.Errorf("logout_csrf field does not match the cookie token")
	}

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, h.endSessionPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://op.example.com")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessionCookie})
	r.AddCookie(&http.Cookie{Name: cookie.LogoutCSRFProfile.Name, Value: token})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST status=%d want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if loc.Host != "rp.example.com" || loc.Path != "/post-logout" || loc.Query().Get("state") != "st-1" {
		t.Errorf("Location = %q", resp.Header.Get("Location"))
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err == nil {
		t.Error("session survived a confirmed logout")
	}
}

func TestLogoutTemplate_SignedOut(t *testing.T) {
	t.Parallel()

	h := brandedHarness(t, "")
	sessionCookie, _ := h.issueSession(t)
	resp := h.doGET(t, url.Values{"id_token_hint": {h.signIDToken(t, nil)}}, sessionCookie)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200: %s", resp.StatusCode, body)
	}
	for _, want := range []string{"BRANDED-SIGNEDOUT", "You&#39;re signed out", "You can close this window."} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q: %s", want, body)
		}
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy = %q, want same-origin", got)
	}
}

func TestLogoutTemplate_ExecuteFailure500(t *testing.T) {
	t.Parallel()

	failing := template.Must(template.New("boom").
		Funcs(template.FuncMap{"boom": func() (string, error) { return "", errors.New("boom") }}).
		Parse("PARTIAL-OUTPUT{{boom}}"))
	h := mountVariant(newHarness(t), func(d *endsession.Deps) {
		d.ConfirmTemplate = failing
		d.SignedOutTemplate = failing
	})
	sessionCookie, _ := h.issueSession(t)

	for name, values := range map[string]url.Values{
		"confirm":    {},
		"signed_out": {"id_token_hint": {h.signIDToken(t, nil)}},
	} {
		resp := h.doGET(t, values, sessionCookie)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s: status=%d want 500", name, resp.StatusCode)
		}
		if strings.Contains(body, "PARTIAL-OUTPUT") || !strings.Contains(body, "Sign-out failed") {
			t.Errorf("%s: body = %q, want the fixed error page only", name, body)
		}
	}
}

func TestLogoutTemplate_DeclaredCSPOrDefault(t *testing.T) {
	t.Parallel()

	declared := "default-src 'none'; style-src 'self'"
	normalized, err := interaction.NormalizeCSP(declared)
	if err != nil {
		t.Fatalf("NormalizeCSP: %v", err)
	}
	rows := []struct {
		name string
		csp  string
		want string
	}{
		{name: "declared", csp: normalized, want: normalized},
		{name: "empty keeps strict default", csp: "", want: strictLogoutCSP},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			h := brandedHarness(t, row.csp)
			sessionCookie, _ := h.issueSession(t)
			for page, values := range map[string]url.Values{
				"confirm":    {},
				"signed_out": {"id_token_hint": {h.signIDToken(t, nil)}},
			} {
				resp := h.doGET(t, values, sessionCookie)
				_ = readBody(t, resp)
				if got := resp.Header.Get("Content-Security-Policy"); got != row.want {
					t.Errorf("%s: CSP = %q, want %q", page, got, row.want)
				}
				if got := resp.Header.Get("Referrer-Policy"); got != "same-origin" {
					t.Errorf("%s: Referrer-Policy = %q", page, got)
				}
			}
		})
	}
}

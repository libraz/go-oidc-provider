package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

// reauthSubject is the subject every fixture in this file authenticates.
const reauthSubject = "user-reauth"

// reauthDriver bundles the multi-hop browser steps the freshness tests
// share: start an /authorize, walk whatever interaction it redirects
// to, and exchange the resulting code.
type reauthDriver struct {
	t   *testing.T
	fix *flowFixture
	cl  *http.Client
}

func newReauthDriver(t *testing.T, fix *flowFixture) *reauthDriver {
	t.Helper()
	return &reauthDriver{t: t, fix: fix, cl: fix.httpClient(t)}
}

// authorize issues GET /authorize with the supplied extra query
// parameters and returns the redirect target.
func (d *reauthDriver) authorize(extra url.Values) *url.URL {
	d.t.Helper()
	v := e2eAuthorizeValues(d.fix.client.ID, d.fix.client.RedirectURIs[0])
	for k, vals := range extra {
		v[k] = vals
	}
	resp, err := newGet(d.fix.server.URL + "/oidc/auth?" + v.Encode()).Do(d.cl)
	if err != nil {
		d.t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		d.t.Fatalf("authorize status=%d body=%s", resp.StatusCode, string(dump))
	}
	loc, err := resp.Location()
	if err != nil {
		d.t.Fatalf("authorize Location: %v", err)
	}
	return loc
}

// firstPrompt fetches the interaction page and returns the decoded
// prompt envelope plus the CSRF cookie value. It fails the test when
// the interaction has already terminated — which is precisely the
// symptom a factor-less chain produces.
func (d *reauthDriver) firstPrompt(path string) (map[string]any, string) {
	d.t.Helper()
	resp, err := newGet(d.fix.server.URL + path).Do(d.cl)
	if err != nil {
		d.t.Fatalf("GET interaction: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc, _ := resp.Location()
		d.t.Fatalf("interaction terminated without emitting a prompt (redirect to %v)", loc)
	}
	env := decodeMap(d.t, resp)
	if promptType, _ := env["type"].(string); promptType == "" {
		d.t.Fatalf("interaction emitted no prompt: status=%d envelope=%v", resp.StatusCode, env)
	}
	csrf := findCookie(resp.Cookies(), "__Host-oidc_csrf")
	if csrf == nil {
		d.t.Fatalf("csrf cookie missing on prompt %v", env["type"])
	}
	return env, csrf.Value
}

// submit posts values against the supplied state_ref and returns the
// raw response.
func (d *reauthDriver) submit(path, csrf, stateRef string, values map[string]string) *http.Response {
	d.t.Helper()
	raw, err := json.Marshal(map[string]any{"state_ref": stateRef, "values": values})
	if err != nil {
		d.t.Fatalf("marshal submission: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		d.fix.server.URL+path, bytes.NewReader(raw))
	if err != nil {
		d.t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", d.fix.issuer)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_csrf", Value: csrf})
	resp, err := d.cl.Do(req)
	if err != nil {
		d.t.Fatalf("POST interaction: %v", err)
	}
	return resp
}

// completeCredentialLogin walks a login interaction to its RP redirect
// and returns that redirect. advanceBeforeSubmit is applied to the
// fixture clock after the prompt is rendered and before the credential
// is submitted, so the returned auth_time can be told apart from the
// interaction's creation time.
func (d *reauthDriver) completeCredentialLogin(path string, advanceBeforeSubmit time.Duration) *url.URL {
	d.t.Helper()
	env, csrf := d.firstPrompt(path)
	if got, _ := env["type"].(string); got != testkit.SubjectPromptType {
		d.t.Fatalf("first prompt type=%q want %q (the credential factor never ran)", got, testkit.SubjectPromptType)
	}
	stateRef, _ := env["state_ref"].(string)
	if advanceBeforeSubmit > 0 {
		d.fix.clock.Advance(advanceBeforeSubmit)
	}
	resp := d.submit(path, csrf, stateRef, map[string]string{testkit.SubjectFieldName: reauthSubject})
	defer resp.Body.Close()
	final := completeConsentIfPrompted(d.t, d.cl, d.fix.server.URL+path, d.fix.issuer, csrf, resp)
	defer final.Body.Close()
	if final.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(final.Body)
		d.t.Fatalf("interaction final status=%d body=%s", final.StatusCode, string(dump))
	}
	loc, err := final.Location()
	if err != nil {
		d.t.Fatalf("final Location: %v", err)
	}
	return loc
}

// exchange redeems code at /token and returns the id_token claims.
func (d *reauthDriver) exchange(code string) map[string]any {
	d.t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {d.fix.client.RedirectURIs[0]},
		"code_verifier": {e2eVerifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		d.fix.server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		d.t.Fatalf("NewRequest token: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(d.fix.client.ID, d.fix.secret)
	resp, err := d.cl.Do(req)
	if err != nil {
		d.t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		d.t.Fatalf("token status=%d body=%s", resp.StatusCode, string(dump))
	}
	body := decodeMap(d.t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		d.t.Fatalf("id_token missing: %v", body)
	}
	return decodeIDTokenPayload(d.t, idt)
}

// codeFrom extracts the authorization code from an RP redirect.
func (d *reauthDriver) codeFrom(loc *url.URL) string {
	d.t.Helper()
	code := loc.Query().Get("code")
	if code == "" {
		d.t.Fatalf("no code in %s", loc.String())
	}
	return code
}

// TestEndToEnd_PromptLoginRunsPrimaryWithLiveSession asserts that a
// request carrying a valid session cookie plus prompt=login re-runs the
// credential factor instead of terminating on the subject the cookie
// already carries.
//
// Both authentication surfaces run the same script: an inherited
// subject identifies the user, it does not stand in for a credential,
// and that has to hold whichever seam the embedder wired.
//
// The assertions are (a) the interaction emits the credential prompt
// rather than redirecting straight back to the RP, (b) the issued
// id_token's auth_time is the moment the credential was submitted —
// not the moment the interaction record was created — and (c) amr is
// present, which it cannot be for a chain that ran no factor.
func TestEndToEnd_PromptLoginRunsPrimaryWithLiveSession(t *testing.T) {
	t.Parallel()
	for _, surface := range []authnSurface{surfaceLoginFlow, surfaceAuthenticators} {
		t.Run(surface.String(), func(t *testing.T) {
			t.Parallel()
			start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
			fix := newFlowFixture(t, surface, newMovableClock(start))
			d := newReauthDriver(t, fix)

			// Pass 1 establishes the session.
			loc1 := d.authorize(nil)
			if loc1.Query().Get("code") != "" {
				t.Fatalf("pass 1 expected an interaction redirect, got a code: %s", loc1)
			}
			claims1 := d.exchange(d.codeFrom(d.completeCredentialLogin(loc1.Path, 0)))
			firstAuthTime, _ := claims1["auth_time"].(float64)
			if firstAuthTime == 0 {
				t.Fatalf("pass 1 id_token has no auth_time: %v", claims1)
			}

			// Pass 2 re-authenticates. The clock moves on both sides of
			// the prompt so the honest auth_time and the forged one
			// (interaction creation time) are distinct values.
			fix.clock.Advance(30 * time.Minute)
			loc2 := d.authorize(url.Values{"prompt": {"login"}})
			if loc2.Query().Get("code") != "" {
				t.Fatalf("prompt=login produced a code without an interaction: %s", loc2)
			}
			interactionCreated := fix.clock.Now()
			redirect := d.completeCredentialLogin(loc2.Path, 7*time.Minute)
			claims2 := d.exchange(d.codeFrom(redirect))

			authTime, _ := claims2["auth_time"].(float64)
			if authTime == firstAuthTime {
				t.Errorf("auth_time did not move: still the pass-1 session value %v", authTime)
			}
			if want := interactionCreated.Add(7 * time.Minute).Unix(); int64(authTime) != want {
				t.Errorf("auth_time=%d want %d (the moment the credential was submitted, not %d)",
					int64(authTime), want, interactionCreated.Unix())
			}
			amr, ok := claims2["amr"].([]any)
			if !ok || len(amr) == 0 {
				t.Errorf("amr=%v want a non-empty list; a chain that ran no factor cannot produce one", claims2["amr"])
			}
		})
	}
}

// TestEndToEnd_MaxAgeRunsPrimaryWithLiveSession is the max_age analogue
// of the prompt=login case: a session older than max_age must not be
// reused, and the resulting id_token must carry the fresh auth_time.
func TestEndToEnd_MaxAgeRunsPrimaryWithLiveSession(t *testing.T) {
	t.Parallel()
	for _, surface := range []authnSurface{surfaceLoginFlow, surfaceAuthenticators} {
		t.Run(surface.String(), func(t *testing.T) {
			t.Parallel()
			start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
			fix := newFlowFixture(t, surface, newMovableClock(start))
			d := newReauthDriver(t, fix)

			loc1 := d.authorize(nil)
			d.exchange(d.codeFrom(d.completeCredentialLogin(loc1.Path, 0)))

			// The session is now 72 hours old; max_age=60 cannot be
			// served from it.
			fix.clock.Advance(72 * time.Hour)
			loc2 := d.authorize(url.Values{"max_age": {"60"}})
			if loc2.Query().Get("code") != "" {
				t.Fatalf("max_age=60 against a 72h-old session produced a code: %s", loc2)
			}
			created := fix.clock.Now()
			claims := d.exchange(d.codeFrom(d.completeCredentialLogin(loc2.Path, 5*time.Minute)))

			authTime, _ := claims["auth_time"].(float64)
			if want := created.Add(5 * time.Minute).Unix(); int64(authTime) != want {
				t.Errorf("auth_time=%d want %d (fresh credential), session-age reuse would give %d",
					int64(authTime), want, start.Unix())
			}
			if int64(authTime) > created.Unix()+int64((10*time.Minute).Seconds()) {
				t.Errorf("auth_time=%d is implausibly far in the future", int64(authTime))
			}
		})
	}
}

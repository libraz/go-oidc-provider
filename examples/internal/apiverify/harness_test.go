//go:build apiverify

// Package apiverify is the API-level counterpart of internal/browserverify:
// it boots each non-browser example under the "example" build tag and
// asserts the example does what its header doc promises over plain HTTP.
//
// One test file per example (example_NN_<slug>_test.go) so `ls` lines up
// with the examples/ directory and a missing smoke is visible at a glance.
// Examples fall into four shapes, one helper each:
//
//   - runDiscovery       — boots an OP and serves a discovery document.
//   - runAuthorizeInteraction — boots an OP and drives /authorize far enough
//     to see the interaction the example wires up.
//   - runSelfVerify      — runs an in-process grant round-trip and prints
//     a "✓ self-verify" marker (custom-grant,
//     device-code, token-exchange, pairwise).
//   - runExitZero        — runs a full round-trip to completion and exits 0
//     (CIBA), or cleanly handles a missing prerequisite
//     (FAPI TLS without certs).
//   - runClientCredentials — boots an OP and exercises the
//     client_credentials token grant over HTTP.
//
// Run it explicitly (gated behind the "apiverify" build tag):
//
//	go test -tags apiverify ./...
//
// Examples bind fixed ports (mostly :8080), so the tests must not run in
// parallel; Go runs a package's tests sequentially by default, so none here
// calls t.Parallel.
package apiverify

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// proc is a started example binary plus its captured log. A goroutine
// reaps the process so the helpers can tell "still serving" from "exited
// early" without blocking.
type proc struct {
	t       *testing.T
	cmd     *exec.Cmd
	logPath string
	done    chan int
	cached  *int
}

// buildAndStart compiles the example (go build -tags example) in its own
// module directory and starts the binary with its working directory set
// there, so relative asset paths resolve.
func buildAndStart(t *testing.T, dir string) *proc {
	return buildAndStartWithEnv(t, dir, nil)
}

// buildAndStartWithEnv is buildAndStart with environment overrides for
// examples whose listener address, TLS materials, or input assets must be
// isolated per test run.
func buildAndStartWithEnv(t *testing.T, dir string, env []string) *proc {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "example.bin")
	build := exec.CommandContext(t.Context(), "go", "build", "-tags", "example", "-o", bin, ".")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build example %s: %v\n%s", dir, err, out)
	}

	logFile, err := os.CreateTemp(t.TempDir(), "example-*.log")
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	// Bound to the test context as a backstop for the deferred kill: the
	// examples bind fixed ports, so a caller that loses its p.kill would
	// stall every test that follows rather than just its own.
	cmd := exec.CommandContext(t.Context(), bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start example %s: %v", dir, err)
	}

	p := &proc{t: t, cmd: cmd, logPath: logFile.Name(), done: make(chan int, 1)}
	go func() {
		err := cmd.Wait()
		p.done <- exitCodeOf(err)
	}()
	return p
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// poll reports whether the process has exited and, if so, its exit code.
func (p *proc) poll() (exited bool, code int) {
	if p.cached != nil {
		return true, *p.cached
	}
	select {
	case c := <-p.done:
		p.cached = &c
		return true, c
	default:
		return false, 0
	}
}

// waitExit blocks until the process exits or d elapses.
func (p *proc) waitExit(d time.Duration) (code int, exited bool) {
	if p.cached != nil {
		return *p.cached, true
	}
	select {
	case c := <-p.done:
		p.cached = &c
		return c, true
	case <-time.After(d):
		return 0, false
	}
}

func (p *proc) readLog() string {
	data, _ := os.ReadFile(p.logPath)
	return string(data)
}

// kill stops the process (if still running) and dumps its log on failure.
func (p *proc) kill() {
	if exited, _ := p.poll(); !exited {
		_ = p.cmd.Process.Kill()
		<-p.done
	}
	if p.t.Failed() {
		p.t.Logf("example log:\n%s", p.readLog())
	}
}

// runDiscovery boots the example and asserts its discovery document answers
// 200 with an issuer — the cheapest proof the OP wired up and serves.
func runDiscovery(t *testing.T, dir, baseURL string) {
	t.Helper()
	p := buildAndStart(t, dir)
	defer p.kill()

	body := pollHTTP(t, p, baseURL+"/.well-known/openid-configuration", 20*time.Second)
	if !strings.Contains(body, `"issuer"`) {
		t.Fatalf("discovery document missing issuer:\n%s", body)
	}
}

// runDiscoveryAssert boots the example and asserts its discovery document
// contains every want substring and none of the notWant substrings — used
// where the discovery document itself is the feature (the public scope
// allowlist, the registered ui_locales).
func runDiscoveryAssert(t *testing.T, dir, baseURL string, want, notWant []string) {
	t.Helper()
	p := buildAndStart(t, dir)
	defer p.kill()

	body := pollHTTP(t, p, baseURL+"/.well-known/openid-configuration", 20*time.Second)
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Fatalf("discovery document missing %q:\n%s", w, body)
		}
	}
	for _, nw := range notWant {
		if strings.Contains(body, nw) {
			t.Fatalf("discovery document unexpectedly contains %q:\n%s", nw, body)
		}
	}
}

// pkceVerifier is the verifier whose S256 challenge authorizeParams sends
// (RFC 7636 Appendix B). Most probes stop at the interaction hand-off and
// never redeem it; the ones that run the code through /token need the
// preimage, and a fixed pair keeps every call site short.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// authorizeParams builds a minimal Authorization Code + PKCE authorization
// request.
func authorizeParams(clientID, redirectURI, scope string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
		"state":                 {"apiverify-state"},
		"code_challenge":        {pkceChallenge},
		"code_challenge_method": {"S256"},
	}
}

// runAuthorizeInteraction boots the example, drives one authorization request,
// and asserts the OP hands the browser to an interaction of its own instead of
// bouncing an OAuth error back to the relying party. It then follows that
// hand-off and asserts the rendered prompt contains every want substring.
//
// Discovery alone cannot see this: an OP with no login flow wired still
// publishes a complete document and only fails at /authorize, with
// error=server_error on the redirect back to the RP. Any example whose header
// doc promises a browser walkthrough belongs here rather than on runDiscovery.
func runAuthorizeInteraction(t *testing.T, dir, baseURL string, params url.Values, want []string) {
	t.Helper()
	p := buildAndStart(t, dir)
	defer p.kill()

	driveAuthorizeInteraction(t, p, baseURL, params, want)
}

// driveAuthorizeInteraction is runAuthorizeInteraction against an example
// the caller already booted, for a probe that has a second thing to assert
// about the same process.
func driveAuthorizeInteraction(t *testing.T, p *proc, baseURL string, params url.Values, want []string) {
	t.Helper()
	doc := pollHTTP(t, p, baseURL+"/.well-known/openid-configuration", 20*time.Second)
	authorize := discoveryEndpointPath(t, doc, "authorization_endpoint")

	// The hand-off itself is the assertion, so redirects are inspected
	// rather than followed.
	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	authzReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+authorize+"?"+params.Encode(), nil)
	if err != nil {
		t.Fatalf("build authorization request: %v", err)
	}
	resp, err := client.Do(authzReq)
	if err != nil {
		t.Fatalf("authorization request: %v\n%s", err, p.readLog())
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/authorize returned %d, want 302 to an interaction:\n%s\n%s", resp.StatusCode, body, p.readLog())
	}

	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location %q: %v", resp.Header.Get("Location"), err)
	}
	if oauthErr := loc.Query().Get("error"); oauthErr != "" {
		t.Fatalf("/authorize bounced %q back to the RP (%s):\n%s",
			oauthErr, loc.Query().Get("error_description"), p.readLog())
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse base URL %q: %v", baseURL, err)
	}
	if loc.Host != "" && loc.Host != base.Host {
		t.Fatalf("/authorize redirected off the OP to %q, want an interaction on %s", loc, base.Host)
	}

	// Replay the interaction cookies by hand: they carry Secure, which a
	// cookiejar would strip on this plain-HTTP demo listener.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base.ResolveReference(loc).String(), nil)
	if err != nil {
		t.Fatalf("build interaction request: %v", err)
	}
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}
	prompt, err := client.Do(req)
	if err != nil {
		t.Fatalf("interaction request: %v\n%s", err, p.readLog())
	}
	promptBody, _ := io.ReadAll(prompt.Body)
	_ = prompt.Body.Close()
	if prompt.StatusCode != http.StatusOK {
		t.Fatalf("interaction %s returned %d:\n%s\n%s", loc, prompt.StatusCode, promptBody, p.readLog())
	}
	for _, w := range want {
		if !strings.Contains(string(promptBody), w) {
			t.Fatalf("interaction prompt missing %q:\n%s", w, promptBody)
		}
	}
}

// discoveryEndpointPath extracts one endpoint URL from a discovery document
// and returns its path. Examples that publish a placeholder issuer serve on a
// loopback address the document never mentions, so the path is the only part
// of the advertised endpoint a test can reuse.
func discoveryEndpointPath(t *testing.T, doc, key string) string {
	t.Helper()
	var meta map[string]any
	if err := json.Unmarshal([]byte(doc), &meta); err != nil {
		t.Fatalf("parse discovery document: %v\n%s", err, doc)
	}
	raw, ok := meta[key].(string)
	if !ok {
		t.Fatalf("discovery document has no %s:\n%s", key, doc)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s %q: %v", key, raw, err)
	}
	return u.Path
}

// runCORSPreflight boots the example and drives a CORS preflight against the
// token endpoint from each origin: allowlisted origins must be echoed back
// in Access-Control-Allow-Origin, a non-allowlisted origin must not be.
func runCORSPreflight(t *testing.T, dir, baseURL string, allowed []string, denied string) {
	t.Helper()
	p := buildAndStart(t, dir)
	defer p.kill()

	pollHTTP(t, p, baseURL+"/.well-known/openid-configuration", 20*time.Second)

	for _, origin := range allowed {
		if got := preflightACAO(t, baseURL, origin); got != origin {
			t.Fatalf("allowlisted origin %q: Access-Control-Allow-Origin = %q, want it echoed", origin, got)
		}
	}
	if got := preflightACAO(t, baseURL, denied); got == denied {
		t.Fatalf("non-allowlisted origin %q was echoed in Access-Control-Allow-Origin", denied)
	}
}

// preflightACAO sends an OPTIONS preflight for a POST /oidc/token from
// origin and returns the Access-Control-Allow-Origin response header.
func preflightACAO(t *testing.T, baseURL, origin string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodOptions, baseURL+"/oidc/token", nil)
	if err != nil {
		t.Fatalf("build preflight: %v", err)
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("preflight from %q: %v", origin, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header.Get("Access-Control-Allow-Origin")
}

// runMetrics boots the example, drives one failing token request to bump an
// OIDC counter (the library emits oidc_* metrics only once a business event
// fires), then asserts the embedder's /metrics surface exposes them.
func runMetrics(t *testing.T, dir, baseURL string) {
	t.Helper()
	p := buildAndStart(t, dir)
	defer p.kill()

	pollHTTP(t, p, baseURL+"/.well-known/openid-configuration", 20*time.Second)

	// An unknown client at the token endpoint fails client authentication,
	// which the metrics bridge counts — enough to surface an oidc_ series.
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"api:read"}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("no-such-client", "wrong-secret")
	if resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req); err == nil {
		_ = resp.Body.Close()
	}

	body := pollHTTP(t, p, baseURL+"/metrics", 10*time.Second)
	if !strings.Contains(body, "oidc_") {
		t.Fatalf("/metrics exposes no oidc_ series after a token failure:\n%s", body)
	}
}

// runSelfVerify boots an example that runs an in-process grant round-trip
// and prints a "✓ self-verify" marker on success, and waits for it. The
// example may keep serving afterward (custom-grant, token-exchange) or exit
// (device-code, pairwise); either way the marker is the contract.
func runSelfVerify(t *testing.T, dir string) {
	t.Helper()
	p := buildAndStart(t, dir)
	defer p.kill()

	const success = "✓ self-verify"
	const failure = "✗ self-verify"
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		log := p.readLog()
		if strings.Contains(log, success) {
			return
		}
		if strings.Contains(log, failure) {
			t.Fatalf("example reported self-verify failure:\n%s", log)
		}
		if exited, code := p.poll(); exited && code != 0 {
			t.Fatalf("example exited with code %d before self-verify marker:\n%s", code, log)
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %q:\n%s", success, p.readLog())
}

// runExitZero boots an example that runs to completion and exits 0 (CIBA's
// full backchannel round-trip; the FAPI-TLS no-cert path). A non-zero exit
// or a hang is the failure.
func runExitZero(t *testing.T, dir string) {
	t.Helper()
	p := buildAndStart(t, dir)
	defer p.kill()

	code, exited := p.waitExit(30 * time.Second)
	if !exited {
		t.Fatalf("example did not exit within deadline:\n%s", p.readLog())
	}
	if code != 0 {
		t.Fatalf("example exited with code %d:\n%s", code, p.readLog())
	}
}

// runClientCredentials boots the example and exercises the OAuth 2.0
// client_credentials grant over HTTP, asserting a bearer access token comes
// back — the grant the example exists to demonstrate.
func runClientCredentials(t *testing.T, dir, baseURL, clientID, secret, scope string) {
	t.Helper()
	p := buildAndStart(t, dir)
	defer p.kill()

	// Discovery readiness implies the token endpoint is mounted too.
	pollHTTP(t, p, baseURL+"/.well-known/openid-configuration", 20*time.Second)

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {scope},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("token request: %v\n%s", err, p.readLog())
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint returned %d:\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"access_token"`) {
		t.Fatalf("token response missing access_token:\n%s", body)
	}
}

// waitForLog blocks until want appears in the example's captured output or
// the deadline passes. Some deliverables are only observable there: an
// outbound call the OP makes on its own (a back-channel logout POST) leaves
// no trace on the response the probe holds.
func waitForLog(t *testing.T, p *proc, want string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if strings.Contains(p.readLog(), want) {
			return
		}
		if exited, code := p.poll(); exited {
			t.Fatalf("example exited (code %d) before logging %q:\n%s", code, want, p.readLog())
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %q in the example log:\n%s", want, p.readLog())
}

// pollHTTP polls url until it answers 200 or the deadline passes, failing
// fast if the example process exits first. It returns the 200 body.
func pollHTTP(t *testing.T, p *proc, url string, within time.Duration) string {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if exited, code := p.poll(); exited {
			t.Fatalf("example exited (code %d) before %s answered:\n%s", code, url, p.readLog())
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("build readiness probe for %s: %v", url, err)
		}
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return string(body)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s:\n%s", url, p.readLog())
	return ""
}

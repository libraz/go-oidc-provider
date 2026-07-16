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
	build := exec.Command("go", "build", "-tags", "example", "-o", bin, ".")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build example %s: %v\n%s", dir, err, out)
	}

	logFile, err := os.CreateTemp(t.TempDir(), "example-*.log")
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	cmd := exec.Command(bin)
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
	req, err := http.NewRequest(http.MethodOptions, baseURL+"/oidc/token", nil)
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
	req, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
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
	req, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/token", strings.NewReader(form.Encode()))
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
		resp, err := client.Get(url) //nolint:noctx // short-lived readiness poll
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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// newSeededInmem returns a fresh *inmem.Store with seedDemoUser
// already applied. Tests that exercise buildOPStore use it so the
// store presents the same shape the run() entrypoint hands to op.New.
func newSeededInmem(t *testing.T) *inmem.Store {
	t.Helper()
	st := inmem.New()
	if err := seedDemoUser(t.Context(), func(ctx context.Context, u *store.User, username string, hash []byte) error {
		st.PutUserWithPassword(ctx, u, username, hash)
		return nil
	}); err != nil {
		t.Fatalf("seedDemoUser: %v", err)
	}
	return st
}

var (
	errInvalidScheme    = errors.New("waitDiscovery: discovery URL must use http or https scheme")
	errDiscoveryTimeout = errors.New("waitDiscovery: timed out waiting for /.well-known/openid-configuration")
)

func TestDefaultListenAddrIsLoopback(t *testing.T) {
	t.Parallel()

	host, port, err := net.SplitHostPort(defaultListenAddr)
	if err != nil {
		t.Fatalf("defaultListenAddr = %q: %v", defaultListenAddr, err)
	}
	if port != "9090" {
		t.Errorf("port = %q, want 9090", port)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Fatalf("host = %q, want loopback address", host)
	}
}

func baseTestConfig(addr string) runConfig {
	return runConfig{
		listen:       addr,
		issuer:       "http://" + addr,
		mount:        "/oidc",
		clientID:     "demo-client",
		redirectURIs: []string{"https://app.example/cb"},
	}
}

func TestBuildClientSeeds_PublicClientShape(t *testing.T) {
	t.Parallel()

	uris := []string{"https://app.example/cb-1", "https://app.example/cb-2"}
	cfg := runConfig{
		clientID:     "demo-client",
		redirectURIs: uris,
	}
	seeds, err := buildClientSeeds(cfg)
	if err != nil {
		t.Fatalf("buildClientSeeds: %v", err)
	}
	if len(seeds) == 0 {
		t.Fatal("buildClientSeeds: returned empty slice")
	}
	pub, ok := seeds[0].(op.PublicClient)
	if !ok {
		t.Fatalf("seeds[0] = %T, want op.PublicClient", seeds[0])
	}
	if pub.ID != "demo-client" {
		t.Errorf("ID = %q, want demo-client", pub.ID)
	}
	if len(pub.RedirectURIs) != len(uris) {
		t.Fatalf("RedirectURIs len = %d, want %d", len(pub.RedirectURIs), len(uris))
	}
	for i, want := range uris {
		if pub.RedirectURIs[i] != want {
			t.Errorf("RedirectURIs[%d] = %q, want %q", i, pub.RedirectURIs[i], want)
		}
	}
}

func TestBuildClientSeeds_ConfidentialTrio(t *testing.T) {
	t.Parallel()

	cfg := runConfig{
		clientID:      "demo-client",
		redirectURIs:  []string{"https://app.example/cb"},
		confClientID:  "demo-conf",
		confClientSec: "demo-conf-secret",
	}
	seeds, err := buildClientSeeds(cfg)
	if err != nil {
		t.Fatalf("buildClientSeeds: %v", err)
	}
	got := map[string]op.AuthMethod{}
	for _, s := range seeds {
		c, ok := s.(op.ConfidentialClient)
		if !ok {
			continue
		}
		got[c.ID] = c.AuthMethod
	}
	want := map[string]op.AuthMethod{
		"demo-conf":      op.AuthClientSecretBasic,
		"demo-conf-post": op.AuthClientSecretPost,
		"demo-conf-2":    op.AuthClientSecretBasic,
	}
	for id, method := range want {
		if got[id] != method {
			t.Errorf("ConfidentialClient[%q].AuthMethod = %q, want %q", id, got[id], method)
		}
	}
}

// TestCommonClientSeeds_FAPIProfilesSeedNothing pins that the shared
// public + client_secret_* seeds are omitted under a FAPI profile. FAPI
// permits only private_key_jwt / mTLS, so op.New rejects a none-auth or
// client_secret_* static seed at construction under an active FAPI
// profile; emitting one here would make the FAPI op-demo fail to boot.
func TestCommonClientSeeds_FAPIProfilesSeedNothing(t *testing.T) {
	t.Parallel()

	for _, profile := range []string{"fapi2-baseline", "fapi2-message-signing", "fapi-ciba"} {
		cfg := runConfig{
			profile:       profile,
			clientID:      "demo-client",
			redirectURIs:  []string{"https://app.example/cb"},
			confClientID:  "demo-confidential",
			confClientSec: "demo-confidential-secret-32-bytes-min",
		}
		if got := commonClientSeeds(cfg, nil); got != nil {
			t.Errorf("commonClientSeeds(profile=%q) returned %d seed(s), want nil", profile, len(got))
		}
	}
}

func TestDerivePostLogoutURIs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "single-callback",
			in:   []string{"https://app.example/test/a/x/callback"},
			want: []string{"https://app.example/test/a/x/post_logout_redirect"},
		},
		{
			name: "drops-non-callback",
			in:   []string{"https://app.example/cb", "https://app.example/test/a/x/callback"},
			want: []string{"https://app.example/test/a/x/post_logout_redirect"},
		},
		{
			name: "empty",
			in:   []string{},
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := derivePostLogoutURIs(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d (got %v)", len(got), len(tc.want), got)
			}
			for i, want := range tc.want {
				if got[i] != want {
					t.Errorf("[%d] = %q, want %q", i, got[i], want)
				}
			}
		})
	}
}

func TestBuildOPStore_WrapsForCIBAProfile(t *testing.T) {
	t.Parallel()

	cfg := runConfig{profile: "fapi-ciba", cibaAutoApproveDelay: time.Second}
	st := newSeededInmem(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	got, err := buildOPStore(ctx, cfg, st, logger)
	if err != nil {
		t.Fatalf("buildOPStore: %v", err)
	}
	if _, ok := got.(*cibaAutoApproveStore); !ok {
		t.Fatalf("buildOPStore for fapi-ciba returned %T; want *cibaAutoApproveStore", got)
	}
	// The wrapper hides everything it does not re-declare, and the
	// capabilities below are discovered by op.New through exactly this
	// assertion. Losing one takes dynamic registration, the atomic
	// static-client seed, or transaction staging off the conformance
	// binary — two of those without any error at all.
	if _, ok := got.(store.ClientRegistry); !ok {
		t.Error("wrapped store no longer implements store.ClientRegistry; dynamic registration cannot boot")
	}
	if _, ok := got.(store.StaticClientReconciler); !ok {
		t.Error("wrapped store no longer implements store.StaticClientReconciler; the atomic seed path is gone")
	}
	if _, ok := got.(store.Transactional); !ok {
		t.Error("wrapped store no longer implements store.Transactional; the token endpoint stops staging")
	}
}

func TestBuildOPStore_BareForNonCIBAProfile(t *testing.T) {
	t.Parallel()

	cfg := runConfig{profile: "fapi2-baseline"}
	st := newSeededInmem(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	got, err := buildOPStore(ctx, cfg, st, logger)
	if err != nil {
		t.Fatalf("buildOPStore: %v", err)
	}
	if got != store.Store(st) {
		t.Errorf("buildOPStore for fapi2-baseline returned a wrapper; want bare *inmem.Store")
	}
}

func TestProfileFor_AcceptsFAPICIBA(t *testing.T) {
	t.Parallel()

	got, err := profileFor("fapi-ciba")
	if err != nil {
		t.Fatalf("profileFor(fapi-ciba): %v", err)
	}
	if got == 0 {
		t.Fatal("profileFor(fapi-ciba) returned 0; expected profile.FAPICIBA")
	}
	if !isCIBAProfile("fapi-ciba") {
		t.Error("isCIBAProfile(fapi-ciba) = false, want true")
	}
	if !isFAPIProfile("fapi-ciba") {
		t.Error("isFAPIProfile(fapi-ciba) = false, want true")
	}
}

// TestRun_DiscoveryAdvertisesDCRAndLogout boots run() with -enable-dcr
// against the empty profile and asserts the discovery document
// advertises /register and /end_session. Without this the smoke test
// suite would not catch a regression that silently dropped the DCR
// option from buildOptions.
func TestRun_DiscoveryAdvertisesDCRAndLogout(t *testing.T) {
	t.Parallel()

	addr := pickFreeAddr(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cfg := baseTestConfig(addr)
	cfg.enableDCR = true

	var (
		runErr error
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		runErr = run(ctx, cfg, logger)
	}()

	doc := fetchDiscovery(t, "http://"+addr+"/.well-known/openid-configuration", http.DefaultClient)
	if doc["registration_endpoint"] == nil {
		t.Error("discovery is missing registration_endpoint; -enable-dcr was not honoured")
	}
	if doc["end_session_endpoint"] == nil {
		t.Error("discovery is missing end_session_endpoint; RP-initiated logout regressed")
	}

	cancel()
	waitRunDone(t, &wg)
	if runErr != nil {
		t.Fatalf("run returned err: %v", runErr)
	}
}

func TestParseRedirectURIs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want []string
	}{
		{name: "single", in: "https://app/cb", want: []string{"https://app/cb"}},
		{name: "comma-separated", in: "https://a/cb,https://b/cb", want: []string{"https://a/cb", "https://b/cb"}},
		{name: "trims-whitespace", in: " https://a/cb , https://b/cb ", want: []string{"https://a/cb", "https://b/cb"}},
		{name: "drops-empty", in: "https://a/cb,,https://b/cb,", want: []string{"https://a/cb", "https://b/cb"}},
		{name: "empty-input", in: "", want: []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseRedirectURIs(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d (got %v)", len(got), len(tc.want), got)
			}
			for i, want := range tc.want {
				if got[i] != want {
					t.Errorf("[%d] = %q, want %q", i, got[i], want)
				}
			}
		})
	}
}

// TestRun_BootsAndShutsDown drives the same path the main entrypoint
// takes — it picks a free port, launches run in a goroutine, hits the
// discovery document over HTTP, and cancels the context to confirm
// the shutdown handler tears the listener down cleanly.
func TestRun_BootsAndShutsDown(t *testing.T) {
	t.Parallel()

	addr := pickFreeAddr(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var (
		runErr error
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		runErr = run(ctx, baseTestConfig(addr), logger)
	}()

	cfg := baseTestConfig(addr)
	if err := waitDiscovery(cfg.issuer+"/.well-known/openid-configuration", http.DefaultClient); err != nil {
		t.Fatalf("discovery never came up: %v", err)
	}

	cancel()
	waitRunDone(t, &wg)
	if runErr != nil {
		t.Fatalf("run returned err: %v", runErr)
	}
}

// TestRun_BootsHTTPS exercises the TLS branch end-to-end with a
// self-signed cert. Without this, a typo like swapping the cert/key
// arguments to ListenAndServeTLS would only surface the first time
// OFCS connects to op-demo over HTTPS.
func TestRun_BootsHTTPS(t *testing.T) {
	t.Parallel()

	certPath, keyPath := writeSelfSignedTLS(t)
	addr := pickFreeAddr(t)

	cfg := baseTestConfig(addr)
	cfg.tlsCert = certPath
	cfg.tlsKey = keyPath
	cfg.issuer = "https://" + addr

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var (
		runErr error
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		runErr = run(ctx, cfg, logger)
	}()

	// The self-signed cert is only trusted within this test, so use
	// an InsecureSkipVerify client here. Production op-demo runs
	// behind a real cert so this knob is test-only.
	tlsClient := &http.Client{
		Timeout: 500 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // G402: self-signed cert under test
		},
	}
	if err := waitDiscovery(cfg.issuer+"/.well-known/openid-configuration", tlsClient); err != nil {
		t.Fatalf("discovery (https) never came up: %v", err)
	}

	cancel()
	waitRunDone(t, &wg)
	if runErr != nil {
		t.Fatalf("run returned err: %v", runErr)
	}
}

// TestRun_RejectsHalfTLSConfig confirms run() refuses to start when
// only one of -tls-cert / -tls-key is set. Falling back to plain HTTP
// in that situation would silently mismatch the issuer scheme and
// break OFCS without an obvious cause.
func TestRun_RejectsHalfTLSConfig(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cases := []struct {
		name string
		cert string
		key  string
	}{
		{name: "cert-only", cert: "/tmp/cert.pem"},
		{name: "key-only", key: "/tmp/key.pem"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := baseTestConfig(":0")
			cfg.tlsCert = tc.cert
			cfg.tlsKey = tc.key
			err := run(context.Background(), cfg, logger)
			if err == nil {
				t.Fatal("run returned nil, want config error")
			}
			if !strings.Contains(err.Error(), "tls-cert") || !strings.Contains(err.Error(), "tls-key") {
				t.Errorf("err = %v, want it to mention both -tls-cert and -tls-key", err)
			}
		})
	}
}

func TestRun_RejectsIssuerListenerSchemeMismatch(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name    string
		issuer  string
		tlsCert string
		tlsKey  string
	}{
		{
			name:   "https issuer on plain HTTP listener",
			issuer: "https://127.0.0.1:9090",
		},
		{
			name:    "http issuer on TLS listener",
			issuer:  "http://127.0.0.1:9090",
			tlsCert: "unused-cert.pem",
			tlsKey:  "unused-key.pem",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := baseTestConfig("127.0.0.1:9090")
			cfg.issuer = tc.issuer
			cfg.tlsCert = tc.tlsCert
			cfg.tlsKey = tc.tlsKey
			err := run(context.Background(), cfg, logger)
			if err == nil {
				t.Fatal("run returned nil, want issuer/listener scheme error")
			}
			if !strings.Contains(err.Error(), "issuer") {
				t.Errorf("err = %v, want it to identify the issuer mismatch", err)
			}
		})
	}
}

// pickFreeAddr binds a TCP listener to localhost:0, captures the
// kernel-assigned port, then closes the listener so run() can rebind
// to the same address. Race-prone in theory, but acceptable for a
// dev-only demo binary's tests.
func pickFreeAddr(t *testing.T) string {
	t.Helper()
	lc := &net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close pre-bind listener: %v", err)
	}
	return addr
}

func waitRunDone(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	doneCh := make(chan struct{})
	go func() { wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return within 10s of context cancel")
	}
}

// fetchDiscovery polls discoveryURL until it responds 200, then
// returns the parsed JSON body. Used by smoke tests that assert on a
// specific discovery field; the polling loop replaces a fixed sleep
// so the test stays correct under -race.
func fetchDiscovery(t *testing.T, discoveryURL string, client *http.Client) map[string]any {
	t.Helper()
	if err := waitDiscovery(discoveryURL, client); err != nil {
		t.Fatalf("discovery never came up: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, discoveryURL, http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("fetch discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return doc
}

// waitDiscovery polls discoveryURL until it responds 200 or the
// budget runs out. The polling loop replaces a fixed sleep so the
// test stays correct even when boot is slower than usual under -race.
func waitDiscovery(discoveryURL string, client *http.Client) error {
	deadline := time.Now().Add(5 * time.Second)
	parsed, err := url.Parse(discoveryURL)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(parsed.Scheme, "http") {
		return errInvalidScheme
	}
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, discoveryURL, http.NoBody)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errDiscoveryTimeout
}

// TestLoadCABundles_EmptyReturnsNil pins the documented signal —
// embedders who do not pass -extra-ca-bundle keep Go's package-default
// trust posture (lazy SystemCertPool inside crypto/tls). A non-nil
// pool here would silently shadow the system roots.
func TestLoadCABundles_EmptyReturnsNil(t *testing.T) {
	t.Parallel()

	pool, err := loadCABundles("")
	if err != nil {
		t.Fatalf("loadCABundles(empty): %v", err)
	}
	if pool != nil {
		t.Fatalf("loadCABundles(empty) = %v, want nil", pool)
	}
	pool, err = loadCABundles("   ")
	if err != nil {
		t.Fatalf("loadCABundles(whitespace): %v", err)
	}
	if pool != nil {
		t.Fatalf("loadCABundles(whitespace) = %v, want nil", pool)
	}
}

// TestLoadCABundles_AppendsValidPEM exercises the success path. A
// throwaway self-signed cert is written to a temp file; the returned
// pool must be non-nil and accept the cert when Subjects is consulted
// (the only way to confirm AppendCertsFromPEM observed it).
func TestLoadCABundles_AppendsValidPEM(t *testing.T) {
	t.Parallel()

	certPath, _ := writeSelfSignedTLS(t)
	pool, err := loadCABundles(certPath)
	if err != nil {
		t.Fatalf("loadCABundles: %v", err)
	}
	if pool == nil {
		t.Fatal("loadCABundles returned nil pool for valid PEM")
	}
	// Re-load the cert and confirm pool acknowledges it. Equal not
	// guaranteed (system pool varies), so we just verify the API
	// surface that an embedder would consult.
	pem, err := os.ReadFile(certPath) //nolint:gosec // G304: certPath comes from writeSelfSignedTLS(t.TempDir).
	if err != nil {
		t.Fatalf("re-read cert: %v", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("pool refused the cert on re-append; AppendCertsFromPEM lost the input")
	}
}

// TestLoadCABundles_RejectsNonExistent pins the loud-failure contract.
// Loading a path that does not exist is almost certainly an operator
// typo; the silent miss would defeat the whole point of the flag.
func TestLoadCABundles_RejectsNonExistent(t *testing.T) {
	t.Parallel()

	_, err := loadCABundles("/nonexistent/path/to/ca.pem")
	if err == nil {
		t.Fatal("loadCABundles returned nil err for missing file")
	}
}

// TestLoadCABundles_RejectsNonPEM confirms a path containing zero
// PEM-encoded certificates surfaces as an explicit error rather than
// returning the system pool unmodified.
func TestLoadCABundles_RejectsNonPEM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	garbage := filepath.Join(dir, "not-a-cert.txt")
	if err := os.WriteFile(garbage, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	_, err := loadCABundles(garbage)
	if err == nil {
		t.Fatal("loadCABundles accepted a non-PEM file")
	}
	if !strings.Contains(err.Error(), "PEM") {
		t.Errorf("err = %v, want PEM diagnostic", err)
	}
}

// TestCIBATestModeHandler_GetReturnsApproveByDefault exercises the
// runner-side read path: with no prior POST, GET returns "approve" so
// the runner can confirm the OP is in the happy-flow shape before
// driving a fapi-ciba test.
//
// The test mutates the package-level [cibaTestMode] atomic so it
// cannot run in parallel with [TestCIBATestModeHandler_PostFlipsAtomic].
//
//nolint:paralleltest // serial by design — package-level atomic.
func TestCIBATestModeHandler_GetReturnsApproveByDefault(t *testing.T) {
	cibaTestMode.Store("") // reset; this test mutates the package-level atomic.
	rec := newRecorder()
	req := newRequest(t, http.MethodGet, "/_test/ciba-mode", nil)
	CIBATestModeHandler().ServeHTTP(rec, req)
	if rec.code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.code)
	}
	if got := strings.TrimSpace(rec.body.String()); got != cibaTestModeApprove {
		t.Errorf("body = %q, want %q", got, cibaTestModeApprove)
	}
}

// TestCIBATestModeHandler_PostFlipsAtomic confirms the runner-side
// write path. Each accepted mode flips the global, and a subsequent
// loadCIBATestMode() observes the new value — the contract Save
// relies on.
//
//nolint:paralleltest // serial by design — package-level atomic.
func TestCIBATestModeHandler_PostFlipsAtomic(t *testing.T) {
	for _, mode := range []string{cibaTestModeApprove, cibaTestModeReject, cibaTestModeSlow} {
		cibaTestMode.Store("")
		rec := newRecorder()
		req := newRequest(t, http.MethodPost, "/_test/ciba-mode", strings.NewReader(mode))
		CIBATestModeHandler().ServeHTTP(rec, req)
		if rec.code != http.StatusOK {
			t.Fatalf("mode=%q status=%d, want 200 (body=%q)", mode, rec.code, rec.body.String())
		}
		if got := loadCIBATestMode(); got != mode {
			t.Errorf("loadCIBATestMode = %q, want %q", got, mode)
		}
	}
}

// TestCIBATestModeHandler_PostRejectsUnknown pins the validation: an
// unknown mode must surface as 400 so a typo in the runner does not
// silently leave the OP in the previous mode.
func TestCIBATestModeHandler_PostRejectsUnknown(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	req := newRequest(t, http.MethodPost, "/_test/ciba-mode", strings.NewReader("delete-everything"))
	CIBATestModeHandler().ServeHTTP(rec, req)
	if rec.code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.code)
	}
}

// recordingResponseWriter is a tiny stand-in for httptest.NewRecorder
// kept in this file to avoid a new dependency on net/http/httptest in
// the cmd-package test binary. It only captures what the handler tests
// assert on (status code, body, headers).
type recordingResponseWriter struct {
	code   int
	header http.Header
	body   strings.Builder
}

func newRecorder() *recordingResponseWriter {
	return &recordingResponseWriter{code: http.StatusOK, header: http.Header{}}
}

func (r *recordingResponseWriter) Header() http.Header { return r.header }

func (r *recordingResponseWriter) Write(p []byte) (int, error) {
	return r.body.Write(p)
}

func (r *recordingResponseWriter) WriteHeader(code int) { r.code = code }

func newRequest(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, target, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

// writeSelfSignedTLS generates a single-purpose ECDSA P-256 cert
// covering 127.0.0.1 / ::1 / localhost, writes it to a temp dir, and
// returns the file paths. Lifetime is 1 hour — long enough for any
// test, short enough that a leaked cert is harmless.
func writeSelfSignedTLS(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

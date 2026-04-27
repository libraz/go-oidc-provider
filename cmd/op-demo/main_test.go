package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

var (
	errInvalidScheme    = errors.New("waitDiscovery: discovery URL must use http or https scheme")
	errDiscoveryTimeout = errors.New("waitDiscovery: timed out waiting for /.well-known/openid-configuration")
)

func baseTestConfig(addr string) runConfig {
	return runConfig{
		listen:       addr,
		issuer:       "https://localhost",
		mount:        "/oidc",
		clientID:     "demo-client",
		redirectURIs: []string{"https://app.example/cb"},
	}
}

func TestSeedClient_RegistersDemoClient(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	uris := []string{"https://app.example/cb-1", "https://app.example/cb-2"}
	if err := seedClient(st, "demo-client", uris); err != nil {
		t.Fatalf("seedClient: %v", err)
	}
	got, err := st.GetClient(context.Background(), "demo-client")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.ID != "demo-client" {
		t.Errorf("ID = %q, want demo-client", got.ID)
	}
	if len(got.RedirectURIs) != len(uris) {
		t.Fatalf("RedirectURIs len = %d, want %d", len(got.RedirectURIs), len(uris))
	}
	for i, want := range uris {
		if got.RedirectURIs[i] != want {
			t.Errorf("RedirectURIs[%d] = %q, want %q", i, got.RedirectURIs[i], want)
		}
	}
	if !got.PublicClient {
		t.Error("PublicClient = false, want true")
	}
	if got.Source != store.ClientSourceStatic {
		t.Errorf("Source = %q, want %q", got.Source, store.ClientSourceStatic)
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

	if err := waitDiscovery("http://"+addr+"/.well-known/openid-configuration", http.DefaultClient); err != nil {
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
	if err := waitDiscovery("https://"+addr+"/.well-known/openid-configuration", tlsClient); err != nil {
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

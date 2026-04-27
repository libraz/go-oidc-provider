package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
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

func TestSeedClient_RegistersDemoClient(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	if err := seedClient(st, "demo-client", "https://app.example/cb"); err != nil {
		t.Fatalf("seedClient: %v", err)
	}
	got, err := st.GetClient(context.Background(), "demo-client")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.ID != "demo-client" {
		t.Errorf("ID = %q, want demo-client", got.ID)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://app.example/cb" {
		t.Errorf("RedirectURIs = %v, want [https://app.example/cb]", got.RedirectURIs)
	}
	if !got.PublicClient {
		t.Error("PublicClient = false, want true")
	}
	if got.Source != store.ClientSourceStatic {
		t.Errorf("Source = %q, want %q", got.Source, store.ClientSourceStatic)
	}
}

// TestRun_BootsAndShutsDown drives the same path the main entrypoint
// takes — it picks a free port, launches run in a goroutine, hits the
// discovery document over HTTP, and cancels the context to confirm
// the shutdown handler tears the listener down cleanly.
func TestRun_BootsAndShutsDown(t *testing.T) {
	t.Parallel()

	lc := &net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close pre-bind listener: %v", err)
	}

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
		runErr = run(ctx, addr, "https://localhost", "/oidc", "demo-client", "https://app.example/cb", logger)
	}()

	if err := waitDiscovery("http://" + addr + "/.well-known/openid-configuration"); err != nil {
		t.Fatalf("discovery never came up: %v", err)
	}

	cancel()

	doneCh := make(chan struct{})
	go func() { wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return within 10s of context cancel")
	}
	if runErr != nil {
		t.Fatalf("run returned err: %v", runErr)
	}
}

// waitDiscovery polls discoveryURL until it responds 200 or the
// budget runs out. The polling loop replaces a fixed sleep so the
// test stays correct even when boot is slower than usual under -race.
func waitDiscovery(discoveryURL string) error {
	deadline := time.Now().Add(5 * time.Second)
	parsed, err := url.Parse(discoveryURL)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(parsed.Scheme, "http") {
		return errInvalidScheme
	}
	client := &http.Client{Timeout: 500 * time.Millisecond}
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

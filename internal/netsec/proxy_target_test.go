//nolint:testpackage // exercises the unexported proxy gate alongside the exported composition.
package netsec

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// proxyRouting describes the two ways a proxy reaches the gated client.
type proxyRouting struct {
	name    string
	options func(proxy func(*http.Request) (*url.URL, error)) Options
}

var proxyRoutings = []proxyRouting{
	{
		name: "caller_transport",
		options: func(proxy func(*http.Request) (*url.URL, error)) Options {
			return Options{BaseTransport: &http.Transport{Proxy: proxy}}
		},
	},
	{
		name: "options_proxy",
		options: func(proxy func(*http.Request) (*url.URL, error)) Options {
			return Options{Proxy: proxy}
		},
	},
}

// newForwardProxy returns a loopback stand-in for a forward proxy that
// answers every request itself and counts them.
func newForwardProxy(t *testing.T) (*url.URL, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("proxied"))
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	return u, hits
}

// TestNewHTTPClient_ProxiedTargetIsGated pins that a request routed
// through a proxy has its target checked against the deny-list before
// the hand-off: the dial-time gate only sees the proxy's address.
func TestNewHTTPClient_ProxiedTargetIsGated(t *testing.T) {
	t.Parallel()

	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "rebind.example":
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
		case "public.example":
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		}
		return nil, errors.New("unexpected lookup")
	}
	cases := []struct {
		target  string
		wantErr error
	}{
		{target: "http://10.1.2.3/x", wantErr: ErrPrivateNetworkBlocked},
		{target: "http://169.254.169.254/latest/meta-data", wantErr: ErrCloudMetadataBlocked},
		{target: "http://rebind.example/x", wantErr: ErrPrivateNetworkBlocked},
		{target: "http://public.example/x"},
	}
	for _, routing := range proxyRoutings {
		for _, tc := range cases {
			t.Run(routing.name+"/"+tc.target, func(t *testing.T) {
				t.Parallel()

				proxyURL, hits := newForwardProxy(t)
				opts := routing.options(http.ProxyURL(proxyURL))
				// The stand-in proxy listens on loopback; the opt-in admits
				// it at dial time without admitting the private targets.
				opts.AllowLoopback = true
				opts.LookupHook = lookup
				opts.Timeout = 2 * time.Second
				client := NewHTTPClient(opts)

				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tc.target, http.NoBody)
				if err != nil {
					t.Fatalf("NewRequestWithContext: %v", err)
				}
				resp, err := client.Do(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if tc.wantErr == nil {
					if err != nil {
						t.Fatalf("public target through proxy: %v", err)
					}
					if hits.Load() != 1 {
						t.Fatalf("proxy hits=%d, want 1", hits.Load())
					}
					return
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v, want %v", err, tc.wantErr)
				}
				if hits.Load() != 0 {
					t.Fatalf("proxy received %d request(s) for a deny-listed target", hits.Load())
				}
			})
		}
	}
}

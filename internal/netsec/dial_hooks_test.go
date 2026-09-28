//nolint:testpackage // exercises the unexported redirect gate alongside the exported composition.
package netsec

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// tlsDialCase describes one way a caller-supplied [*http.Transport] can
// carry its own HTTPS dial function.
type tlsDialCase struct {
	name    string
	install func(tr *http.Transport, dial func(ctx context.Context, network, addr string) (net.Conn, error))
}

var tlsDialCases = []tlsDialCase{
	{
		name: "DialTLSContext",
		install: func(tr *http.Transport, dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
			tr.DialTLSContext = dial
		},
	},
	{
		name: "DialTLS",
		install: func(tr *http.Transport, dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
			tr.DialTLS = func(network, addr string) (net.Conn, error) { //nolint:staticcheck // the deprecated hook is the shape under test.
				return dial(context.Background(), network, addr)
			}
		},
	},
}

// newCallerTLSTransport returns a transport trusting srv's certificate
// whose own TLS dial function counts its invocations.
func newCallerTLSTransport(srv *httptest.Server, install func(*http.Transport, func(context.Context, string, string) (net.Conn, error))) (*http.Transport, *atomic.Int32) {
	calls := &atomic.Int32{}
	tlsConf := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tr := &http.Transport{TLSClientConfig: tlsConf}
	install(tr, func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		d := tls.Dialer{Config: tlsConf}
		return d.DialContext(ctx, network, addr)
	})
	return tr, calls
}

// TestNewHTTPClient_CallerTLSDialIsGated pins that an HTTPS request
// through a caller transport carrying its own TLS dial function still
// meets the dial-time deny-list: the caller's dial is never invoked and
// the loopback peer is refused.
func TestNewHTTPClient_CallerTLSDialIsGated(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	for _, tc := range tlsDialCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			caller, calls := newCallerTLSTransport(srv, tc.install)
			client := NewHTTPClient(Options{BaseTransport: caller, Timeout: 2 * time.Second})
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
			if err != nil {
				t.Fatalf("NewRequestWithContext: %v", err)
			}
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("HTTPS request to a loopback peer succeeded; want the dial-time gate to refuse it")
			}
			if !errors.Is(err, ErrPrivateNetworkBlocked) {
				t.Fatalf("err=%v want ErrPrivateNetworkBlocked", err)
			}
			if n := calls.Load(); n != 0 {
				t.Fatalf("caller TLS dial invoked %d times; want 0", n)
			}
		})
	}
}

// TestNewHTTPClient_CallerTLSDialKeepsTLSConfig confirms the gated
// dialer still carries the caller's TLSClientConfig, so a transport
// supplied for its trust store keeps working once the peer is admitted.
func TestNewHTTPClient_CallerTLSDialKeepsTLSConfig(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	for _, tc := range tlsDialCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			caller, calls := newCallerTLSTransport(srv, tc.install)
			client := NewHTTPClient(Options{BaseTransport: caller, AllowLoopback: true, Timeout: 2 * time.Second})
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
			if err != nil {
				t.Fatalf("NewRequestWithContext: %v", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("HTTPS request with AllowLoopback: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d want 200", resp.StatusCode)
			}
			if n := calls.Load(); n != 0 {
				t.Fatalf("caller TLS dial invoked %d times; want 0", n)
			}
		})
	}
}

// TestCheckRedirect_HookCannotAdmit pins that a caller hook returning
// nil cannot admit a redirect the package gate refuses, on either the
// deny-list or the redirect cap.
func TestCheckRedirect_HookCannotAdmit(t *testing.T) {
	t.Parallel()

	permissive := func(*http.Request, []*http.Request) error { return nil }
	opts := Options{MaxRedirects: 2, CheckRedirect: permissive}
	check := CheckRedirect(opts)

	private, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://10.0.0.1/admin", http.NoBody)
	if err := check(private, nil); !errors.Is(err, ErrRedirectBlocked) || !errors.Is(err, ErrPrivateNetworkBlocked) {
		t.Fatalf("private target: err=%v want ErrRedirectBlocked wrapping ErrPrivateNetworkBlocked", err)
	}

	public, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://1.1.1.1/x", http.NoBody)
	if err := check(public, []*http.Request{public, public, public}); !errors.Is(err, ErrRedirectBlocked) {
		t.Fatalf("over the cap: err=%v want ErrRedirectBlocked", err)
	}

	if err := CheckRedirect(Options{CheckRedirect: permissive})(public, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("MaxRedirects=0: err=%v want http.ErrUseLastResponse", err)
	}
}

// TestCheckRedirect_HookAddsVeto confirms the caller hook can refuse a
// redirect the gate admits and can replace the gate's plain refusal
// with its own error.
func TestCheckRedirect_HookAddsVeto(t *testing.T) {
	t.Parallel()

	errVeto := errors.New("caller veto")
	veto := func(*http.Request, []*http.Request) error { return errVeto }
	public, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://1.1.1.1/x", http.NoBody)

	if err := CheckRedirect(Options{MaxRedirects: 2, CheckRedirect: veto})(public, nil); !errors.Is(err, errVeto) {
		t.Fatalf("admitted redirect: err=%v want caller veto", err)
	}
	if err := CheckRedirect(Options{CheckRedirect: veto})(public, nil); !errors.Is(err, errVeto) {
		t.Fatalf("MaxRedirects=0: err=%v want caller veto", err)
	}
}

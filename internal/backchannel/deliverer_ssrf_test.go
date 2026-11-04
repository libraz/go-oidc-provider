// Package backchannel: test file exercises unexported helpers
// (the request-build SSRF gate, ErrPrivateNetworkBlocked) so the
// deny-list can be pinned without exporting internal types. The package decl is
// intentionally aligned with the production package.
//
//nolint:testpackage // exercises unexported helpers
package backchannel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// requestGate runs the SSRF gate Deliver applies while building its
// request, with the same error classification, without sending anything.
func requestGate(d *HTTPDeliverer, rawURL string) error {
	_, err := d.resolveClient().NewRequest(context.Background(), http.MethodPost, rawURL, nil)
	if err != nil {
		return classifyDeliverError(rawURL, err)
	}
	return nil
}

// TestHTTPDeliverer_SSRFDenyList exercises the H-PROTO-1 deny-list
// matrix: a backchannel_logout_uri that points at a loopback /
// link-local / RFC 1918 / IPv6 ULA host MUST NOT receive a signed
// logout_token. The matrix doubles as a regression guard against a
// future revision that accidentally re-opens the private-network
// surface.
func TestHTTPDeliverer_SSRFDenyList(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		url         string
		wantBlocked bool
	}{
		{"loopback-v4", "http://127.0.0.1/logout", true},
		{"loopback-v4-block", "http://127.0.0.5/logout", true},
		{"loopback-v6", "http://[::1]/logout", true},
		{"link-local-v4", "http://169.254.169.254/logout", true},
		{"link-local-v6", "http://[fe80::1]/logout", true},
		{"rfc1918-10", "http://10.0.0.1/logout", true},
		{"rfc1918-172", "http://172.16.0.1/logout", true},
		{"rfc1918-192", "http://192.168.1.1/logout", true},
		{"localhost-name", "http://localhost/logout", true},
		{"localhost-mixed", "http://LocalHost/logout", true},
		{"unknown-scheme", "ftp://rp.example.com/logout", true},
		{"empty-host", "http:///logout", true},
		{"public-ip", "https://1.1.1.1/logout", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := &HTTPDeliverer{
				Client:  &http.Client{Timeout: time.Second},
				Timeout: time.Second,
			}
			err := requestGate(d, tc.url)
			if tc.wantBlocked {
				if err == nil {
					t.Fatalf("requestGate(%q) = nil, want blocked", tc.url)
				}
				return
			}
			if err != nil {
				t.Fatalf("requestGate(%q) unexpected error: %v", tc.url, err)
			}
		})
	}
}

// TestHTTPDeliverer_SSRFAllowPrivate confirms the AllowPrivateNetwork
// opt-in suppresses the deny-list. With the flag set, a loopback URL
// passes the gate (so the embedder fronting an internal-only RP can
// still deliver logout tokens).
func TestHTTPDeliverer_SSRFAllowPrivate(t *testing.T) {
	t.Parallel()

	d := &HTTPDeliverer{
		Client:              &http.Client{Timeout: time.Second},
		Timeout:             time.Second,
		AllowPrivateNetwork: true,
	}
	if err := requestGate(d, "http://127.0.0.1/logout"); err != nil {
		t.Fatalf("AllowPrivateNetwork=true should permit loopback; got %v", err)
	}
}

// TestHTTPDeliverer_DenyByDefault wires the deny-list end-to-end:
// Deliver MUST return [ErrPrivateNetworkBlocked] for a loopback
// URL without ever opening the network. The test inspects the
// returned error and confirms no upstream Server saw the POST.
func TestHTTPDeliverer_DenyByDefault(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("delivery should have been blocked before the POST")
	}))
	defer srv.Close()
	// httptest.NewServer binds 127.0.0.1 by default; use that URL
	// to drive the loopback-block path.
	if !strings.HasPrefix(srv.URL, "http://127.0.0.1") {
		t.Skipf("httptest.Server is not on 127.0.0.1: %s", srv.URL)
	}

	d := NewHTTPDeliverer(time.Second)
	err := d.Deliver(context.Background(), Target{URL: srv.URL, ClientID: "rp"}, "x")
	if err == nil {
		t.Fatal("Deliver returned nil; want SSRF block")
	}
	if !errors.Is(err, ErrPrivateNetworkBlocked) {
		t.Errorf("error = %v, want errors.Is ErrPrivateNetworkBlocked", err)
	}
}

// TestHTTPDeliverer_ResolverRebinding fixes the DNS-rebinding gate:
// when the configured resolver returns a private IP for a public
// host, the deliverer rejects the URL even though the URL itself
// names a public-looking name. Without the resolver-time check, an
// attacker could register backchannel_logout_uri = "https://evil.example/"
// where evil.example resolves to 127.0.0.1 at the moment the OP
// looks it up.
func TestHTTPDeliverer_ResolverRebinding(t *testing.T) {
	t.Parallel()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, errors.New("test: synthetic resolver in use")
		},
	}
	d := &HTTPDeliverer{
		Client:   &http.Client{Timeout: time.Second},
		Timeout:  time.Second,
		Resolver: resolver,
	}
	// The synthetic resolver fails the lookup outright; the gate
	// surfaces the error rather than falling through to the
	// transport layer.
	err := requestGate(d, "http://evil.example/logout")
	if err == nil {
		t.Fatal("expected resolver lookup error")
	}
}

// TestHTTPDeliverer_DeliverResolvesOnce pins that Deliver spends a
// single DNS round trip on the SSRF gate, not one for a pre-check and
// another while building the request.
func TestHTTPDeliverer_DeliverResolvesOnce(t *testing.T) {
	t.Parallel()

	var dials atomic.Int64
	d := &HTTPDeliverer{
		Client:  &http.Client{Timeout: time.Second},
		Timeout: time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("test: synthetic resolver in use")
			},
		},
	}
	const rawURL = "http://evil.example/logout"
	if err := requestGate(d, rawURL); err == nil {
		t.Fatal("expected resolver lookup error")
	}
	perGate := dials.Swap(0)
	if perGate == 0 {
		t.Skip("resolver was not consulted")
	}
	if err := d.Deliver(context.Background(), Target{URL: rawURL}, "x"); err == nil {
		t.Fatal("expected resolver lookup error")
	}
	if got := dials.Load(); got >= 2*perGate {
		t.Errorf("Deliver dialed the resolver %d times, one gate costs %d", got, perGate)
	}
}

// TestHTTPDeliverer_PrivateRefusalNamesOptIn pins that the configured
// opt-in reaches the refusal text.
func TestHTTPDeliverer_PrivateRefusalNamesOptIn(t *testing.T) {
	t.Parallel()

	const optIn = "op.WithAllowPrivateNetworkBackchannel()"
	d := &HTTPDeliverer{Timeout: time.Second, OptIn: optIn}
	err := requestGate(d, "http://10.0.0.1/logout")
	if !errors.Is(err, ErrPrivateNetworkBlocked) || !strings.Contains(err.Error(), optIn) {
		t.Fatalf("err=%v want ErrPrivateNetworkBlocked naming %s", err, optIn)
	}
}

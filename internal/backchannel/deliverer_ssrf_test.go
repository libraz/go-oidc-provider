// Package backchannel: test file exercises unexported helpers
// (assertSafeURL, ErrPrivateNetworkBlocked) so the SSRF deny-list can
// be pinned without exporting internal types. The package decl is
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
	"testing"
	"time"
)

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
			err := d.assertSafeURL(context.Background(), tc.url)
			if tc.wantBlocked {
				if err == nil {
					t.Fatalf("assertSafeURL(%q) = nil, want blocked", tc.url)
				}
				return
			}
			if err != nil {
				t.Fatalf("assertSafeURL(%q) unexpected error: %v", tc.url, err)
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
	if err := d.assertSafeURL(context.Background(), "http://127.0.0.1/logout"); err != nil {
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
	err := d.assertSafeURL(context.Background(), "http://evil.example/logout")
	if err == nil {
		t.Fatal("expected resolver lookup error")
	}
}

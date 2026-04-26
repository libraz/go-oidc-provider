package proxy_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/proxy"
)

// newRequest builds an [http.Request] suitable for [proxy.Resolve] tests
// without tripping the noctx linter. It uses [httptest.NewRequestWithContext]
// internally so the resulting request carries a real context.
func newRequest(tb testing.TB, target string) *http.Request {
	tb.Helper()
	return httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
}

func TestNewTrust_RejectsInvalidCIDR(t *testing.T) {
	t.Parallel()

	cases := map[string][]string{
		"empty":         {""},
		"not_cidr":      {"10.0.0.1"},
		"bad_prefix":    {"10.0.0.0/40"},
		"non_address":   {"banana/8"},
		"trailing_text": {"10.0.0.0/8x"},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := proxy.NewTrust(in); err == nil {
				t.Errorf("NewTrust(%q) err=nil want non-nil", in)
			}
		})
	}
}

func TestNewTrust_EmptyIsValid(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrust(nil)
	if err != nil {
		t.Fatalf("NewTrust(nil): %v", err)
	}
	if tr.IsConfigured() {
		t.Error("empty trust must report IsConfigured=false")
	}
}

func TestResolve_NoTrust_IgnoresForwardedHeaders(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrust(nil)
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "203.0.113.5:5555"
	req.Header.Set("X-Forwarded-For", "192.0.2.1")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "evil.example.com")

	got := proxy.Resolve(req, tr)
	if got.Trusted {
		t.Error("Trusted must be false when trust is empty")
	}
	if got.ClientIP.String() != "203.0.113.5" {
		t.Errorf("ClientIP=%v want 203.0.113.5", got.ClientIP)
	}
	if got.Scheme != "http" {
		t.Errorf("Scheme=%q want http (XFP must be ignored)", got.Scheme)
	}
	if got.Host != "op.example.com" {
		t.Errorf("Host=%q want op.example.com", got.Host)
	}
}

func TestResolve_UntrustedRemote_IgnoresForwardedHeaders(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrust([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "203.0.113.5:5555" // not in 10.0.0.0/8
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	req.Header.Set("X-Forwarded-Proto", "https")

	got := proxy.Resolve(req, tr)
	if got.Trusted {
		t.Error("Trusted must be false when RemoteAddr is outside trust")
	}
	if got.ClientIP.String() != "203.0.113.5" {
		t.Errorf("ClientIP=%v want 203.0.113.5 (XFF spoof rejected)", got.ClientIP)
	}
	if got.Scheme == "https" {
		t.Error("Scheme=https must not leak from untrusted XFP")
	}
}

func TestResolve_TrustedRemote_HonoursForwardedHeaders(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrust([]string{"10.0.0.0/8", "172.16.0.0/12"})
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "10.1.2.3:7777"
	// Two trusted hops on the right; client at the left.
	req.Header.Set("X-Forwarded-For", "198.51.100.99, 10.5.5.5, 172.16.4.4")
	req.Header.Set("X-Forwarded-Proto", "HTTPS")
	req.Header.Set("X-Forwarded-Host", "op.public.example.com")

	got := proxy.Resolve(req, tr)
	if !got.Trusted {
		t.Fatal("Trusted must be true when RemoteAddr is inside trust")
	}
	if got.ClientIP.String() != "198.51.100.99" {
		t.Errorf("ClientIP=%v want 198.51.100.99 (first non-trusted hop)", got.ClientIP)
	}
	if got.Scheme != "https" {
		t.Errorf("Scheme=%q want https (lower-cased)", got.Scheme)
	}
	if got.Host != "op.public.example.com" {
		t.Errorf("Host=%q want forwarded host", got.Host)
	}
}

func TestResolve_TrustedRemote_FullXFFFromTrustedHops_FallsBackToRemoteAddr(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrust([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "10.1.1.1:80"
	req.Header.Set("X-Forwarded-For", "10.2.2.2, 10.3.3.3")

	got := proxy.Resolve(req, tr)
	if !got.Trusted {
		t.Fatal("Trusted must be true")
	}
	// All hops are trusted -> no real client IP found in XFF, fall back to RemoteAddr.
	if got.ClientIP.String() != "10.1.1.1" {
		t.Errorf("ClientIP=%v want 10.1.1.1 (RemoteAddr fallback)", got.ClientIP)
	}
}

func TestResolve_TrustedRemote_MalformedXFF_FallsBackToRemoteAddr(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrust([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "10.1.1.1:80"
	req.Header.Set("X-Forwarded-For", "not-an-ip")

	got := proxy.Resolve(req, tr)
	if got.ClientIP.String() != "10.1.1.1" {
		t.Errorf("ClientIP=%v want 10.1.1.1 (malformed XFF rejected)", got.ClientIP)
	}
}

func TestResolve_IPv6Trust(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrust([]string{"2400:cb00::/32"})
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "[2400:cb00::1]:443"
	req.Header.Set("X-Forwarded-For", "2001:db8::42")

	got := proxy.Resolve(req, tr)
	if !got.Trusted {
		t.Fatal("Trusted must be true for IPv6 in CIDR")
	}
	want := netip.MustParseAddr("2001:db8::42")
	if got.ClientIP != want {
		t.Errorf("ClientIP=%v want %v", got.ClientIP, want)
	}
}

func TestResolve_HTTPSDerivedFromTLS(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrust(nil)
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}
	req := newRequest(t, "https://op.example.com/x")
	req.TLS = &tls.ConnectionState{} // mark request as TLS-terminated
	req.RemoteAddr = "203.0.113.1:80"

	got := proxy.Resolve(req, tr)
	if got.Scheme != "https" {
		t.Errorf("Scheme=%q want https from TLS state", got.Scheme)
	}
}

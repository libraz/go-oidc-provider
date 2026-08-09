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

// TestResolve_TrustedRemote_ForwardedChains covers multi-hop deployments,
// where each proxy appends its own view of the scheme and host. Reading the
// header verbatim yields "https, https" as the scheme, which corrupts every
// issuer-relative URL and breaks the DPoP htu comparison.
func TestResolve_TrustedRemote_ForwardedChains(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrust([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}

	tests := []struct {
		name       string
		proto      []string
		host       []string
		wantScheme string
		wantHost   string
	}{
		{
			name:       "comma separated chain",
			proto:      []string{"https, https"},
			host:       []string{"op.public.example.com, op.public.example.com"},
			wantScheme: "https",
			wantHost:   "op.public.example.com",
		},
		{
			name:       "repeated header lines",
			proto:      []string{"https", "http"},
			host:       []string{"op.public.example.com", "inner.example.com"},
			wantScheme: "https",
			wantHost:   "op.public.example.com",
		},
		{
			name:       "unknown scheme falls back to the local view",
			proto:      []string{"gopher"},
			wantScheme: "http",
		},
		{
			name:       "leading empty element is skipped",
			proto:      []string{", https"},
			wantScheme: "https",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := newRequest(t, "http://op.example.com/x")
			req.RemoteAddr = "10.1.2.3:7777"
			for _, v := range tc.proto {
				req.Header.Add("X-Forwarded-Proto", v)
			}
			for _, v := range tc.host {
				req.Header.Add("X-Forwarded-Host", v)
			}

			got := proxy.Resolve(req, tr)
			if got.Scheme != tc.wantScheme {
				t.Errorf("Scheme=%q want %q", got.Scheme, tc.wantScheme)
			}
			if tc.wantHost != "" && got.Host != tc.wantHost {
				t.Errorf("Host=%q want %q", got.Host, tc.wantHost)
			}
		})
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

func TestResolve_TrustedRemote_MalformedTokenSkippedNotAborted(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrust([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "10.1.1.1:80"
	// Mix a malformed token with valid client and trusted-proxy entries.
	// The walker must skip "junk" and still surface 198.51.100.42 as the
	// authoritative client IP.
	req.Header.Set("X-Forwarded-For", "198.51.100.42, junk, 10.5.5.5")

	got := proxy.Resolve(req, tr)
	if got.ClientIP.String() != "198.51.100.42" {
		t.Errorf("ClientIP=%v want 198.51.100.42 (skip-on-error preserves earlier valid token)", got.ClientIP)
	}
}

func TestResolve_TrustedRemote_XFHAllowlistAccepts(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrustWithHosts(
		[]string{"10.0.0.0/8"},
		[]string{"op.public.example.com"},
	)
	if err != nil {
		t.Fatalf("NewTrustWithHosts: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "10.1.1.1:80"
	req.Header.Set("X-Forwarded-Host", "op.public.example.com")

	got := proxy.Resolve(req, tr)
	if got.Host != "op.public.example.com" {
		t.Errorf("Host=%q want op.public.example.com", got.Host)
	}
}

func TestResolve_TrustedRemote_XFHAllowlistRejectsForeignHost(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrustWithHosts(
		[]string{"10.0.0.0/8"},
		[]string{"op.public.example.com"},
	)
	if err != nil {
		t.Fatalf("NewTrustWithHosts: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "10.1.1.1:80"
	// Even though the request comes from a trusted proxy, the XFH value
	// is client-supplied and the allowlist must override.
	req.Header.Set("X-Forwarded-Host", "evil.example.com")

	got := proxy.Resolve(req, tr)
	if got.Host != "op.example.com" {
		t.Errorf("Host=%q want op.example.com (XFH allowlist rejected forgery)", got.Host)
	}
}

func TestResolve_TrustedRemote_XFHAllowlistEmpty_PreservesLegacy(t *testing.T) {
	t.Parallel()

	// An empty allowlist preserves the pre-hardening behaviour of honouring
	// any XFH value from a trusted proxy.
	tr, err := proxy.NewTrust([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "10.1.1.1:80"
	req.Header.Set("X-Forwarded-Host", "anything.example.com")

	got := proxy.Resolve(req, tr)
	if got.Host != "anything.example.com" {
		t.Errorf("Host=%q want anything.example.com (legacy passthrough)", got.Host)
	}
}

func TestResolve_TrustedRemote_XFHAllowlistStripsPort(t *testing.T) {
	t.Parallel()

	tr, err := proxy.NewTrustWithHosts(
		[]string{"10.0.0.0/8"},
		[]string{"op.public.example.com"},
	)
	if err != nil {
		t.Fatalf("NewTrustWithHosts: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "10.1.1.1:80"
	req.Header.Set("X-Forwarded-Host", "op.public.example.com:8443")

	got := proxy.Resolve(req, tr)
	if got.Host != "op.public.example.com:8443" {
		t.Errorf("Host=%q want op.public.example.com:8443 (port preserved)", got.Host)
	}
}

func TestResolve_TrustedRemote_XFFIPv6Forms(t *testing.T) {
	t.Parallel()

	// RFC 7239 §4 allows IPv6 literals to appear bare, bracketed, or
	// bracketed-with-port inside X-Forwarded-For. The proxy walker must
	// normalise the three representations to the same netip.Addr so a
	// single CIDR rule covers a fronting proxy regardless of which
	// concrete syntax it emits.
	tr, err := proxy.NewTrust([]string{"2400:cb00::/32"})
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}
	want := netip.MustParseAddr("2001:db8::1")
	cases := map[string]string{
		"bare":              "2001:db8::1",
		"bracketed":         "[2001:db8::1]",
		"bracketed_w_port":  "[2001:db8::1]:443",
		"loopback_brackets": "[::1]",
	}
	wants := map[string]netip.Addr{
		"bare":              want,
		"bracketed":         want,
		"bracketed_w_port":  want,
		"loopback_brackets": netip.MustParseAddr("::1"),
	}
	for name, xff := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := newRequest(t, "http://op.example.com/x")
			req.RemoteAddr = "[2400:cb00::1]:443"
			req.Header.Set("X-Forwarded-For", xff)

			got := proxy.Resolve(req, tr)
			if !got.Trusted {
				t.Fatal("Trusted must be true (proxy IP inside trusted CIDR)")
			}
			if got.ClientIP != wants[name] {
				t.Errorf("ClientIP=%v want %v (xff=%q)", got.ClientIP, wants[name], xff)
			}
		})
	}
}

func TestResolve_TrustedRemote_XFFIPv6Mixed(t *testing.T) {
	t.Parallel()

	// A multi-hop XFF chain that mixes IPv6 representations resolves the
	// first non-trusted hop regardless of which syntax it uses.
	tr, err := proxy.NewTrust([]string{"2400:cb00::/32"})
	if err != nil {
		t.Fatalf("NewTrust: %v", err)
	}
	req := newRequest(t, "http://op.example.com/x")
	req.RemoteAddr = "[2400:cb00::1]:443"
	// Client-on-the-left, two trusted hops on the right; the right-most
	// hop arrives bracketed-with-port.
	req.Header.Set("X-Forwarded-For", "2001:db8::42, [2400:cb00::5], [2400:cb00::6]:443")

	got := proxy.Resolve(req, tr)
	if !got.Trusted {
		t.Fatal("Trusted must be true")
	}
	if got.ClientIP != netip.MustParseAddr("2001:db8::42") {
		t.Errorf("ClientIP=%v want 2001:db8::42 (first non-trusted hop)", got.ClientIP)
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

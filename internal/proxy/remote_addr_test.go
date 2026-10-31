package proxy_test

import (
	"net/netip"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/proxy"
)

// TestResolve_ClientIPFromRemoteAddr pins the shapes RemoteAddr may take
// when no forwarding is trusted; they parse exactly like an XFF token.
func TestResolve_ClientIPFromRemoteAddr(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		remote string
		want   netip.Addr
	}{
		{"ipv4_port", "192.0.2.7:4711", netip.MustParseAddr("192.0.2.7")},
		{"ipv4_bare", "192.0.2.7", netip.MustParseAddr("192.0.2.7")},
		{"ipv6_bracket_port", "[2001:db8::1]:443", netip.MustParseAddr("2001:db8::1")},
		{"ipv6_bare", "2001:db8::1", netip.MustParseAddr("2001:db8::1")},
		{"ipv6_bracket_no_port", "[::1]", netip.MustParseAddr("::1")},
		{"ipv4_mapped_unmapped", "[::ffff:192.0.2.7]:80", netip.MustParseAddr("192.0.2.7")},
		{"empty", "", netip.Addr{}},
		{"garbage", "not-an-ip:80", netip.Addr{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRequest(t, "/")
			r.RemoteAddr = tc.remote
			if got := proxy.Resolve(r, nil).ClientIP; got != tc.want {
				t.Errorf("ClientIP(%q) = %v, want %v", tc.remote, got, tc.want)
			}
		})
	}
}

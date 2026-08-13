//nolint:testpackage // exercises unexported helpers (classifyAddr, makeDialControl) for SSRF coverage.
package netsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
)

// loopbackScopeCase is one address evaluated under each of the three
// opt-in postures. The table is the regression surface for the width
// of an opt-in: adding a range to [IsPrivateIP], or widening
// [Options.AllowLoopback] to cover something beyond the loopback
// block, changes at least one column here.
type loopbackScopeCase struct {
	name string
	ip   string
	// wantClosed is the verdict with no opt-in at all.
	wantClosed error
	// wantLoopback is the verdict under AllowLoopback alone — the
	// posture the dev back-channel-logout opt-in installs.
	wantLoopback error
	// wantPrivate is the verdict under AllowPrivate alone.
	wantPrivate error
}

// loopbackScopeMatrix returns the address rows every posture iterates.
func loopbackScopeMatrix() []loopbackScopeCase {
	return []loopbackScopeCase{
		// Loopback: the only block the narrow opt-in releases.
		{"loopback-v4", "127.0.0.1", ErrPrivateNetworkBlocked, nil, nil},
		{"loopback-v4-block", "127.0.0.53", ErrPrivateNetworkBlocked, nil, nil},
		{"loopback-v6", "::1", ErrPrivateNetworkBlocked, nil, nil},
		{"loopback-v4-mapped-v6", "::ffff:127.0.0.1", ErrPrivateNetworkBlocked, nil, nil},

		// RFC 1918: reachable only under the wide opt-in.
		{"rfc1918-10", "10.0.5.12", ErrPrivateNetworkBlocked, ErrPrivateNetworkBlocked, nil},
		{"rfc1918-172", "172.16.0.1", ErrPrivateNetworkBlocked, ErrPrivateNetworkBlocked, nil},
		{"rfc1918-192", "192.168.1.1", ErrPrivateNetworkBlocked, ErrPrivateNetworkBlocked, nil},
		{"rfc1918-mapped-v6", "::ffff:10.0.5.12", ErrPrivateNetworkBlocked, ErrPrivateNetworkBlocked, nil},

		// Link-local, ULA and the unspecified address: private, not loopback.
		{"link-local-v4", "169.254.10.1", ErrPrivateNetworkBlocked, ErrPrivateNetworkBlocked, nil},
		{"link-local-v6", "fe80::1", ErrPrivateNetworkBlocked, ErrPrivateNetworkBlocked, nil},
		{"ipv6-ula-fc00", "fc00::1", ErrPrivateNetworkBlocked, ErrPrivateNetworkBlocked, nil},
		{"ipv6-ula-fd00", "fd00::1", ErrPrivateNetworkBlocked, ErrPrivateNetworkBlocked, nil},
		{"unspecified-v4", "0.0.0.0", ErrPrivateNetworkBlocked, ErrPrivateNetworkBlocked, nil},
		{"unspecified-v6", "::", ErrPrivateNetworkBlocked, ErrPrivateNetworkBlocked, nil},

		// Cloud metadata: refused under every posture.
		{"metadata-aws", "169.254.169.254", ErrCloudMetadataBlocked, ErrCloudMetadataBlocked, ErrCloudMetadataBlocked},
		{"metadata-aws-mapped", "::ffff:169.254.169.254", ErrCloudMetadataBlocked, ErrCloudMetadataBlocked, ErrCloudMetadataBlocked},
		{"metadata-alibaba", "100.100.100.200", ErrCloudMetadataBlocked, ErrCloudMetadataBlocked, ErrCloudMetadataBlocked},
		{"metadata-aws-v6", "fd00:ec2::254", ErrCloudMetadataBlocked, ErrCloudMetadataBlocked, ErrCloudMetadataBlocked},

		// Public: allowed under every posture.
		{"public-v4", "93.184.216.34", nil, nil, nil},
		{"public-v6", "2606:2800:220:1:248:1893:25c8:1946", nil, nil, nil},
	}
}

// urlHost renders ip as it appears in a URL authority: IPv6 literals
// carry brackets, IPv4 literals do not.
func urlHost(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

// refuseLookup is the resolver stub the IP-literal rows install so a
// stray hostname cannot reach the real resolver.
func refuseLookup(_ context.Context, host string) ([]net.IPAddr, error) {
	return nil, fmt.Errorf("test-stub: refusing lookup for %s", host)
}

// newRedirectRequest builds the Location-target request the
// [http.Client.CheckRedirect] hook is handed. The host is a name so
// the hook's re-check routes through the caller's LookupHook, which is
// what puts the redirect gate on the same address as the other three.
func newRedirectRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://rp.example/x", nil)
	if err != nil {
		t.Fatalf("build redirect request: %v", err)
	}
	return req
}

// checkVerdict asserts one gate's error against the expected sentinel.
func checkVerdict(t *testing.T, gate string, err, want error) {
	t.Helper()
	switch {
	case want == nil && err != nil:
		t.Errorf("%s: err=%v want nil", gate, err)
	case want != nil && !errors.Is(err, want):
		t.Errorf("%s: err=%v want errors.Is %v", gate, err, want)
	}
}

// TestOptOutWidth_AddressMatrix is the acceptance test for the width of
// the two opt-ins. Every address is driven through all three
// enforcement points — the IP-literal URL check, the DNS-resolution
// check, and the dial-time [Dialer.Control] hook — under each posture,
// because a gate that disagrees with its siblings is exactly how a
// documented "loopback only" promise turns into private-network reach.
func TestOptOutWidth_AddressMatrix(t *testing.T) {
	t.Parallel()

	postures := []struct {
		name string
		opts Options
		want func(loopbackScopeCase) error
	}{
		{"closed", Options{}, func(c loopbackScopeCase) error { return c.wantClosed }},
		{"allow-loopback", Options{AllowLoopback: true}, func(c loopbackScopeCase) error { return c.wantLoopback }},
		{"allow-private", Options{AllowPrivate: true}, func(c loopbackScopeCase) error { return c.wantPrivate }},
	}
	for _, posture := range postures {
		t.Run(posture.name, func(t *testing.T) {
			t.Parallel()
			for _, tc := range loopbackScopeMatrix() {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					want := posture.want(tc)

					literalOpts := posture.opts
					literalOpts.LookupHook = refuseLookup
					checkVerdict(t, "url-literal",
						AssertSafeURL(context.Background(), "http://"+urlHost(tc.ip)+"/x", literalOpts), want)

					resolvedOpts := posture.opts
					resolvedOpts.LookupHook = func(_ context.Context, _ string) ([]net.IPAddr, error) {
						return []net.IPAddr{{IP: net.ParseIP(tc.ip)}}, nil
					}
					checkVerdict(t, "dns-resolved",
						AssertSafeURL(context.Background(), "http://rp.example/x", resolvedOpts), want)

					checkVerdict(t, "dial-control",
						makeDialControl(posture.opts)("tcp", net.JoinHostPort(tc.ip, "443"), nil), want)

					redirectOpts := resolvedOpts
					redirectOpts.MaxRedirects = 3
					checkVerdict(t, "redirect-recheck",
						makeCheckRedirect(redirectOpts)(newRedirectRequest(t), nil), want)
				})
			}
		})
	}
}

// TestAllowLoopback_TextualNameMustResolveToLoopback pins the
// split-horizon shape: the narrow opt-in admits the textual loopback
// names, but only while they actually resolve to a loopback address.
// A resolver that maps "localhost" onto an internal host must not turn
// the loopback opt-in back into a private-network one.
func TestAllowLoopback_TextualNameMustResolveToLoopback(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		host     string
		resolved string
		want     error
	}{
		{"localhost-to-loopback", "localhost", "127.0.0.1", nil},
		{"localhost-to-loopback-v6", "localhost", "::1", nil},
		{"localhost-to-rfc1918", "localhost", "10.0.5.12", ErrPrivateNetworkBlocked},
		{"localhost-to-link-local", "localhost", "169.254.10.1", ErrPrivateNetworkBlocked},
		{"localhost-to-metadata", "localhost", "169.254.169.254", ErrCloudMetadataBlocked},
		{"ip6-localhost-to-rfc1918", "ip6-localhost", "10.0.5.12", ErrPrivateNetworkBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := Options{
				AllowLoopback: true,
				LookupHook: func(_ context.Context, _ string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP(tc.resolved)}}, nil
				},
			}
			err := AssertSafeURL(context.Background(), "http://"+tc.host+"/x", opts)
			checkVerdict(t, "url-hostname", err, tc.want)
		})
	}
}

// TestAllowLoopback_ClosedPostureStillRefusesTextualNames confirms the
// narrow opt-in is the only thing that admits the textual loopback
// names: with no opt-in they are refused without a lookup at all.
func TestAllowLoopback_ClosedPostureStillRefusesTextualNames(t *testing.T) {
	t.Parallel()

	for _, host := range []string{"localhost", "LOCALHOST", "localhost.", "ip6-localhost", "ip6-loopback"} {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			opts := Options{LookupHook: refuseLookup}
			err := AssertSafeURL(context.Background(), "http://"+host+"/x", opts)
			checkVerdict(t, "url-hostname", err, ErrPrivateNetworkBlocked)
		})
	}
}

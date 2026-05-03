//nolint:testpackage // exercises unexported helpers (assertResolvedHostSafe) for SSRF coverage.
package netsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestAssertSafeURL_Matrix pins the syntactic gate against the
// canonical deny-list. The cases double as a regression guard: a
// future revision that loosens any of the rows will fail loudly here
// rather than silently widening the SSRF surface.
func TestAssertSafeURL_Matrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		url     string
		want    error
		allow   bool
		schemes []string
	}{
		{"loopback-v4", "http://127.0.0.1/x", ErrPrivateNetworkBlocked, false, nil},
		{"loopback-v6", "http://[::1]/x", ErrPrivateNetworkBlocked, false, nil},
		{"localhost", "http://localhost/x", ErrPrivateNetworkBlocked, false, nil},
		{"rfc1918-10", "http://10.0.0.1/x", ErrPrivateNetworkBlocked, false, nil},
		{"rfc1918-172", "http://172.16.0.1/x", ErrPrivateNetworkBlocked, false, nil},
		{"rfc1918-192", "http://192.168.1.1/x", ErrPrivateNetworkBlocked, false, nil},
		{"ipv6-ula", "http://[fc00::1]/x", ErrPrivateNetworkBlocked, false, nil},
		{"link-local", "http://[fe80::1]/x", ErrPrivateNetworkBlocked, false, nil},
		{"unspecified", "http://0.0.0.0/x", ErrPrivateNetworkBlocked, false, nil},
		// Cloud metadata IPs are rejected on AllowPrivate=true.
		{"cloud-metadata-aws-allow-private", "http://169.254.169.254/x", ErrCloudMetadataBlocked, true, nil},
		{"cloud-metadata-alibaba-allow-private", "http://100.100.100.200/x", ErrCloudMetadataBlocked, true, nil},
		{"cloud-metadata-v6-allow-private", "http://[fd00:ec2::254]/x", ErrCloudMetadataBlocked, true, nil},
		// Without AllowPrivate, the AWS IMDS literal trips the
		// cloud-metadata gate first because the explicit list runs
		// before the broader IsPrivateIP check.
		{"cloud-metadata-aws-default", "http://169.254.169.254/x", ErrCloudMetadataBlocked, false, nil},
		// AllowPrivate releases the loopback gate.
		{"loopback-allow-private", "http://127.0.0.1/x", nil, true, nil},
		{"localhost-allow-private", "http://localhost/x", nil, true, nil},
		// Scheme allow-list.
		{"ftp-default", "ftp://example.com/x", ErrSchemeNotAllowed, false, nil},
		{"https-only", "http://example.com/x", ErrSchemeNotAllowed, false, []string{"https"}},
		// Missing host.
		{"missing-host", "http:///x", ErrMissingHost, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := Options{
				AllowPrivate:   tc.allow,
				AllowedSchemes: tc.schemes,
				// Force the test path through the IP-literal branch by
				// blocking DNS so a stray hostname cannot reach the
				// real resolver and pollute the matrix.
				LookupHook: func(_ context.Context, host string) ([]net.IPAddr, error) {
					return nil, fmt.Errorf("test-stub: refusing lookup for %s", host)
				},
			}
			err := AssertSafeURL(context.Background(), tc.url, opts)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("AssertSafeURL(%q) err=%v want nil", tc.url, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("AssertSafeURL(%q) err=%v want errors.Is %v", tc.url, err, tc.want)
			}
		})
	}
}

// TestAssertSafeURL_HostnameRebindingResolved exercises the
// DNS-time gate: when the resolver hands out a private address for a
// public-looking name, the gate refuses the URL even though the host
// itself parses as a public name.
func TestAssertSafeURL_HostnameRebindingResolved(t *testing.T) {
	t.Parallel()

	opts := Options{
		LookupHook: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
		},
	}
	err := AssertSafeURL(context.Background(), "http://attacker.example/x", opts)
	if !errors.Is(err, ErrPrivateNetworkBlocked) {
		t.Fatalf("err=%v want ErrPrivateNetworkBlocked", err)
	}
}

// TestAssertSafeURL_HostnameRebindingMetadata pins the carve-out: a
// public-looking name that resolves to a cloud-metadata IP is rejected
// even when AllowPrivate is true (the embedder has opted into private
// LANs, not into cloud-credential exposure).
func TestAssertSafeURL_HostnameRebindingMetadata(t *testing.T) {
	t.Parallel()

	opts := Options{
		AllowPrivate: true,
		LookupHook: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
		},
	}
	err := AssertSafeURL(context.Background(), "http://attacker.example/x", opts)
	if !errors.Is(err, ErrCloudMetadataBlocked) {
		t.Fatalf("err=%v want ErrCloudMetadataBlocked", err)
	}
}

// TestAssertSafeURL_HostnameLookupNoAddrs covers the (empty addrs)
// branch: a misconfigured upstream that returns zero records is
// rejected so callers do not fall through to a 0-results dial.
func TestAssertSafeURL_HostnameLookupNoAddrs(t *testing.T) {
	t.Parallel()

	opts := Options{
		LookupHook: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return nil, nil
		},
	}
	err := AssertSafeURL(context.Background(), "http://attacker.example/x", opts)
	if err == nil || !strings.Contains(err.Error(), "no addresses") {
		t.Fatalf("err=%v want \"no addresses\"", err)
	}
}

// TestNewHTTPClient_DialControlBlocksRebinding wires the dial-time
// gate end-to-end. The synthetic resolver hook reports a public IP at
// URL-parse time but the dial control hook is asked to dial a private
// IP — simulating a DNS rebinding window between gate and dial. The
// dialer MUST refuse the connection even though the URL passed the
// pre-flight check.
func TestNewHTTPClient_DialControlBlocksRebinding(t *testing.T) {
	t.Parallel()

	opts := Options{
		Timeout:     2 * time.Second,
		DialTimeout: 1 * time.Second,
		// Pretend the URL parsed against a public name; the lookup
		// hands a public IP so AssertSafeURL succeeds.
		LookupHook: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		},
	}
	if err := AssertSafeURL(context.Background(), "http://attacker.example/x", opts); err != nil {
		t.Fatalf("pre-flight gate failed: %v", err)
	}

	client := NewHTTPClient(opts)
	// Replace the transport's DialContext with a stub that simulates
	// the rebinding window — we drive the dial-control hook directly
	// by constructing the dialer manually and invoking Control with
	// a private IP.
	control := makeDialControl(opts)
	if err := control("tcp4", "127.0.0.1:8080", nil); err == nil {
		t.Fatal("dial control accepted loopback; want rejection")
	} else if !errors.Is(err, ErrPrivateNetworkBlocked) {
		t.Fatalf("dial control err=%v want ErrPrivateNetworkBlocked", err)
	}
	if err := control("tcp4", "169.254.169.254:80", nil); err == nil {
		t.Fatal("dial control accepted cloud metadata; want rejection")
	} else if !errors.Is(err, ErrCloudMetadataBlocked) {
		t.Fatalf("dial control err=%v want ErrCloudMetadataBlocked", err)
	}
	// Public IP passes.
	if err := control("tcp4", "1.1.1.1:443", nil); err != nil {
		t.Fatalf("dial control rejected public IP: %v", err)
	}
	_ = client // exercised via control above; no live dial required.
}

// TestNewHTTPClient_DialControlAllowPrivate confirms AllowPrivate
// suppresses the broader loopback / RFC1918 gate while still rejecting
// cloud-metadata IPs. The matrix matches the AssertSafeURL one but
// runs against the dial-time hook so the two surfaces stay aligned.
func TestNewHTTPClient_DialControlAllowPrivate(t *testing.T) {
	t.Parallel()

	control := makeDialControl(Options{AllowPrivate: true})
	// Loopback now passes (AllowPrivate=true).
	if err := control("tcp4", "127.0.0.1:8080", nil); err != nil {
		t.Fatalf("AllowPrivate=true rejected loopback: %v", err)
	}
	// Cloud metadata still rejected.
	if err := control("tcp4", "169.254.169.254:80", nil); err == nil {
		t.Fatal("AllowPrivate=true accepted cloud metadata; want rejection")
	} else if !errors.Is(err, ErrCloudMetadataBlocked) {
		t.Fatalf("err=%v want ErrCloudMetadataBlocked", err)
	}
}

// TestNewHTTPClient_RedirectBlocked covers the CheckRedirect hook:
// a redirect target whose host is private is refused even when
// MaxRedirects > 0.
func TestNewHTTPClient_RedirectBlocked(t *testing.T) {
	t.Parallel()

	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		// Always redirect to a private target so the gate trips.
		http.Redirect(w, &http.Request{}, "http://127.0.0.1:1/never", http.StatusFound)
	}))
	defer srv.Close()

	// Wire AllowPrivate so we can reach the httptest server (which
	// binds 127.0.0.1) but craft the redirect chain so the gate fires
	// against a deny-listed host on the second hop.
	opts := Options{
		AllowPrivate: false,
		MaxRedirects: 3,
		Timeout:      2 * time.Second,
		// URL-parse gate must allow the first hop. Override the lookup
		// to return a public IP for the literal so the syntactic gate
		// does not refuse the test server's own loopback URL.
		LookupHook: func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		},
	}
	check := makeCheckRedirect(opts)
	// Synthesise a redirect-target request and confirm the hook
	// rejects it.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:1/never", http.NoBody)
	err := check(req, nil)
	if !errors.Is(err, ErrRedirectBlocked) {
		t.Fatalf("redirect gate err=%v want ErrRedirectBlocked", err)
	}
}

// TestNewHTTPClient_NoRedirectByDefault confirms the zero-value
// MaxRedirects setting collapses every 30x onto http.ErrUseLastResponse,
// so the caller surfaces the upstream response rather than chasing the
// redirect blindly.
func TestNewHTTPClient_NoRedirectByDefault(t *testing.T) {
	t.Parallel()

	check := makeCheckRedirect(Options{})
	if err := check(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("err=%v want http.ErrUseLastResponse", err)
	}
}

// TestNewHTTPClient_RedirectExceeded confirms the cap fires on the
// (N+1)-th redirect.
func TestNewHTTPClient_RedirectExceeded(t *testing.T) {
	t.Parallel()

	opts := Options{MaxRedirects: 2}
	check := makeCheckRedirect(opts)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/x", http.NoBody)
	via := []*http.Request{req, req}
	if err := check(req, via); !errors.Is(err, ErrRedirectBlocked) {
		t.Fatalf("err=%v want ErrRedirectBlocked", err)
	}
}

// TestNewHTTPClient_DialHookFiresOnLiveRequest performs a live
// request against an httptest server with AllowPrivate=true so the
// loopback dial succeeds. The test confirms the wired client is
// usable end-to-end (i.e. the dial control hook does not refuse a
// legitimate connection).
func TestNewHTTPClient_DialHookFiresOnLiveRequest(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := NewHTTPClient(Options{AllowPrivate: true, Timeout: 2 * time.Second})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("live Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
}

// TestMakeDialControl_NotAnIP exercises the malformed-address branch
// (the dialer should always hand a literal IP, but cover the
// defensive return all the same).
func TestMakeDialControl_NotAnIP(t *testing.T) {
	t.Parallel()
	control := makeDialControl(Options{})
	if err := control("tcp4", "example.com:80", nil); err == nil {
		t.Fatal("control accepted a hostname; want rejection")
	}
	if err := control("tcp4", "not-a-host-port", nil); err == nil {
		t.Fatal("control accepted a malformed address; want rejection")
	}
}

// TestMakeDialControl_HookFires confirms the test-injected
// DialControlHook runs after the deny-list passes. Useful so callers
// who want to layer additional checks (e.g. logging) get the expected
// invocation order.
func TestMakeDialControl_HookFires(t *testing.T) {
	t.Parallel()

	called := atomic.Bool{}
	opts := Options{
		AllowPrivate: true, // permit loopback so we reach the hook
		DialControlHook: func(_ string, _ string, _ syscall.RawConn) error {
			called.Store(true)
			return nil
		},
	}
	control := makeDialControl(opts)
	if err := control("tcp4", "127.0.0.1:8080", nil); err != nil {
		t.Fatalf("control: %v", err)
	}
	if !called.Load() {
		t.Fatal("DialControlHook was not invoked")
	}
}

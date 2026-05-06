package securefetch_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/netsec"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
)

// TestNewClient_ClampsNegativeMaxBody pins the constructor's
// no-panic posture: a negative cap is a programming bug, but library
// code refuses to panic, so the constructor clamps to the default
// ceiling rather than returning an error or panicking.
func TestNewClient_ClampsNegativeMaxBody(t *testing.T) {
	t.Parallel()

	c := securefetch.NewClient(securefetch.Policy{MaxBodyBytes: -1})
	if got := c.Policy().MaxBodyBytes; got != 0 && got != securefetch.DefaultMaxBody {
		t.Fatalf("MaxBodyBytes=%d after clamp, want 0 (effective DefaultMaxBody) or DefaultMaxBody", got)
	}
}

// TestClient_Get_HappyPath exercises the GET path against a small
// 2xx JSON response. The body cap and content-type allow-list both
// admit the upstream so the helper returns the body bytes verbatim.
func TestClient_Get_HappyPath(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := mustClient(t, securefetch.Policy{
		AllowPrivateNetwork: true, // httptest binds 127.0.0.1.
		AcceptContentTypes:  []string{"application/json"},
	})
	body, resp, err := c.Get(context.Background(), srv.URL) //nolint:bodyclose // securefetch.Get drains and closes the body internally.
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body=%q want JSON", body)
	}
}

// TestClient_Get_RejectsNon2xx pins the status gate. A 500 response
// surfaces as ErrUnexpectedStatus before the body-cap or content-type
// gates run.
func TestClient_Get_RejectsNon2xx(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`oops`))
	}))
	defer srv.Close()

	c := mustClient(t, securefetch.Policy{AllowPrivateNetwork: true})
	_, _, err := c.Get(context.Background(), srv.URL) //nolint:bodyclose // securefetch.Get drains and closes the body internally.
	if !errors.Is(err, securefetch.ErrUnexpectedStatus) {
		t.Fatalf("err=%v want ErrUnexpectedStatus", err)
	}
}

// TestClient_Get_RejectsBadContentType pins the content-type gate.
// A response whose declared media type is outside the policy's
// allow-list surfaces as ErrUnexpectedContentType.
func TestClient_Get_RejectsBadContentType(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html/>`))
	}))
	defer srv.Close()

	c := mustClient(t, securefetch.Policy{
		AllowPrivateNetwork: true,
		AcceptContentTypes:  []string{"application/json"},
	})
	_, _, err := c.Get(context.Background(), srv.URL) //nolint:bodyclose // securefetch.Get drains and closes the body internally.
	if !errors.Is(err, securefetch.ErrUnexpectedContentType) {
		t.Fatalf("err=%v want ErrUnexpectedContentType", err)
	}
}

// TestClient_Get_AcceptContentTypeIgnoresParameters confirms the
// content-type matcher strips ";charset=..." parameters before
// comparing against the allow-list.
func TestClient_Get_AcceptContentTypeIgnoresParameters(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := mustClient(t, securefetch.Policy{
		AllowPrivateNetwork: true,
		AcceptContentTypes:  []string{"application/json"},
	})
	if _, _, err := c.Get(context.Background(), srv.URL); err != nil { //nolint:bodyclose // securefetch.Get drains and closes the body internally.
		t.Fatalf("Get: %v", err)
	}
}

// TestClient_Get_BodyCap pins the body-cap gate. The upstream emits
// MaxBodyBytes+1 bytes; the helper surfaces ErrBodyTooLarge instead
// of silently truncating.
func TestClient_Get_BodyCap(t *testing.T) {
	t.Parallel()

	const limit = 16
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, limit+1))
	}))
	defer srv.Close()

	c := mustClient(t, securefetch.Policy{
		AllowPrivateNetwork: true,
		MaxBodyBytes:        limit,
	})
	_, _, err := c.Get(context.Background(), srv.URL) //nolint:bodyclose // securefetch.Get drains and closes the body internally.
	if !errors.Is(err, securefetch.ErrBodyTooLarge) {
		t.Fatalf("err=%v want ErrBodyTooLarge", err)
	}
}

// TestClient_Post_HappyPath exercises the POST path. The body is
// echoed by the test server; the helper returns the response bytes.
func TestClient_Post_HappyPath(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("content-type=%q", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := mustClient(t, securefetch.Policy{AllowPrivateNetwork: true})
	body, _, err := c.Post(context.Background(), srv.URL, //nolint:bodyclose // securefetch.Post drains and closes the body internally.
		"application/x-www-form-urlencoded",
		strings.NewReader("a=1"),
	)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if string(body) != "a=1" {
		t.Fatalf("echo=%q want a=1", body)
	}
}

// TestClient_DoAndDiscard_HappyPath exercises the back-channel
// shape: the response body is discarded; only the status is
// surfaced.
func TestClient_DoAndDiscard_HappyPath(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 64*1024)))
	}))
	defer srv.Close()

	c := mustClient(t, securefetch.Policy{AllowPrivateNetwork: true})
	req, err := c.NewRequest(context.Background(), http.MethodPost, srv.URL,
		strings.NewReader("ignored"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.DoAndDiscard(req) //nolint:bodyclose // securefetch.DoAndDiscard drains and closes the body internally.
	if err != nil {
		t.Fatalf("DoAndDiscard: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

// TestClient_DoAndDiscard_RejectsNon2xx pins the status gate on the
// discard path: a non-2xx response surfaces as ErrUnexpectedStatus
// even though the body is drained.
func TestClient_DoAndDiscard_RejectsNon2xx(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := mustClient(t, securefetch.Policy{AllowPrivateNetwork: true})
	req, err := c.NewRequest(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := c.DoAndDiscard(req); !errors.Is(err, securefetch.ErrUnexpectedStatus) { //nolint:bodyclose // securefetch.DoAndDiscard drains and closes the body internally.
		t.Fatalf("err=%v want ErrUnexpectedStatus", err)
	}
}

// TestClient_AssertSafeURL_EmptyURL pins the empty-URL fast path.
// The gate fires before any DNS round-trip so a buggy call site
// surfaces deterministically.
func TestClient_AssertSafeURL_EmptyURL(t *testing.T) {
	t.Parallel()
	c := mustClient(t, securefetch.Policy{AllowPrivateNetwork: true})
	if err := c.AssertSafeURL(context.Background(), ""); !errors.Is(err, securefetch.ErrEmptyURL) {
		t.Fatalf("err=%v want ErrEmptyURL", err)
	}
}

// TestClient_NewRequest_EmptyURL pins the empty-URL fast path on
// NewRequest.
func TestClient_NewRequest_EmptyURL(t *testing.T) {
	t.Parallel()
	c := mustClient(t, securefetch.Policy{AllowPrivateNetwork: true})
	_, err := c.NewRequest(context.Background(), http.MethodGet, "", nil)
	if !errors.Is(err, securefetch.ErrEmptyURL) {
		t.Fatalf("err=%v want ErrEmptyURL", err)
	}
}

// TestClient_Get_DefaultsToDefaultMaxBody confirms the zero value of
// Policy.MaxBodyBytes resolves to [DefaultMaxBody]. The upstream
// emits one byte more than the default; the helper surfaces
// ErrBodyTooLarge.
func TestClient_Get_DefaultsToDefaultMaxBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, securefetch.DefaultMaxBody+1))
	}))
	defer srv.Close()

	c := mustClient(t, securefetch.Policy{AllowPrivateNetwork: true})
	_, _, err := c.Get(context.Background(), srv.URL) //nolint:bodyclose // securefetch.Get drains and closes the body internally.
	if !errors.Is(err, securefetch.ErrBodyTooLarge) {
		t.Fatalf("err=%v want ErrBodyTooLarge", err)
	}
}

// TestPolicy_SSRFContract is the contract test the parent task asked
// for: every policy variant the consolidated fetchers use MUST refuse
// the canonical SSRF deny-list. The matrix walks the four production
// policies (JAR JWKS, encryption JWKS, sector, back-channel) plus a
// minimal default; for each the test confirms the URL-time gate
// rejects loopback, RFC 1918, link-local, IPv6 ULA, and cloud-metadata
// hosts. A future revision that loosens any policy fails this test
// loudly rather than silently widening the surface.
func TestPolicy_SSRFContract(t *testing.T) {
	t.Parallel()

	denyURLs := []struct {
		name string
		url  string
		want error
	}{
		{"loopback-v4", "http://127.0.0.1/x", netsec.ErrPrivateNetworkBlocked},
		{"loopback-v6", "http://[::1]/x", netsec.ErrPrivateNetworkBlocked},
		{"localhost", "http://localhost/x", netsec.ErrPrivateNetworkBlocked},
		{"rfc1918-10", "http://10.0.0.1/x", netsec.ErrPrivateNetworkBlocked},
		{"rfc1918-172", "http://172.16.0.1/x", netsec.ErrPrivateNetworkBlocked},
		{"rfc1918-192", "http://192.168.1.1/x", netsec.ErrPrivateNetworkBlocked},
		{"link-local-v4", "http://169.254.1.2/x", netsec.ErrPrivateNetworkBlocked},
		{"link-local-v6", "http://[fe80::1]/x", netsec.ErrPrivateNetworkBlocked},
		{"ipv6-ula", "http://[fc00::1]/x", netsec.ErrPrivateNetworkBlocked},
		{"cloud-metadata-aws", "http://169.254.169.254/x", netsec.ErrCloudMetadataBlocked},
		{"cloud-metadata-alibaba", "http://100.100.100.200/x", netsec.ErrCloudMetadataBlocked},
		{"cloud-metadata-v6", "http://[fd00:ec2::254]/x", netsec.ErrCloudMetadataBlocked},
	}

	policies := []struct {
		name   string
		policy securefetch.Policy
	}{
		{
			name: "jar-jwks",
			policy: securefetch.Policy{
				MaxBodyBytes:       256 * 1024,
				AcceptContentTypes: []string{"application/json", "application/jwk-set+json"},
				Timeout:            5 * time.Second,
			},
		},
		{
			name: "encryption-jwks",
			policy: securefetch.Policy{
				MaxBodyBytes: 64 * 1024,
				Timeout:      5 * time.Second,
			},
		},
		{
			name: "sector",
			policy: securefetch.Policy{
				AllowedSchemes:     []string{"https"},
				MaxBodyBytes:       64 * 1024,
				AcceptContentTypes: []string{"application/json"},
				Timeout:            5 * time.Second,
			},
		},
		{
			name: "backchannel",
			policy: securefetch.Policy{
				MaxBodyBytes: 8 * 1024,
				Timeout:      5 * time.Second,
			},
		},
		{
			name:   "default",
			policy: securefetch.Policy{},
		},
	}

	for _, p := range policies {
		// Force lookup through a stub so a stray hostname cannot reach
		// the real resolver and pollute the matrix.
		policy := p.policy
		policy.LookupHook = func(_ context.Context, host string) ([]net.IPAddr, error) {
			return nil, fmt.Errorf("contract: refusing lookup for %s", host)
		}
		c := securefetch.NewClient(policy)
		for _, u := range denyURLs {
			t.Run(p.name+"/"+u.name, func(t *testing.T) {
				t.Parallel()
				err := c.AssertSafeURL(context.Background(), u.url)
				// The sector policy only allows https, so the http
				// scheme test cases would surface ErrSchemeNotAllowed
				// before the deny-list gate. That is still a refusal,
				// so we accept either sentinel here as long as the
				// gate fired.
				if err == nil {
					t.Fatalf("policy %s: AssertSafeURL(%q) returned nil; want refusal",
						p.name, u.url)
				}
				if errors.Is(err, u.want) {
					return
				}
				if errors.Is(err, netsec.ErrSchemeNotAllowed) && p.name == "sector" {
					// Acceptable: the scheme gate fires first.
					return
				}
				t.Fatalf("policy %s: AssertSafeURL(%q) err=%v want errors.Is %v",
					p.name, u.url, err, u.want)
			})
		}
	}
}

// TestPolicy_SSRFContract_DNSRebinding confirms every policy refuses
// a public-looking hostname whose authoritative DNS hands out a
// private address. The contract pins the URL-time DNS gate; the
// dial-time hook in [netsec.NewHTTPClient] runs independently.
func TestPolicy_SSRFContract_DNSRebinding(t *testing.T) {
	t.Parallel()

	policies := []securefetch.Policy{
		{MaxBodyBytes: 256 * 1024, AcceptContentTypes: []string{"application/json"}},
		{MaxBodyBytes: 64 * 1024},
		{MaxBodyBytes: 64 * 1024, AcceptContentTypes: []string{"application/json"}},
		{MaxBodyBytes: 8 * 1024},
	}
	for i, p := range policies {
		t.Run(fmt.Sprintf("policy-%d", i), func(t *testing.T) {
			t.Parallel()
			p.LookupHook = func(_ context.Context, _ string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
			}
			c := securefetch.NewClient(p)
			err := c.AssertSafeURL(context.Background(), "http://attacker.example/x")
			if !errors.Is(err, netsec.ErrPrivateNetworkBlocked) {
				t.Fatalf("err=%v want ErrPrivateNetworkBlocked", err)
			}
		})
	}
}

// mustClient builds a [*securefetch.Client] or fails the test. The
// helper centralises the constructor-error noise so individual cases
// stay focused on the assertion under test.
func mustClient(t *testing.T, p securefetch.Policy) *securefetch.Client {
	t.Helper()
	return securefetch.NewClient(p)
}

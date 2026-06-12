package op

// Tests in this file live in package op (not op_test) so they can drive
// [wrapWithTrustedProxy] directly without booting a full Provider. The
// middleware's contract is small enough that exercising it through the
// public API would require a working store, signing key, and cookie
// codec — all of which are unrelated to the trust decision the
// middleware makes.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/proxy"
)

// TestWrapWithTrustedProxy_HonoursTrustedHeaders verifies the
// middleware rewrites the URL scheme and Host on the request handed to
// the downstream handler when the source IP is inside the configured
// trust. The downstream handler observes the externally-visible
// values, so issuer matching, redirect_uri scheme checks, and DPoP htu
// canonicalisation all see "https" and the public host even when the
// inbound listener is plain HTTP behind a TLS-terminating proxy.
func TestWrapWithTrustedProxy_HonoursTrustedHeaders(t *testing.T) {
	t.Parallel()

	trust, err := proxy.NewTrust([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("proxy.NewTrust: %v", err)
	}

	var sawScheme, sawHost string
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		sawScheme = r.URL.Scheme
		sawHost = r.Host
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal:8080/.well-known/openid-configuration", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "op.example.com")

	rw := httptest.NewRecorder()
	wrapWithTrustedProxy(h, trust).ServeHTTP(rw, req)

	if sawScheme != "https" {
		t.Errorf("downstream r.URL.Scheme = %q, want %q", sawScheme, "https")
	}
	if sawHost != "op.example.com" {
		t.Errorf("downstream r.Host = %q, want %q", sawHost, "op.example.com")
	}
}

// TestWrapWithTrustedProxy_IgnoresUntrustedHeaders verifies the
// middleware leaves the request untouched when the source IP is not
// inside the configured trust. A hostile client must not be able to
// forge issuer scheme or host by injecting headers.
func TestWrapWithTrustedProxy_IgnoresUntrustedHeaders(t *testing.T) {
	t.Parallel()

	trust, err := proxy.NewTrust([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("proxy.NewTrust: %v", err)
	}

	var sawScheme, sawHost string
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		sawScheme = r.URL.Scheme
		sawHost = r.Host
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal:8080/.well-known/openid-configuration", nil)
	req.RemoteAddr = "203.0.113.5:9999"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "op.example.com")

	rw := httptest.NewRecorder()
	wrapWithTrustedProxy(h, trust).ServeHTTP(rw, req)

	if sawScheme == "https" {
		t.Error("untrusted X-Forwarded-Proto leaked into r.URL.Scheme")
	}
	if sawHost == "op.example.com" {
		t.Error("untrusted X-Forwarded-Host leaked into r.Host")
	}
	if sawHost != "internal:8080" {
		t.Errorf("downstream r.Host = %q, want inbound %q", sawHost, "internal:8080")
	}
}

// TestWrapWithTrustedProxy_EmptyTrustIsNoOp verifies that an empty
// trust (the default when [WithTrustedProxies] is not called) does not
// alter the request — the middleware is wired unconditionally so the
// request flow is uniform across deployments.
func TestWrapWithTrustedProxy_EmptyTrustIsNoOp(t *testing.T) {
	t.Parallel()

	trust, err := proxy.NewTrust(nil)
	if err != nil {
		t.Fatalf("proxy.NewTrust: %v", err)
	}

	var sawHost string
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		sawHost = r.Host
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://op.local/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-Host", "evil.example")

	rw := httptest.NewRecorder()
	wrapWithTrustedProxy(h, trust).ServeHTTP(rw, req)

	if sawHost != "op.local" {
		t.Errorf("empty trust altered r.Host: got %q, want %q", sawHost, "op.local")
	}
}

func TestWrapWithTrustedProxy_RejectsDisallowedForwardedHost(t *testing.T) {
	t.Parallel()

	trust, err := proxy.NewTrustWithHosts([]string{"127.0.0.1/32"}, []string{"op.example.com"})
	if err != nil {
		t.Fatalf("proxy.NewTrustWithHosts: %v", err)
	}

	var sawScheme, sawHost string
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		sawScheme = r.URL.Scheme
		sawHost = r.Host
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal:8080/.well-known/openid-configuration", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "evil.example.com")

	rw := httptest.NewRecorder()
	wrapWithTrustedProxy(h, trust).ServeHTTP(rw, req)

	if sawScheme != "https" {
		t.Errorf("downstream r.URL.Scheme = %q, want %q", sawScheme, "https")
	}
	if sawHost != "internal:8080" {
		t.Errorf("disallowed X-Forwarded-Host altered r.Host: got %q, want inbound %q", sawHost, "internal:8080")
	}
}

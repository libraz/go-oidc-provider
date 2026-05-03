package op //nolint:testpackage // exercises package-private buildProxyTrust helper.

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/proxy"
)

// TestBuildProxyTrust_NilWhenNoCIDRs confirms the documented "no proxy
// trusted" sentinel: when [WithTrustedProxies] was never invoked, the
// helper returns (nil, nil) so the authorize endpoint short-circuits
// the X-Forwarded-* path entirely.
func TestBuildProxyTrust_NilWhenNoCIDRs(t *testing.T) {
	t.Parallel()

	cfg := &config{}
	got, err := buildProxyTrust(cfg)
	if err != nil {
		t.Fatalf("buildProxyTrust: %v", err)
	}
	if got != nil {
		t.Errorf("trust=%v want nil for empty CIDRs", got)
	}
}

// TestBuildProxyTrust_AutoIncludesIssuerHost pins the H-C3 default:
// when [WithTrustedProxies] is configured, the runtime allowlist auto-
// includes the canonical issuer host so the typical single-hostname
// deployment requires no further configuration.
func TestBuildProxyTrust_AutoIncludesIssuerHost(t *testing.T) {
	t.Parallel()

	cfg := &config{
		issuer:         "https://op.example.com",
		trustedProxies: []string{"10.0.0.0/8"},
	}
	tr, err := buildProxyTrust(cfg)
	if err != nil {
		t.Fatalf("buildProxyTrust: %v", err)
	}
	if tr == nil {
		t.Fatal("trust=nil want non-nil with trustedProxies configured")
	}

	// Build a request from inside the trusted CIDR with a hostile
	// XFH; the issuer-derived allowlist must reject the foreign value
	// and fall back to r.Host.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://op.example.com/x", http.NoBody)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-Host", "evil.example.com")
	resolved := proxy.Resolve(req, tr)
	if resolved.Host == "evil.example.com" {
		t.Error("foreign XFH admitted; issuer allowlist did not gate the value")
	}

	// Same request with the canonical issuer host as XFH must succeed.
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://op.example.com/x", http.NoBody)
	req2.RemoteAddr = "10.1.2.3:12345"
	req2.Header.Set("X-Forwarded-Host", "op.example.com")
	resolved2 := proxy.Resolve(req2, tr)
	if resolved2.Host != "op.example.com" {
		t.Errorf("Host=%q want op.example.com (issuer host allowlisted)", resolved2.Host)
	}
}

// TestBuildProxyTrust_IncludesExplicitHosts pins the layered allowlist:
// [WithTrustedProxyHosts] entries compose with the auto-derived issuer
// host so a deployment fronting two public hostnames can register the
// secondary one without losing the canonical issuer match.
func TestBuildProxyTrust_IncludesExplicitHosts(t *testing.T) {
	t.Parallel()

	cfg := &config{
		issuer:            "https://op.example.com",
		trustedProxies:    []string{"10.0.0.0/8"},
		trustedProxyHosts: []string{"alt.example.com"},
	}
	tr, err := buildProxyTrust(cfg)
	if err != nil {
		t.Fatalf("buildProxyTrust: %v", err)
	}

	// Both alt host and canonical issuer host must succeed.
	for _, host := range []string{"alt.example.com", "op.example.com"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://op.example.com/x", http.NoBody)
		req.RemoteAddr = "10.1.2.3:12345"
		req.Header.Set("X-Forwarded-Host", host)
		got := proxy.Resolve(req, tr)
		if got.Host != host {
			t.Errorf("Host=%q want %q", got.Host, host)
		}
	}

	// A foreign value must still be rejected.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://op.example.com/x", http.NoBody)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-Host", "evil.example.com")
	got := proxy.Resolve(req, tr)
	if got.Host == "evil.example.com" {
		t.Error("foreign XFH admitted; allowlist did not gate the value")
	}
}

// TestBuildProxyTrust_WarnsWhenNoAllowlistAvailable pins the startup
// WARN: when the embedder configures CIDRs but the issuer is empty AND
// no explicit hosts were supplied, the helper emits a warning so the
// operator notices the gap.
func TestBuildProxyTrust_WarnsWhenNoAllowlistAvailable(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg := &config{
		trustedProxies: []string{"10.0.0.0/8"},
		logger:         logger,
		// issuer left empty AND no trustedProxyHosts → empty allowlist.
	}
	_, err := buildProxyTrust(cfg)
	if err != nil {
		t.Fatalf("buildProxyTrust: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("X-Forwarded-Host")) {
		t.Errorf("WARN log not emitted: %q", buf.String())
	}
}

// TestBuildProxyTrust_RejectsInvalidCIDR pins that an invalid CIDR
// surfaces as a configuration error wrapped in [Error]. The option
// layer already validates input at [WithTrustedProxies] time but the
// runtime helper re-asserts the invariant so a future regression
// (manual config injection, future option that bypasses the option
// validator) cannot bypass the runtime check.
func TestBuildProxyTrust_RejectsInvalidCIDR(t *testing.T) {
	t.Parallel()

	cfg := &config{
		issuer:         "https://op.example.com",
		trustedProxies: []string{"not-a-cidr"},
	}
	_, err := buildProxyTrust(cfg)
	if err == nil {
		t.Fatal("buildProxyTrust accepted invalid CIDR")
	}
}

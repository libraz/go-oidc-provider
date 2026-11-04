package op //nolint:testpackage // exercises package-private buildProxyTrust helper.

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/proxy"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

type builderTestClock struct{ now time.Time }

func (c builderTestClock) Now() time.Time { return c.now }

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

// TestBuildAssertionVerifiers_EndpointScopedAudience pins that a
// private_key_jwt assertion minted for PAR is not also accepted at token /
// revoke / introspection / device endpoints. Issuer remains an accepted
// alias for FAPI 2.0, and PAR additionally accepts the token endpoint URL
// (RFC 9126 §2 authenticates PAR as a token-endpoint client), but the
// token endpoint does not reciprocally accept the PAR URL — the scoping
// stays directional.
func TestBuildAssertionVerifiers_EndpointScopedAudience(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cfg := &config{
		issuer: "https://op.example.com",
		store:  inmem.New(inmem.WithClock(builderTestClock{now: now})),
		clock:  builderTestClock{now: now},
	}
	cfg.applyDefaults()

	verifiers, err := testAssertionVerifiers(cfg)
	if err != nil {
		t.Fatalf("buildAssertionVerifiers: %v", err)
	}

	tokenAud := absoluteEndpointURL(cfg, cfg.endpoints.Token)
	parAud := absoluteEndpointURL(cfg, cfg.endpoints.PAR)
	backchannelAud := absoluteEndpointURL(cfg, cfg.endpoints.Backchannel)

	assertVerifierAudiences(t, "token", verifiers.Token, tokenAud, []string{cfg.issuer}, []string{parAud, backchannelAud})
	assertVerifierAudiences(t, "par", verifiers.PAR, parAud, []string{cfg.issuer, tokenAud}, []string{backchannelAud})
	assertVerifierAudiences(t, "introspect", verifiers.Introspect, tokenAud, []string{cfg.issuer}, []string{parAud, backchannelAud})
	assertVerifierAudiences(t, "revoke", verifiers.Revoke, tokenAud, []string{cfg.issuer}, []string{parAud, backchannelAud})
	assertVerifierAudiences(t, "device", verifiers.Device, tokenAud, []string{cfg.issuer}, []string{parAud, backchannelAud})
	assertVerifierAudiences(t, "backchannel", verifiers.Backchannel, backchannelAud, []string{cfg.issuer, tokenAud}, []string{parAud})
}

// TestBuildAssertionVerifiers_FAPI2IssuerOnly pins FAPI 2.0 Security
// Profile §5.3.2.1 at the wiring layer: under either FAPI 2.0 profile
// every client-authenticating endpoint accepts the issuer, as a single
// string, and nothing else. FAPI-CIBA keeps the endpoint-scoped dual
// acceptance the test above describes.
func TestBuildAssertionVerifiers_FAPI2IssuerOnly(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		profile    profile.Profile
		issuerOnly bool
	}{
		{profile.FAPI2Baseline, true},
		{profile.FAPI2MessageSigning, true},
		{profile.FAPICIBA, false},
		{profile.OAuth21, false},
	} {
		t.Run(tc.profile.String(), func(t *testing.T) {
			t.Parallel()
			cfg := &config{
				issuer:   "https://op.example.com",
				store:    inmem.New(inmem.WithClock(builderTestClock{now: now})),
				clock:    builderTestClock{now: now},
				profiles: []profile.Profile{tc.profile},
			}
			cfg.applyDefaults()
			verifiers, err := testAssertionVerifiers(cfg)
			if err != nil {
				t.Fatalf("buildAssertionVerifiers: %v", err)
			}
			for name, v := range map[string]*clientauth.PrivateKeyJWTVerifier{
				"token": verifiers.Token, "par": verifiers.PAR, "introspect": verifiers.Introspect,
				"revoke": verifiers.Revoke, "device": verifiers.Device, "backchannel": verifiers.Backchannel,
			} {
				if v.SingleStringAudience != tc.issuerOnly {
					t.Errorf("%s SingleStringAudience=%v want %v", name, v.SingleStringAudience, tc.issuerOnly)
				}
				if !tc.issuerOnly {
					continue
				}
				if v.Audience != cfg.issuer || len(v.AuxAudiences) != 0 {
					t.Errorf("%s Audience=%q Aux=%v, want the issuer alone", name, v.Audience, v.AuxAudiences)
				}
			}
		})
	}
}

// TestDPoPHTU_AdvertisedURLAndAlias pins the htu set an OP endpoint
// compares DPoP proofs against: the URL discovery advertises (issuer,
// mount prefix, endpoint path) and the endpoint's own
// mtls_endpoint_aliases entry, never another endpoint's.
func TestDPoPHTU_AdvertisedURLAndAlias(t *testing.T) {
	t.Parallel()

	cfg := &config{issuer: "https://op.example.com/tenant", mountPrefix: "/oidc"}
	cfg.discoveryMetadata.MTLSEndpointAliases = map[string]string{ //nolint:gosec // endpoint URLs, not credentials.
		"token_endpoint": "https://mtls.op.example.com/tenant/oidc/token",
	}
	got := dpopHTU(cfg, "/token", "token_endpoint")
	want := []string{"https://op.example.com/tenant/oidc/token", "https://mtls.op.example.com/tenant/oidc/token"}
	if !slices.Equal(got, want) {
		t.Errorf("token htu=%v want %v", got, want)
	}
	if got := dpopHTU(cfg, "/userinfo", "userinfo_endpoint"); !slices.Equal(got, []string{"https://op.example.com/tenant/oidc/userinfo"}) {
		t.Errorf("userinfo htu=%v want the advertised URL alone", got)
	}
}

func assertVerifierAudiences(
	t *testing.T,
	name string,
	v *clientauth.PrivateKeyJWTVerifier,
	wantAudience string,
	wantAux []string,
	forbidden []string,
) {
	t.Helper()
	if v == nil {
		t.Fatalf("%s verifier nil", name)
	}
	if v.Audience != wantAudience {
		t.Errorf("%s Audience=%q want %q", name, v.Audience, wantAudience)
	}
	aux := make(map[string]bool, len(v.AuxAudiences))
	for _, aud := range v.AuxAudiences {
		aux[aud] = true
	}
	for _, aud := range wantAux {
		if !aux[aud] {
			t.Errorf("%s AuxAudiences=%v missing %q", name, v.AuxAudiences, aud)
		}
	}
	for _, aud := range forbidden {
		if aux[aud] || v.Audience == aud {
			t.Errorf("%s accepts forbidden endpoint audience %q (Audience=%q Aux=%v)", name, aud, v.Audience, v.AuxAudiences)
		}
	}
}

// TestBuildProxyTrust_AutoIncludesIssuerHost pins the trusted-proxy default:
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

// TestBuildProxyTrust_IssuerHostMatchesForwardedHost pins that the
// issuer host auto-allowlisted for X-Forwarded-Host is in the form the
// proxy trust extracts from the header, so a trusted proxy forwarding the
// issuer's own host is honoured for an IPv6-literal issuer exactly as for
// a hostname one.
func TestBuildProxyTrust_IssuerHostMatchesForwardedHost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		issuer string
		xfh    string
	}{
		{"hostname", "https://OP.Example.com:8443", "op.example.com:8443"},
		{"ipv6-with-port", "https://[::1]:8443", "[::1]:8443"},
		{"ipv6-default-port", "https://[2001:DB8::1]", "[2001:db8::1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			trust, err := buildProxyTrust(&config{
				issuer:         tc.issuer,
				trustedProxies: []string{"10.0.0.0/8"},
			})
			if err != nil {
				t.Fatalf("buildProxyTrust: %v", err)
			}
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://internal/", nil)
			r.RemoteAddr = "10.0.0.1:1234"
			r.Header.Set("X-Forwarded-Host", tc.xfh)
			if got := proxy.Resolve(r, trust).Host; got != tc.xfh {
				t.Errorf("resolved host=%q want %q (issuer host not allowlisted in forwarded form)", got, tc.xfh)
			}
		})
	}
}

// TestPrivateNetworkRefusals_NameTheirOption pins which public option each
// fetcher built by the op layer names when the deny-list refuses a target.
func TestPrivateNetworkRefusals_NameTheirOption(t *testing.T) {
	t.Parallel()

	cfg := &config{clock: builderTestClock{now: time.Unix(1_700_000_000, 0)}}

	_, err := cfg.relyingPartyJWKS().Fetch(context.Background(), "http://10.0.0.1/jwks")
	if err == nil || !strings.Contains(err.Error(), "op.WithAllowPrivateNetwork(op.OutboundJWKS)") {
		t.Errorf("jwks err=%v want a hint naming op.WithAllowPrivateNetwork(op.OutboundJWKS)", err)
	}

	_, err = buildSectorResolver(cfg).Resolve(context.Background(), "https://10.0.0.1/sector.json", nil)
	if err == nil || !strings.Contains(err.Error(), "op.WithAllowPrivateNetwork(op.OutboundSector)") {
		t.Errorf("sector err=%v want a hint naming op.WithAllowPrivateNetwork(op.OutboundSector)", err)
	}
}

// TestRelyingPartyJWKS_RefusalReachesConfiguredLogger pins that the Provider's
// logger is the one the RP JWKS fetcher reports a deny-list refusal on.
func TestRelyingPartyJWKS_RefusalReachesConfiguredLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cfg := &config{
		clock:  builderTestClock{now: time.Unix(1_700_000_000, 0)},
		logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	}

	if _, err := cfg.relyingPartyJWKS().Fetch(context.Background(), "http://10.0.0.1/jwks"); err == nil {
		t.Fatal("fetch of a private target succeeded")
	}
	out := buf.String()
	for _, want := range []string{`"level":"WARN"`, `"fetch":"jwks_uri"`, "op.WithAllowPrivateNetwork(op.OutboundJWKS)"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output %q missing %q", out, want)
		}
	}
}

// testAssertionVerifiers builds the endpoint assertion verifiers over the
// client JWKS resolver the router builds.
func testAssertionVerifiers(cfg *config) (assertionVerifiers, error) {
	resolver, err := buildClientJWKSResolver(cfg)
	if err != nil {
		return assertionVerifiers{}, err
	}
	return buildAssertionVerifiers(cfg, resolver), nil
}

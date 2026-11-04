package op_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// acceptsMTLSProxy exists to prove — at compile time, from a package
// outside op — that a value built here is assignable to the parameter
// type the public API uses. A helper is used rather than a typed
// variable declaration so the assertion cannot be optimised away by a
// reader "simplifying" the test.
func acceptsMTLSProxy(v op.MTLSProxy) string { return v.HeaderName }

// mtlsProxyProvider builds a provider with the mTLS feature on, so the
// proxy option is wired into a real verifier.
func mtlsProxyProvider(tb testing.TB, opts ...op.Option) *testkit.Provider {
	tb.Helper()
	return testkit.NewProvider(tb, testkit.WithOptions(append([]op.Option{op.WithFeature(feature.MTLS)}, opts...)...))
}

// TestMTLSProxy_ConstructibleOutsideThePackage pins the public shape of
// [op.MTLSProxy]. An external caller must be able to name the type,
// declare a value of it, build one field by field, and read the same
// shape back from the Provider.
//
// This file is an external test package (op_test), so it has exactly
// the visibility an embedder has.
func TestMTLSProxy_ConstructibleOutsideThePackage(t *testing.T) {
	t.Parallel()

	var zero op.MTLSProxy
	if zero.HeaderName != "" || len(zero.TrustedProxies) != 0 {
		t.Fatalf("zero MTLSProxy is not the header-path-disabled shape: %+v", zero)
	}

	built := op.MTLSProxy{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: []string{"10.0.0.0/8"},
	}
	if acceptsMTLSProxy(built) != "X-Client-Cert" {
		t.Fatal("a locally built MTLSProxy does not carry its own HeaderName")
	}

	prov := mtlsProxyProvider(t, op.WithMTLSProxy(built))
	got := prov.OP.MTLSProxy()
	if acceptsMTLSProxy(got) != built.HeaderName {
		t.Errorf("HeaderName = %q, want %q", got.HeaderName, built.HeaderName)
	}
	if !slices.Equal(got.TrustedProxies, built.TrustedProxies) {
		t.Errorf("TrustedProxies = %v, want %v", got.TrustedProxies, built.TrustedProxies)
	}
}

// TestMTLSProxy_NormalisesBareIPs pins the read-back notation: the
// effective list is CIDR strings, with a bare IP literal promoted to its
// host-mask prefix.
func TestMTLSProxy_NormalisesBareIPs(t *testing.T) {
	t.Parallel()

	prov := mtlsProxyProvider(t, op.WithMTLSProxy(op.MTLSProxy{
		HeaderName:     "X-Client-Cert",
		TrustedProxies: []string{"192.168.1.1", "fd00::/8"},
	}))
	want := []string{"192.168.1.1/32", "fd00::/8"}
	if got := prov.OP.MTLSProxy().TrustedProxies; !slices.Equal(got, want) {
		t.Fatalf("TrustedProxies = %v, want %v", got, want)
	}
}

// TestMTLSProxy_FallsBackToTrustedProxies pins D5's fallback: an empty
// MTLSProxy.TrustedProxies uses the WithTrustedProxies CIDRs, in either
// option order, and the read-back reports the effective list.
func TestMTLSProxy_FallsBackToTrustedProxies(t *testing.T) {
	t.Parallel()

	proxy := op.WithMTLSProxy(op.MTLSProxy{HeaderName: "X-Client-Cert"})
	trusted := op.WithTrustedProxies("10.0.0.0/8", "172.16.0.0/12")
	for name, opts := range map[string][]op.Option{
		"proxy-then-trusted": {proxy, trusted},
		"trusted-then-proxy": {trusted, proxy},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			prov := mtlsProxyProvider(t, opts...)
			got := prov.OP.MTLSProxy()
			if got.HeaderName != "X-Client-Cert" {
				t.Errorf("HeaderName = %q", got.HeaderName)
			}
			if want := []string{"10.0.0.0/8", "172.16.0.0/12"}; !slices.Equal(got.TrustedProxies, want) {
				t.Errorf("TrustedProxies = %v, want the WithTrustedProxies CIDRs %v", got.TrustedProxies, want)
			}
		})
	}
}

// TestMTLSProxy_ExplicitListWinsOverTrustedProxies confirms the fallback
// is only a fallback: a non-empty MTLSProxy.TrustedProxies is used as is.
func TestMTLSProxy_ExplicitListWinsOverTrustedProxies(t *testing.T) {
	t.Parallel()

	prov := mtlsProxyProvider(t,
		op.WithTrustedProxies("10.0.0.0/8"),
		op.WithMTLSProxy(op.MTLSProxy{HeaderName: "X-Client-Cert", TrustedProxies: []string{"192.168.0.0/16"}}),
	)
	if got, want := prov.OP.MTLSProxy().TrustedProxies, []string{"192.168.0.0/16"}; !slices.Equal(got, want) {
		t.Fatalf("TrustedProxies = %v, want %v", got, want)
	}
}

// TestWithMTLSProxy_RejectsUnresolvableConfiguration covers the
// construction errors of the option itself.
func TestWithMTLSProxy_RejectsUnresolvableConfiguration(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		opt  op.Option
		want string
	}{
		{
			"both lists empty",
			op.WithMTLSProxy(op.MTLSProxy{HeaderName: "X-Client-Cert"}),
			"WithTrustedProxies is not set",
		},
		{
			"empty header",
			op.WithMTLSProxy(op.MTLSProxy{TrustedProxies: []string{"10.0.0.0/8"}}),
			"HeaderName must not be empty",
		},
		{
			"unparsable entry",
			op.WithMTLSProxy(op.MTLSProxy{HeaderName: "X-Client-Cert", TrustedProxies: []string{"not-a-cidr"}}),
			"TrustedProxies rejected",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t), op.WithFeature(feature.MTLS), tc.opt)...)
			if err == nil {
				t.Fatal("op.New accepted the configuration")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestMTLSProxy_ReturnsFreshTrustedProxies pins that a caller cannot
// widen the allow-list the Provider enforces by writing into the slice it
// was handed.
func TestMTLSProxy_ReturnsFreshTrustedProxies(t *testing.T) {
	t.Parallel()

	prov := mtlsProxyProvider(t, op.WithMTLSProxy(op.MTLSProxy{
		HeaderName: "X-Client-Cert", TrustedProxies: []string{"10.0.0.0/8"},
	}))
	first := prov.OP.MTLSProxy()
	first.TrustedProxies[0] = "0.0.0.0/0"

	if got := prov.OP.MTLSProxy().TrustedProxies[0]; got != "10.0.0.0/8" {
		t.Fatalf("mutation leaked into the Provider's allow-list: %v", got)
	}
}

// TestMTLSProxy_PerProviderIsolation pins that [op.WithMTLSProxy] state is
// scoped to the [op.Provider] it was configured on. Two Providers
// constructed with distinct headers / trusted-proxy lists MUST NOT observe
// each other's configuration through [op.Provider.MTLSProxy].
func TestMTLSProxy_PerProviderIsolation(t *testing.T) {
	t.Parallel()

	first := mtlsProxyProvider(t, op.WithMTLSProxy(op.MTLSProxy{
		HeaderName: "X-First-Cert", TrustedProxies: []string{"10.0.0.0/8"},
	}))
	second := mtlsProxyProvider(t, op.WithMTLSProxy(op.MTLSProxy{
		HeaderName: "X-Second-Cert", TrustedProxies: []string{"192.168.0.0/16"},
	}))

	firstCfg := first.OP.MTLSProxy()
	secondCfg := second.OP.MTLSProxy()

	if firstCfg.HeaderName != "X-First-Cert" {
		t.Fatalf("first HeaderName = %q, want %q", firstCfg.HeaderName, "X-First-Cert")
	}
	if secondCfg.HeaderName != "X-Second-Cert" {
		t.Fatalf("second HeaderName = %q, want %q", secondCfg.HeaderName, "X-Second-Cert")
	}

	// A third Provider that never calls WithMTLSProxy must see the
	// header path disabled, not a value inherited from either sibling.
	unconfigured := testkit.NewProvider(t)
	unconfiguredCfg := unconfigured.OP.MTLSProxy()
	if unconfiguredCfg.HeaderName != "" || len(unconfiguredCfg.TrustedProxies) != 0 {
		t.Fatalf("unconfigured Provider leaked proxy state: %+v", unconfiguredCfg)
	}
}

// TestProviderMTLSProxy_NilProvider keeps the accessor total.
func TestProviderMTLSProxy_NilProvider(t *testing.T) {
	t.Parallel()

	var p *op.Provider
	if got := p.MTLSProxy(); got.HeaderName != "" || len(got.TrustedProxies) != 0 {
		t.Fatalf("nil Provider MTLSProxy = %+v, want zero value", got)
	}
}

package op_test

import (
	"net/netip"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// acceptsMTLSProxy exists to prove — at compile time, from a package
// outside op — that a value built here is assignable to the parameter
// type the public API uses. A helper is used rather than a typed
// variable declaration so the assertion cannot be optimised away by a
// reader "simplifying" the test.
func acceptsMTLSProxy(v op.MTLSProxy) string { return v.HeaderName }

// TestMTLSProxy_ConstructibleOutsideThePackage pins the public shape of
// [op.MTLSProxyConfig]'s return value. An external caller must be able
// to name the type, declare a value of it, and build one field by
// field; a signature that named a type from an internal package would
// compile inside the module and be unusable to every embedder, making
// the exported function pointless.
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
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	if acceptsMTLSProxy(built) != "X-Client-Cert" {
		t.Fatal("a locally built MTLSProxy does not carry its own HeaderName")
	}

	prov := testkit.NewProvider(t, testkit.WithOptions(
		op.WithMTLSProxy(built.HeaderName, []string{"10.0.0.0/8"}),
	))
	got := op.MTLSProxyConfig(prov.OP)
	if acceptsMTLSProxy(got) != built.HeaderName {
		t.Errorf("HeaderName = %q, want %q", got.HeaderName, built.HeaderName)
	}
	if len(got.TrustedProxies) != 1 || got.TrustedProxies[0] != built.TrustedProxies[0] {
		t.Errorf("TrustedProxies = %v, want %v", got.TrustedProxies, built.TrustedProxies)
	}
}

// TestMTLSProxyConfig_ReturnsFreshTrustedProxies pins that a caller
// cannot widen the allow-list the Provider enforces by appending to the
// slice it was handed.
func TestMTLSProxyConfig_ReturnsFreshTrustedProxies(t *testing.T) {
	t.Parallel()

	prov := testkit.NewProvider(t, testkit.WithOptions(
		op.WithMTLSProxy("X-Client-Cert", []string{"10.0.0.0/8"}),
	))
	first := op.MTLSProxyConfig(prov.OP)
	first.TrustedProxies[0] = netip.MustParsePrefix("0.0.0.0/0")

	second := op.MTLSProxyConfig(prov.OP)
	if second.TrustedProxies[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("mutation leaked into the Provider's allow-list: %v", second.TrustedProxies)
	}
}

// TestMTLSProxyConfig_PerProviderIsolation pins that [op.WithMTLSProxy]
// state is scoped to the [op.Provider] it was configured on. Two
// Providers constructed with distinct headers / trusted-proxy lists
// MUST NOT observe each other's configuration through
// [op.MTLSProxyConfig]; before the fix the state lived in a
// package-level registry keyed by the config pointer, which risked
// stale entries surviving hot-reload-style reconstruction.
func TestMTLSProxyConfig_PerProviderIsolation(t *testing.T) {
	t.Parallel()

	first := testkit.NewProvider(t, testkit.WithOptions(
		op.WithMTLSProxy("X-First-Cert", []string{"10.0.0.0/8"}),
	))
	second := testkit.NewProvider(t, testkit.WithOptions(
		op.WithMTLSProxy("X-Second-Cert", []string{"192.168.0.0/16"}),
	))

	firstCfg := op.MTLSProxyConfig(first.OP)
	secondCfg := op.MTLSProxyConfig(second.OP)

	if firstCfg.HeaderName != "X-First-Cert" {
		t.Fatalf("first HeaderName = %q, want %q", firstCfg.HeaderName, "X-First-Cert")
	}
	if secondCfg.HeaderName != "X-Second-Cert" {
		t.Fatalf("second HeaderName = %q, want %q", secondCfg.HeaderName, "X-Second-Cert")
	}
	if firstCfg.HeaderName == secondCfg.HeaderName {
		t.Fatalf("both Providers observed the same HeaderName %q; proxy config leaked across Providers", firstCfg.HeaderName)
	}

	// A third Provider that never calls WithMTLSProxy must see the
	// header path disabled, not a value inherited from either sibling.
	unconfigured := testkit.NewProvider(t)
	unconfiguredCfg := op.MTLSProxyConfig(unconfigured.OP)
	if unconfiguredCfg.HeaderName != "" || len(unconfiguredCfg.TrustedProxies) != 0 {
		t.Fatalf("unconfigured Provider leaked proxy state: %+v", unconfiguredCfg)
	}
}

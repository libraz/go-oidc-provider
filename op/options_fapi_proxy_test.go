package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

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

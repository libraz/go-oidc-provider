// Test file exercises unexported config struct and apply paths.
//
//nolint:testpackage // exercises unexported config fields
package op

import (
	"errors"
	"testing"
	"time"
)

// TestWithAllowPrivateNetworkBackchannel drives the option and its
// deprecated predecessor against a fresh config and confirms the accessor
// reads back the value. The SSRF behaviour itself is exercised by
// internal/backchannel/deliverer_ssrf_test.go.
func TestWithAllowPrivateNetworkBackchannel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opt  Option
		want bool
	}{
		{"opt-in", WithAllowPrivateNetworkBackchannel(), true},
		{"deprecated-false", WithBackchannelAllowPrivateNetwork(false), false},
		{"deprecated-true", WithBackchannelAllowPrivateNetwork(true), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &config{}
			if err := tc.opt.apply(c); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if got := c.BackchannelAllowsPrivateNetwork(); got != tc.want {
				t.Errorf("BackchannelAllowsPrivateNetwork = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWithAllowPrivateNetworkBackchannel_ConflictsWithDeprecated pins that
// the two spellings claim one setting, so a configuration carrying both
// is refused instead of resolved by option order.
func TestWithAllowPrivateNetworkBackchannel_ConflictsWithDeprecated(t *testing.T) {
	t.Parallel()

	c := &config{}
	if err := WithBackchannelAllowPrivateNetwork(false).apply(c); err != nil {
		t.Fatalf("apply deprecated: %v", err)
	}
	if err := WithAllowPrivateNetworkBackchannel().apply(c); err == nil {
		t.Fatal("expected a conflict error when both spellings are supplied")
	}
}

// TestBackchannelAllowsPrivateNetwork_Unconfigured confirms the
// accessor returns false when the option was never invoked.
func TestBackchannelAllowsPrivateNetwork_Unconfigured(t *testing.T) {
	t.Parallel()

	c := &config{}
	if c.BackchannelAllowsPrivateNetwork() {
		t.Error("default must be deny (false)")
	}
}

// TestWithAllowPrivateNetworkBackchannel_PerConfig confirms the flag
// lives on the config it was applied to and nowhere else. The gate is
// a plain config field rather than a package-level registry, so a
// config that fails validation is collected with everything it
// references — its keyset, ClientStore and substores included —
// instead of being pinned for the process lifetime.
func TestWithAllowPrivateNetworkBackchannel_PerConfig(t *testing.T) {
	t.Parallel()

	permissive := &config{}
	if err := WithAllowPrivateNetworkBackchannel().apply(permissive); err != nil {
		t.Fatalf("apply: %v", err)
	}
	strict := &config{}

	if !permissive.BackchannelAllowsPrivateNetwork() {
		t.Error("permissive config lost its opt-in")
	}
	if strict.BackchannelAllowsPrivateNetwork() {
		t.Error("strict config picked up another config's opt-in")
	}
}

// TestWithBackchannelFanOutBudget_AcceptsPositive confirms a usable
// budget reaches the config field the coordinator builder reads.
func TestWithBackchannelFanOutBudget_AcceptsPositive(t *testing.T) {
	t.Parallel()

	c := &config{}
	if err := WithBackchannelFanOutBudget(90 * time.Second).apply(c); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if c.backchannelFanOutBudget != 90*time.Second {
		t.Errorf("backchannelFanOutBudget = %v, want 90s", c.backchannelFanOutBudget)
	}
}

// TestWithBackchannelFanOutBudget_RejectsNonPositive pins the
// option-site validation. Zero cannot mean "unbounded" — it is the
// sentinel the coordinator reads as "use the library default" — and a
// negative budget would abandon every delivery before it started, so
// both are refused where the embedder can still see the mistake.
func TestWithBackchannelFanOutBudget_RejectsNonPositive(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		give time.Duration
	}{
		{"zero", 0},
		{"negative", -time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &config{}
			err := WithBackchannelFanOutBudget(tc.give).apply(c)
			if err == nil {
				t.Fatal("apply accepted a non-positive budget")
			}
			var opErr *Error
			if !errors.As(err, &opErr) {
				t.Fatalf("apply returned %T, want *op.Error", err)
			}
			if opErr.Code != codeConfiguration {
				t.Errorf("Code = %q, want %q", opErr.Code, codeConfiguration)
			}
			if c.backchannelFanOutBudget != 0 {
				t.Errorf("rejected budget still reached the config: %v", c.backchannelFanOutBudget)
			}
		})
	}
}

// TestBackchannelFanOutBudget_UnsetIsZero confirms the "option not
// called" state stays the zero value, which is what defers the choice
// to the coordinator's own default instead of pinning a second copy of
// it in the op package.
func TestBackchannelFanOutBudget_UnsetIsZero(t *testing.T) {
	t.Parallel()

	c := &config{}
	if c.backchannelFanOutBudget != 0 {
		t.Errorf("unset budget = %v, want 0", c.backchannelFanOutBudget)
	}
}

// TestWithAllowPrivateNetworkSector confirms the option flips the
// underlying config field. The runtime SSRF behaviour itself is
// covered in internal/sector/resolver_test.go; this test pins the
// option-to-config wiring so a future refactor that drops the
// allowPrivateNetworkSector field is caught at the option layer.
func TestWithAllowPrivateNetworkSector(t *testing.T) {
	t.Parallel()

	c := &config{}
	if c.allowPrivateNetworkSector {
		t.Fatal("default must be deny (false)")
	}
	if err := WithAllowPrivateNetworkSector().apply(c); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !c.allowPrivateNetworkSector {
		t.Error("WithAllowPrivateNetworkSector did not flip allowPrivateNetworkSector")
	}
}

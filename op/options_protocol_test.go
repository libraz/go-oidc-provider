// Test file exercises unexported config struct and apply paths.
//
//nolint:testpackage // exercises unexported config fields
package op

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

// TestWithAllowPrivateNetwork_Backchannel drives the option against a fresh
// config and confirms the accessor reads back the value. The SSRF behaviour itself is exercised by
// internal/backchannel/deliverer_ssrf_test.go.
func TestWithAllowPrivateNetwork_Backchannel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opt  Option
		want bool
	}{
		{"opt-in", WithAllowPrivateNetwork(OutboundBackchannel), true},
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

// TestBackchannelAllowsPrivateNetwork_Unconfigured confirms the
// accessor returns false when the option was never invoked.
func TestBackchannelAllowsPrivateNetwork_Unconfigured(t *testing.T) {
	t.Parallel()

	c := &config{}
	if c.BackchannelAllowsPrivateNetwork() {
		t.Error("default must be deny (false)")
	}
}

// TestWithAllowPrivateNetwork_Backchannel_PerConfig confirms the flag
// lives on the config it was applied to and nowhere else. The gate is
// a plain config field rather than a package-level registry, so a
// config that fails validation is collected with everything it
// references — its keyset, ClientStore and substores included —
// instead of being pinned for the process lifetime.
func TestWithAllowPrivateNetwork_Backchannel_PerConfig(t *testing.T) {
	t.Parallel()

	permissive := &config{}
	if err := WithAllowPrivateNetwork(OutboundBackchannel).apply(permissive); err != nil {
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

// TestWithBackchannelLogout_RecordsFields confirms every field reaches the
// config field the coordinator builder reads.
func TestWithBackchannelLogout_RecordsFields(t *testing.T) {
	t.Parallel()

	rt := http.DefaultTransport
	c := &config{}
	err := WithBackchannelLogout(BackchannelLogout{Transport: rt, Timeout: 2 * time.Second, FanOutBudget: 90 * time.Second}).apply(c)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if c.backchannelLogoutTransport != rt {
		t.Errorf("backchannelLogoutTransport = %v, want the supplied transport", c.backchannelLogoutTransport)
	}
	if c.backchannelLogoutTimeout != 2*time.Second {
		t.Errorf("backchannelLogoutTimeout = %v, want 2s", c.backchannelLogoutTimeout)
	}
	if c.backchannelFanOutBudget != 90*time.Second {
		t.Errorf("backchannelFanOutBudget = %v, want 90s", c.backchannelFanOutBudget)
	}
}

// TestWithBackchannelLogout_ZeroKeepsDefaults pins the zero value as the
// "use the library default" sentinel: the coordinator reads it as unset,
// so the defaults live in one place instead of a second copy in op.
func TestWithBackchannelLogout_ZeroKeepsDefaults(t *testing.T) {
	t.Parallel()

	c := &config{}
	if err := WithBackchannelLogout(BackchannelLogout{}).apply(c); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if c.backchannelLogoutTransport != nil || c.backchannelLogoutTimeout != 0 || c.backchannelFanOutBudget != 0 {
		t.Errorf("zero BackchannelLogout recorded non-zero state: %+v", c)
	}
}

// TestWithBackchannelLogout_RejectsNegative pins the option-site
// validation. A negative timeout or budget would abandon every delivery
// before it started, so both are refused where the embedder can still see
// the mistake, and nothing reaches the config.
func TestWithBackchannelLogout_RejectsNegative(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		give BackchannelLogout
	}{
		{"negative timeout", BackchannelLogout{Timeout: -time.Second}},
		{"negative fan-out budget", BackchannelLogout{FanOutBudget: -time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &config{}
			err := WithBackchannelLogout(tc.give).apply(c)
			if err == nil {
				t.Fatal("apply accepted a negative duration")
			}
			var opErr *Error
			if !errors.As(err, &opErr) {
				t.Fatalf("apply returned %T, want *op.Error", err)
			}
			if opErr.Code != codeConfiguration {
				t.Errorf("Code = %q, want %q", opErr.Code, codeConfiguration)
			}
			if c.backchannelLogoutTimeout != 0 || c.backchannelFanOutBudget != 0 {
				t.Errorf("rejected value still reached the config: %+v", c)
			}
		})
	}
}

// TestWithBackchannelLogout_AtMostOnce confirms a second call fails
// rather than silently replacing the first.
func TestWithBackchannelLogout_AtMostOnce(t *testing.T) {
	t.Parallel()

	c := &config{}
	if err := WithBackchannelLogout(BackchannelLogout{Timeout: time.Second}).apply(c); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := WithBackchannelLogout(BackchannelLogout{Timeout: 2 * time.Second}).apply(c); err == nil {
		t.Fatal("second apply succeeded")
	}
}

// TestWithAllowPrivateNetwork_Sector confirms the option flips the
// underlying config field. The runtime SSRF behaviour itself is
// covered in internal/sector/resolver_test.go; this test pins the
// option-to-config wiring so a future refactor that drops the
// allowPrivateNetworkSector field is caught at the option layer.
func TestWithAllowPrivateNetwork_Sector(t *testing.T) {
	t.Parallel()

	c := &config{}
	if c.allowPrivateNetworkSector {
		t.Fatal("default must be deny (false)")
	}
	if err := WithAllowPrivateNetwork(OutboundSector).apply(c); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !c.allowPrivateNetworkSector {
		t.Error("WithAllowPrivateNetwork(OutboundSector) did not flip allowPrivateNetworkSector")
	}
}

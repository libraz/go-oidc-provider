// Test file exercises unexported config struct and apply paths.
//
//nolint:testpackage // exercises unexported config fields
package op

import "testing"

// TestWithBackchannelAllowPrivateNetwork drives the new option
// against a fresh config and confirms the accessor reads back the
// value. The check guards the per-config wiring path independent of
// the actual SSRF behaviour (which is exercised by
// internal/backchannel/deliverer_ssrf_test.go).
func TestWithBackchannelAllowPrivateNetwork(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		give bool
		want bool
	}{
		{"default-deny", false, false},
		{"explicit-true", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &config{}
			if err := WithBackchannelAllowPrivateNetwork(tc.give).apply(c); err != nil {
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

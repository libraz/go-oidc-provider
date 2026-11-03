package op

import (
	"html/template"
	"strings"
	"testing"
)

func TestZeroArgPrivateNetworkOptions_AreIdempotent(t *testing.T) {
	t.Parallel()

	c, err := newConfig([]Option{
		WithAllowPrivateNetworkSharedSignals(), WithAllowPrivateNetworkSharedSignals(),
		WithAllowPrivateNetworkBackchannel(), WithAllowPrivateNetworkBackchannel(),
	})
	if err != nil {
		t.Fatalf("repeating a zero-argument option failed: %v", err)
	}
	if !c.sharedSignalsAllowPrivateNetwork || !c.backchannelAllowPrivateNetwork {
		t.Fatalf("flags not set: ssf=%v backchannel=%v", c.sharedSignalsAllowPrivateNetwork, c.backchannelAllowPrivateNetwork)
	}
}

func TestWithDefaults_UIOptionsYieldToExplicitCounterpart(t *testing.T) {
	t.Parallel()

	spa := WithSPAUI(SPAUI{LoginMount: "/login"})
	consent := WithConsentUI(ConsentUI{Template: template.Must(template.New("c").Parse("ok"))})

	for _, tc := range []struct {
		name     string
		opts     []Option
		wantSPA  bool
		wantFail bool
	}{
		{"explicit SPA, default consent", []Option{spa, WithDefaults(consent)}, true, false},
		{"default consent, explicit SPA", []Option{WithDefaults(consent), spa}, true, false},
		{"explicit consent, default SPA", []Option{consent, WithDefaults(spa)}, false, false},
		{"default SPA, explicit consent", []Option{WithDefaults(spa), consent}, false, false},
		{"both explicit", []Option{spa, consent}, false, true},
		{"both default", []Option{WithDefaults(spa), WithDefaults(consent)}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := newConfig(tc.opts)
			if tc.wantFail {
				if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
					t.Fatalf("err = %v, want a mutual-exclusion failure", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("newConfig: %v", err)
			}
			if c.spaUISet != tc.wantSPA || c.consentUISet == tc.wantSPA {
				t.Fatalf("spaUISet=%v consentUISet=%v, want SPA=%v", c.spaUISet, c.consentUISet, tc.wantSPA)
			}
		})
	}
}

func TestWithSessionDurabilityPosture_RejectsUndefinedValue(t *testing.T) {
	t.Parallel()

	c, err := newConfig([]Option{WithSessionDurabilityPosture(SessionDurabilityPosture(7))})
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	if err := c.validateSessionDurabilityPosture(); err == nil {
		t.Fatal("validateSessionDurabilityPosture accepted an undefined posture")
	}
}

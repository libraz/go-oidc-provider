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

func TestWithDefaults_UIYieldsToExplicitCounterpart(t *testing.T) {
	t.Parallel()

	spa := WithUI(SPAUI{LoginMount: "/login"})
	html := WithUI(HTMLUI{Consent: PageTemplate{Template: template.Must(template.New("c").Parse("ok"))}})

	for _, tc := range []struct {
		name     string
		opts     []Option
		wantSPA  bool
		wantFail bool
	}{
		{"explicit SPA, default HTML", []Option{spa, WithDefaults(html)}, true, false},
		{"default HTML, explicit SPA", []Option{WithDefaults(html), spa}, true, false},
		{"explicit HTML, default SPA", []Option{html, WithDefaults(spa)}, false, false},
		{"default SPA, explicit HTML", []Option{WithDefaults(spa), html}, false, false},
		{"both explicit", []Option{spa, html}, false, true},
		{"both default", []Option{WithDefaults(spa), WithDefaults(html)}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := newConfig(tc.opts)
			if tc.wantFail {
				if err == nil || !strings.Contains(err.Error(), "WithUI may be called at most once") {
					t.Fatalf("err = %v, want a repeated-WithUI failure", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("newConfig: %v", err)
			}
			if !c.uiSet || (c.ui.spa != nil) != tc.wantSPA {
				t.Fatalf("uiSet=%v spa=%v, want SPA=%v", c.uiSet, c.ui.spa, tc.wantSPA)
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

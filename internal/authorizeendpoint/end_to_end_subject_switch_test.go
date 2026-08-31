package authorizeendpoint_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

// The two accounts every row below drives: the one whose consent the
// first pass records, and the one who answers the credential prompt when
// the second pass re-runs authentication.
const (
	switchSubjectFirst  = "user-switch-first"
	switchSubjectSecond = "user-switch-second"
)

// TestEndToEnd_ReauthSubjectSwitchNeverInheritsConsent covers every
// branch that sends a request with a live session back through the
// authentication chain: prompt=login, a max_age the session is too old
// to satisfy, and an RFC 9470 step-up to an acr the session does not
// carry. All three start the interaction with the cookie subject's grant
// in hand, and all three can bind a different subject at the credential
// screen.
//
// The account that ends up authenticated must never receive an
// authorization code for scopes it did not approve. Either the consent
// ceremony runs for it, or the attempt terminates without a code —
// inheriting the first account's consent is not an outcome.
//
// The same-subject counterpart (the second pass mints for the account
// that already consented, with no repeat ceremony) is pinned by
// TestEndToEnd_PromptLoginRunsPrimaryWithLiveSession and
// TestEndToEnd_ACRStepUp, so an over-broad fix here would not go
// unnoticed.
func TestEndToEnd_ReauthSubjectSwitchNeverInheritsConsent(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name     string
		clientID string
		// firstPass carries the extra authorize parameters the account
		// that consents starts with.
		firstPass url.Values
		// reauth returns the extra parameters that force the second pass
		// back through the chain, advancing clock when the branch needs
		// an aged session.
		reauth func(clock *movableClock) url.Values
	}{
		{
			name:     "prompt_login",
			clientID: "rp-switch-prompt-login",
			reauth: func(*movableClock) url.Values {
				return url.Values{"prompt": {"login"}}
			},
		},
		{
			name:     "max_age_expired",
			clientID: "rp-switch-max-age",
			reauth: func(clock *movableClock) url.Values {
				// Well past max_age but far inside the session idle
				// window, so the second pass still resolves the first
				// account's session (and therefore its grant).
				clock.Advance(72 * time.Hour)
				return url.Values{"max_age": {"60"}}
			},
		},
		{
			name:      "acr_step_up",
			clientID:  "rp-switch-acr",
			firstPass: url.Values{"acr_values": {"1"}},
			reauth: func(*movableClock) url.Values {
				return url.Values{"acr_values": {"2"}}
			},
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			clock := newMovableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
			f := newE2EFlow(t, row.clientID, testkit.WithClock(clock))

			// Pass 1 records the first account's consent for the full
			// requested scope set.
			first := f.values()
			for k, vals := range row.firstPass {
				first[k] = vals
			}
			loc1 := f.authorize(t, first)
			if loc1.Query().Get("code") != "" {
				t.Fatalf("pass 1 minted a code without an interaction: %s", loc1)
			}
			f.completeLogin(t, loc1, switchSubjectFirst)

			// Pass 2 re-runs authentication and the second account
			// answers the credential prompt.
			second := f.values()
			for k, vals := range row.reauth(clock) {
				second[k] = vals
			}
			loc2 := f.authorize(t, second)
			if loc2.Query().Get("code") != "" {
				t.Fatalf("pass 2 minted a code without re-authenticating: %s", loc2)
			}
			resp, _ := f.submitSubject(t, f.interactionURL(loc2), switchSubjectSecond)
			defer resp.Body.Close()

			prompted, _, err := testkit.IsConsentPrompt(resp)
			if err != nil {
				t.Fatalf("inspect consent prompt: %v", err)
			}
			if prompted {
				// The second account is being asked to approve for
				// itself, which is the whole point.
				return
			}
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("chain neither prompted for consent nor terminated: status=%d", resp.StatusCode)
			}
			final, err := resp.Location()
			if err != nil {
				t.Fatalf("Location after credential submission: %v", err)
			}
			if code := final.Query().Get("code"); code != "" {
				t.Fatalf("%s received code %q with no consent ceremony of its own: %s",
					switchSubjectSecond, code, final)
			}
			if final.Query().Get("error") == "" {
				t.Fatalf("terminal redirect carries neither a code nor an error: %s", final)
			}
		})
	}
}

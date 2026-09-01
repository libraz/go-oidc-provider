package authorizeendpoint_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

// consentPromptType is the prompt type the built-in consent screen
// renders under. The tests below branch on it to tell "the chain ran a
// credential ceremony" apart from "the chain only asked for scope".
const consentPromptType = "consent.scope"

// walkInteraction drives the interaction at path to its RP redirect,
// answering whichever prompt the chain emits first, and returns that
// prompt's type together with the redirect.
//
// The type matters to the caller: a request served from a live session
// reaches the redirect through the consent screen alone, whereas one
// that re-authenticates presents the credential factor first. The two
// carry different expectations for auth_time, and nothing else in the
// response distinguishes them.
func (d *reauthDriver) walkInteraction(path string) (string, *url.URL) {
	d.t.Helper()
	env, csrf := d.firstPrompt(path)
	first, _ := env["type"].(string)
	stateRef, _ := env["state_ref"].(string)
	if stateRef == "" {
		d.t.Fatalf("prompt %q carries no state_ref", first)
	}
	var resp *http.Response
	switch first {
	case testkit.SubjectPromptType:
		resp = d.submit(path, csrf, stateRef, map[string]string{testkit.SubjectFieldName: reauthSubject})
	case consentPromptType:
		resp = testkit.PostConsentApproval(d.t, d.cl, d.fix.server.URL+path,
			d.fix.issuer, csrf, stateRef, approvedScopesFromPrompt(env))
	default:
		d.t.Fatalf("unexpected first prompt type %q", first)
	}
	defer resp.Body.Close()
	final := completeConsentIfPrompted(d.t, d.cl, d.fix.server.URL+path, d.fix.issuer, csrf, resp)
	defer final.Body.Close()
	if final.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(final.Body)
		d.t.Fatalf("interaction final status=%d body=%s", final.StatusCode, string(dump))
	}
	loc, err := final.Location()
	if err != nil {
		d.t.Fatalf("final Location: %v", err)
	}
	return first, loc
}

// claimStrings reads a claim that is either a JSON string list or
// absent, returning nil for the latter so a caller can tell an empty
// list from a missing claim only by the claim's presence in the map.
func claimStrings(tb testing.TB, claims map[string]any, name string) []string {
	tb.Helper()
	raw, ok := claims[name]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		tb.Fatalf("%s = %v, want a JSON list", name, raw)
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			tb.Fatalf("%s contains %v, want strings only", name, v)
		}
		out = append(out, s)
	}
	return out
}

// TestEndToEnd_ConsentOnlyKeepsSessionAuthentication asserts that an
// authorization served from a live session reports the authentication
// that session records rather than one synthesised at the moment the
// consent screen was answered.
//
// The script widens the requested scope three hours after the login, so
// the cached grant no longer covers the request and a consent ceremony
// runs. No credential is presented during that second pass on the
// LoginFlow surface, which means the attempt has no factors of its own:
// auth_time MUST stay the login's, and acr / amr MUST stay the ones the
// login produced. Re-deriving them from the empty factor set inflates
// auth_time to "just now" — permanently defeating an RP's freshness
// check — and drops acr / amr from the id_token entirely.
//
// The Authenticators surface reaches the same redirect through the
// credential factor, so its auth_time legitimately moves; the assertion
// is therefore expressed against the prompt the chain actually emitted.
// What holds on both surfaces without qualification is that acr / amr
// survive and that the durable grant keeps whatever the response
// reported, since every later token minted from that grant reads them
// back off the record.
func TestEndToEnd_ConsentOnlyKeepsSessionAuthentication(t *testing.T) {
	t.Parallel()
	for _, surface := range []authnSurface{surfaceLoginFlow, surfaceAuthenticators} {
		t.Run(surface.String(), func(t *testing.T) {
			t.Parallel()
			start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
			fix := newFlowFixture(t, surface, newMovableClock(start))
			d := newReauthDriver(t, fix)

			// Pass 1 authenticates and consents to "openid" alone, so the
			// grant it leaves behind cannot cover the wider second request.
			loc1 := d.authorize(url.Values{"scope": {"openid"}})
			if loc1.Query().Get("code") != "" {
				t.Fatalf("pass 1 expected an interaction redirect, got a code: %s", loc1)
			}
			_, redirect1 := d.walkInteraction(loc1.Path)
			claims1 := d.exchange(d.codeFrom(redirect1))
			authTime1, _ := claims1["auth_time"].(float64)
			if int64(authTime1) != start.Unix() {
				t.Fatalf("pass 1 auth_time=%d want %d", int64(authTime1), start.Unix())
			}
			acr1, _ := claims1["acr"].(string)
			if acr1 == "" {
				t.Fatalf("pass 1 id_token carries no acr: %v", claims1)
			}
			amr1 := claimStrings(t, claims1, "amr")
			if len(amr1) == 0 {
				t.Fatalf("pass 1 id_token carries no amr: %v", claims1)
			}

			// Pass 2 asks for scope the grant does not hold. The clock has
			// moved, so an auth_time taken from the session and one forged
			// from "now" are distinct values.
			fix.clock.Advance(3 * time.Hour)
			reentry := fix.clock.Now()
			loc2 := d.authorize(nil)
			if loc2.Query().Get("code") != "" {
				t.Fatalf("widened scope produced a code without an interaction: %s", loc2)
			}
			first, redirect2 := d.walkInteraction(loc2.Path)
			claims2 := d.exchange(d.codeFrom(redirect2))
			authTime2, _ := claims2["auth_time"].(float64)
			acr2, _ := claims2["acr"].(string)
			amr2 := claimStrings(t, claims2, "amr")

			// The authentication a consent-only pass reports is the
			// session's; one that ran the credential factor again reports
			// the moment that factor answered. Either way the factor is
			// the same password authenticator, so acr / amr do not move.
			wantAuthTime := reentry.Unix()
			if first == consentPromptType {
				wantAuthTime = int64(authTime1)
			}
			if int64(authTime2) != wantAuthTime {
				t.Errorf("pass 2 auth_time=%d want %d (first prompt was %q)",
					int64(authTime2), wantAuthTime, first)
			}
			if acr2 != acr1 {
				t.Errorf("pass 2 acr=%q want %q", acr2, acr1)
			}
			if !slices.Equal(amr2, amr1) {
				t.Errorf("pass 2 amr=%v want %v", amr2, amr1)
			}

			grant, err := fix.store.Grants().FindBySubjectClient(context.Background(), reauthSubject, fix.client.ID)
			if err != nil {
				t.Fatalf("FindBySubjectClient: %v", err)
			}
			if grant.AuthTime.Unix() != wantAuthTime {
				t.Errorf("grant auth_time=%d want %d; every later token minted from this grant reports it",
					grant.AuthTime.Unix(), wantAuthTime)
			}
			if grant.ACR != acr1 {
				t.Errorf("grant acr=%q want %q", grant.ACR, acr1)
			}
			if !slices.Equal(grant.AMR, amr1) {
				t.Errorf("grant amr=%v want %v", grant.AMR, amr1)
			}
		})
	}
}

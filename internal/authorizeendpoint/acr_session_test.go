package authorizeendpoint_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

const customMFAACR = "urn:example:mfa"

// ladderSatisfier judges a requested acr against a per-acr level table,
// reading the session's level off its canonical acr the way the library
// wiring does.
func ladderSatisfier(levels map[string]authn.AAL) authorizeendpoint.ACRSatisfier {
	return func(_ context.Context, requested string, entry authn.EntryAuthn) bool {
		want, ok := levels[requested]
		if !ok {
			want = authn.AALFromACRURI(requested)
		}
		return want > authn.AAL0 && want <= authn.AALFromACRURI(entry.ACR)
	}
}

// seedACRSession establishes a session for user-1 at acr and a grant
// covering the canonical request, returning the session cookie value.
func seedACRSession(t *testing.T, h *testHarness, acr string, amr []string) string {
	t.Helper()
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now.Add(-time.Minute),
		ACR:      acr,
		AMR:      amr,
	}, h.clock.now)
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        "grant-1",
		Subject:   "user-1",
		ClientID:  "client-1",
		Scope:     []string{"openid", "profile"},
		CreatedAt: h.clock.now,
		UpdatedAt: h.clock.now,
	}); err != nil {
		t.Fatalf("Save grant: %v", err)
	}
	return out.Cookie
}

// authorizeWithSession runs GET /authorize carrying the session cookie and
// returns the redirect target.
func authorizeWithSession(t *testing.T, h *testHarness, sessionCookie string, v url.Values) *url.URL {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessionCookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	return mustParseLocation(t, resp)
}

func assertSilentCode(t *testing.T, loc *url.URL) {
	t.Helper()
	if loc.Query().Get("code") == "" {
		t.Fatalf("Location=%s, want a code served from the session", loc)
	}
}

func assertReauthentication(t *testing.T, h *testHarness, loc *url.URL) {
	t.Helper()
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("Location=%s, want an interaction redirect", loc)
	}
}

func TestAuthorize_ACRSatisfiedBySession_LadderAbove(t *testing.T) {
	t.Parallel()

	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.ACRSatisfier = ladderSatisfier(map[string]authn.AAL{customMFAACR: authn.AAL2})
	})
	sessionCookie := seedACRSession(t, h, authn.AAL3.ACRURI(), []string{"pwd", "hwk"})
	v := goodAuthorizeValues()
	v.Set("acr_values", customMFAACR)
	assertSilentCode(t, authorizeWithSession(t, h, sessionCookie, v))
}

func TestAuthorize_ACRSatisfiedBySession_LadderBelow(t *testing.T) {
	t.Parallel()

	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.ACRSatisfier = ladderSatisfier(map[string]authn.AAL{customMFAACR: authn.AAL2})
	})
	sessionCookie := seedACRSession(t, h, authn.AAL1.ACRURI(), []string{"pwd"})
	v := goodAuthorizeValues()
	v.Set("acr_values", customMFAACR)
	assertReauthentication(t, h, authorizeWithSession(t, h, sessionCookie, v))
}

// TestAuthorize_ACRSatisfiedBySession_AnyRequestedValue pins the any-of
// reading: acr_values is a preference list, so one satisfied entry is
// enough even when an earlier one is out of reach.
func TestAuthorize_ACRSatisfiedBySession_AnyRequestedValue(t *testing.T) {
	t.Parallel()

	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.ACRSatisfier = ladderSatisfier(map[string]authn.AAL{customMFAACR: authn.AAL2})
	})
	sessionCookie := seedACRSession(t, h, authn.AAL2.ACRURI(), []string{"pwd", "otp"})
	v := goodAuthorizeValues()
	v.Set("acr_values", authn.AAL3.ACRURI()+" "+customMFAACR)
	assertSilentCode(t, authorizeWithSession(t, h, sessionCookie, v))
}

func TestAuthorize_ACRSatisfiedBySession_EssentialClaim(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		sessionACR string
		wantCode   bool
	}{
		{name: "above", sessionACR: authn.AAL2.ACRURI(), wantCode: true},
		{name: "below", sessionACR: authn.AAL1.ACRURI(), wantCode: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, func(d *authorizeendpoint.Deps) {
				d.ClaimsParameterEnabled = true
				d.ACRSatisfier = ladderSatisfier(map[string]authn.AAL{customMFAACR: authn.AAL2})
			})
			sessionCookie := seedACRSession(t, h, tc.sessionACR, []string{"pwd"})
			v := goodAuthorizeValues()
			v.Set("claims", `{"id_token":{"acr":{"essential":true,"values":["`+customMFAACR+`"]}}}`)
			loc := authorizeWithSession(t, h, sessionCookie, v)
			if tc.wantCode {
				assertSilentCode(t, loc)
				return
			}
			assertReauthentication(t, h, loc)
		})
	}
}

// TestAuthorize_ACRSatisfiedBySession_NilSatisfierExactMatch covers the
// unwired endpoint: without a satisfier only the session's own canonical
// acr is satisfied.
func TestAuthorize_ACRSatisfiedBySession_NilSatisfierExactMatch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		requested string
		wantCode  bool
	}{
		{name: "custom value", requested: customMFAACR, wantCode: false},
		{name: "lower canonical", requested: authn.AAL1.ACRURI(), wantCode: false},
		{name: "own canonical", requested: authn.AAL2.ACRURI(), wantCode: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t)
			sessionCookie := seedACRSession(t, h, authn.AAL2.ACRURI(), []string{"pwd", "otp"})
			v := goodAuthorizeValues()
			v.Set("acr_values", tc.requested)
			loc := authorizeWithSession(t, h, sessionCookie, v)
			if tc.wantCode {
				assertSilentCode(t, loc)
				return
			}
			assertReauthentication(t, h, loc)
		})
	}
}

// TestAuthorize_ACRSatisfiedBySession_ResolveSeesSatisfierCompleted pins
// that the policy's Resolve judges a session-served response with the
// completed kinds the satisfier judged the reuse with. A policy reading
// completed would otherwise accept the session and then refuse the
// essential acr it just accepted.
func TestAuthorize_ACRSatisfiedBySession_ResolveSeesSatisfierCompleted(t *testing.T) {
	t.Parallel()

	var (
		mu      sync.Mutex
		seen    [][]string
		resolve authorizeendpoint.ACRResolveInput
	)
	var orch *authn.Orchestrator
	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.ClaimsParameterEnabled = true
		orch = d.Authn
		d.ACRSatisfier = func(_ context.Context, requested string, entry authn.EntryAuthn) bool {
			completed := orch.InheritedCompletedKinds(entry)
			mu.Lock()
			seen = append(seen, completed)
			mu.Unlock()
			return requested == customMFAACR && len(completed) > 0
		}
		d.ACRResolver = func(_ context.Context, in authorizeendpoint.ACRResolveInput) authorizeendpoint.ACRResolveOutput {
			mu.Lock()
			resolve = in
			mu.Unlock()
			return authorizeendpoint.ACRResolveOutput{ACR: customMFAACR, OK: len(in.CompletedKinds) > 0}
		}
	})
	sessionCookie := seedACRSession(t, h, authn.AAL2.ACRURI(), []string{"pwd", "otp"})
	v := goodAuthorizeValues()
	v.Set("claims", `{"id_token":{"acr":{"essential":true,"values":["`+customMFAACR+`"]}}}`)
	assertSilentCode(t, authorizeWithSession(t, h, sessionCookie, v))

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("the satisfier was never consulted")
	}
	want := seen[len(seen)-1]
	if len(want) == 0 {
		t.Fatal("the satisfier saw no completed kinds; the comparison would be vacuous")
	}
	if !slices.Equal(resolve.CompletedKinds, want) {
		t.Errorf("Resolve CompletedKinds = %v, want the satisfier's %v", resolve.CompletedKinds, want)
	}
	if !resolve.SessionReused {
		t.Error("Resolve SessionReused = false for a response served from the session")
	}
	if !slices.Equal(resolve.AMR, []string{"pwd", "otp"}) {
		t.Errorf("Resolve AMR = %v, want the session's", resolve.AMR)
	}
	if wantTime := h.clock.now.Add(-time.Minute); !resolve.AuthTime.Equal(wantTime) {
		t.Errorf("Resolve AuthTime = %v, want the session's %v", resolve.AuthTime, wantTime)
	}
	if resolve.InternalAAL != authn.AAL2 {
		t.Errorf("Resolve InternalAAL = %v, want AAL2", resolve.InternalAAL)
	}
}

package authorizeendpoint

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

// coveringGrant is the fixture every row below starts from: a grant that
// already carries the requested scope and the requested RFC 9396
// element, i.e. the state in which a request may legitimately skip the
// consent ceremony.
func coveringGrant() *store.Grant {
	return &store.Grant{
		ID:                   "grant-covering",
		Subject:              "user-1",
		ClientID:             "client-1",
		Scope:                []string{"openid", "profile", "email"},
		AuthorizationDetails: []map[string]any{{"type": "payment_initiation", "amount": "100"}},
	}
}

// TestConsentAlreadyCovered pins the single predicate behind both
// consent gates. Every "false" row is a request the user must be
// prompted for; returning true for any of them would let the endpoint
// mint a code for an authorization that was never confirmed.
func TestConsentAlreadyCovered(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		req   *authorize.Request
		grant *store.Grant
		want  bool
	}{
		{
			name:  "covering grant covers the request",
			req:   &authorize.Request{Scope: []string{"openid", "profile"}},
			grant: coveringGrant(),
			want:  true,
		},
		{
			name:  "no grant",
			req:   &authorize.Request{Scope: []string{"openid"}},
			grant: nil,
			want:  false,
		},
		{
			name:  "prompt=consent overrides a covering grant",
			req:   &authorize.Request{Scope: []string{"openid"}, Prompt: []string{"consent"}},
			grant: coveringGrant(),
			want:  false,
		},
		{
			name:  "scope outside the grant",
			req:   &authorize.Request{Scope: []string{"openid", "billing:write"}},
			grant: coveringGrant(),
			want:  false,
		},
		{
			name: "new authorization_details element",
			req: &authorize.Request{
				Scope:                []string{"openid"},
				AuthorizationDetails: []map[string]any{{"type": "payment_initiation", "amount": "999"}},
			},
			grant: coveringGrant(),
			want:  false,
		},
		{
			name: "grant management action always prompts",
			req: &authorize.Request{
				Scope:                 []string{"openid"},
				GrantManagementAction: gmActionMerge,
				GrantID:               "grant-covering",
			},
			grant: coveringGrant(),
			want:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := consentAlreadyCovered(tc.req, tc.grant); got != tc.want {
				t.Errorf("consentAlreadyCovered=%v want %v", got, tc.want)
			}
			// The interaction state must agree with the decision matrix:
			// a request that is not covered may never start its
			// interaction with consent pre-marked as already run.
			run := initialInteractionsRun(tc.req, tc.grant, false)
			if run[consent.Name] != tc.want {
				t.Errorf("initialInteractionsRun[%q]=%v want %v", consent.Name, run[consent.Name], tc.want)
			}
		})
	}
}

// TestInitialInteractionsRun_ChooserSuppressesPreMark keeps the chooser
// carve-out: the grant was looked up against the cookie-resolved
// subject, which the chooser may replace, so consent re-evaluates after
// the pick.
func TestInitialInteractionsRun_ChooserSuppressesPreMark(t *testing.T) {
	t.Parallel()

	req := &authorize.Request{Scope: []string{"openid"}}
	if run := initialInteractionsRun(req, coveringGrant(), true); run[consent.Name] {
		t.Error("consent pre-marked as run while the chooser is pending")
	}
}

// TestStampGrantAuthContext pins the re-stamp helper: it overwrites the
// grant's authentication context and reports whether anything actually
// changed, so the silent path can skip a store write when the grant
// already matches the session.
func TestStampGrantAuthContext(t *testing.T) {
	t.Parallel()

	authTime := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	active := &sessions.Active{Session: &store.Session{
		Subject:  "user-1",
		AuthTime: authTime,
		ACR:      "urn:test:acr:current",
		AMR:      []string{"pwd"},
	}}

	stale := &store.Grant{
		AuthTime: authTime.Add(-72 * time.Hour),
		ACR:      "urn:test:acr:stale",
		AMR:      []string{"stale"},
	}
	if !stampGrantAuthContext(stale, sessionAuthContext(active)) {
		t.Error("stampGrantAuthContext reported no change for a stale grant")
	}
	if !stale.AuthTime.Equal(authTime) {
		t.Errorf("AuthTime=%v want %v", stale.AuthTime, authTime)
	}
	if stale.ACR != "urn:test:acr:current" {
		t.Errorf("ACR=%q want urn:test:acr:current", stale.ACR)
	}
	if len(stale.AMR) != 1 || stale.AMR[0] != "pwd" {
		t.Errorf("AMR=%v want [pwd]", stale.AMR)
	}

	if stampGrantAuthContext(stale, sessionAuthContext(active)) {
		t.Error("stampGrantAuthContext reported a change for an already-current grant")
	}

	// The stamped slice must not alias the session record.
	stale.AMR[0] = "mutated"
	if active.Session.AMR[0] != "pwd" {
		t.Errorf("session AMR mutated through the grant: %v", active.Session.AMR)
	}
}

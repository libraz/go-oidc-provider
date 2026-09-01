//go:build example

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestEveryHTMLSurfaceDeniesFraming walks the HTML responses this process
// emits and asserts each one carries the framing defence. The three
// stamping sites used to be three separate ones and the relying party's
// screens were the pair that had neither X-Frame-Options nor
// frame-ancestors — while the sign-in-complete screen is the page that
// renders the member's verified identity claims.
func TestEveryHTMLSurfaceDeniesFraming(t *testing.T) {
	t.Parallel()

	members := newFakeMembers()
	subject := members.seed("member-1", "member@example.com", "correct-horse")
	ui := newTestAppUI(t, members, &recordingTOTPs{})
	sessionID, _ := signedIn(t, ui, subject)

	driver, err := newAppDriver()
	if err != nil {
		t.Fatalf("newAppDriver: %v", err)
	}

	rp, _ := newTestRelyingParty(t)

	for _, tc := range []struct {
		name  string
		serve func(w http.ResponseWriter)
	}{
		{
			name: "relying party index",
			serve: func(w http.ResponseWriter) {
				rp.index(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
			},
		},
		{
			name:  "relying party failure",
			serve: func(w http.ResponseWriter) { rp.fail(w, http.StatusBadRequest, "no") },
		},
		{
			// The success screen shares rp.page with the two above; it is
			// listed separately because it is the one that displays the
			// verified sub / email / name.
			name: "relying party signed in",
			serve: func(w http.ResponseWriter) {
				rp.page(w, http.StatusOK, "Signed in", "<p>claims</p>")
			},
		},
		{
			name: "application account page",
			serve: func(w http.ResponseWriter) {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/account", nil)
				req.AddCookie(&http.Cookie{Name: appSessionCookie, Value: sessionID})
				ui.account(w, req)
			},
		},
		{
			name: "provider prompt",
			serve: func(w http.ResponseWriter) {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/interaction/x", nil)
				if err := driver.Render(w, req, interaction.Prompt{
					Type:     "auth.password",
					StateRef: "ref",
					Inputs: []interaction.FieldSpec{
						{Name: "username", Kind: interaction.FieldEmail, Label: "auth.password.username"},
						{Name: "password", Kind: interaction.FieldPassword, Label: "auth.password.password"},
					},
				}); err != nil {
					t.Errorf("Render: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			tc.serve(rec)

			header := rec.Result().Header
			if got := header.Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %q, want DENY", got)
			}
			policy := header.Get("Content-Security-Policy")
			if !strings.Contains(policy, "frame-ancestors 'none'") {
				t.Errorf("Content-Security-Policy = %q, want frame-ancestors 'none'", policy)
			}
			if !strings.Contains(policy, "base-uri 'none'") {
				t.Errorf("Content-Security-Policy = %q, want base-uri 'none'", policy)
			}
			// form-action stays unpinned on every surface: the consent POST
			// redirects cross-origin and browsers enforce form-action across
			// redirects.
			if strings.Contains(policy, "form-action") {
				t.Errorf("Content-Security-Policy = %q pins form-action, which breaks the consent redirect", policy)
			}
			if got := header.Get("Referrer-Policy"); got != "same-origin" {
				t.Errorf("Referrer-Policy = %q, want same-origin; no-referrer makes the browser send Origin: null", got)
			}
			if got := header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
		})
	}
}

//go:build example

package rpkit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
)

// fakeOP stands up the minimum subset of the OIDC discovery surface
// rpkit.New consumes: a /.well-known/openid-configuration document
// pointing at synthesised /authorize, /token, /jwks endpoints. The
// fake never receives a real authorize call — the tests redirect
// against the URL the discovery doc names but stop short of the OP
// actually rendering a login page; the redirect chain is enough to
// inspect the URL shape rpkit produces.
func fakeOP(t *testing.T) (issuer string, cleanup func()) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	return srv.URL, srv.Close
}

// newCodeFlow constructs a CodeFlow against the fake OP. The tests
// in this file do not exercise the callback path; they hit /step-up
// (or /login) and inspect the 302 Location header.
func newCodeFlow(t *testing.T) *rpkit.CodeFlow {
	t.Helper()
	issuer, cleanup := fakeOP(t)
	t.Cleanup(cleanup)

	cf, err := rpkit.New(context.Background(), rpkit.Options{
		Issuer:      issuer,
		ClientID:    "demo-rp",
		RedirectURL: "http://rp.example/callback",
		Scopes:      []string{"profile"},
	})
	if err != nil {
		t.Fatalf("rpkit.New: %v", err)
	}
	return cf
}

// recordRedirect mounts h on a fresh ServeMux at /step-up and hits
// it with a GET. It returns the parsed query of the Location header
// the handler set when redirecting (302). Any other status is a
// fatal test failure — the helper centralises the assertion so each
// test stays focused on the property it pins.
func recordRedirect(t *testing.T, h http.HandlerFunc) url.Values {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://rp.example/step-up", nil)
	h(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %q", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("Location header is empty")
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	return u.Query()
}

// TestStepUpHandler_AddsAcrValues pins that StepUpHandler forwards
// the acrValues argument as the OIDC `acr_values` query parameter
// and unconditionally sets `prompt=login` so the OP forces a fresh
// authentication ceremony. Without these two parameters the OP
// would silently reuse an existing session at a lower ACR and the
// step-up demo would never observe the elevated `acr` claim.
func TestStepUpHandler_AddsAcrValues(t *testing.T) {
	t.Parallel()

	cf := newCodeFlow(t)
	q := recordRedirect(t, cf.StepUpHandler("https://example.com/acr/totp"))

	if got := q.Get("acr_values"); got != "https://example.com/acr/totp" {
		t.Errorf("acr_values = %q, want %q", got, "https://example.com/acr/totp")
	}
	if got := q.Get("prompt"); got != "login" {
		t.Errorf("prompt = %q, want \"login\"", got)
	}
}

// TestStepUpHandler_KeepsPKCE pins that the step-up redirect carries
// a PKCE challenge with method=S256. PKCE applies to every
// authorization-code flow rpkit drives, including step-up; without
// it a network attacker could swap the authorization code from a
// concurrent session and harvest tokens.
func TestStepUpHandler_KeepsPKCE(t *testing.T) {
	t.Parallel()

	cf := newCodeFlow(t)
	q := recordRedirect(t, cf.StepUpHandler("urn:mace:incommon:iap:silver"))

	if got := q.Get("code_challenge"); got == "" {
		t.Error("code_challenge is empty")
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want \"S256\"", got)
	}
}

// TestStepUpHandler_KeepsState pins that the step-up redirect
// carries a non-empty `state`. State is the RP's CSRF guard for the
// callback; an empty value would mean the helper silently regressed
// the security posture relative to /login.
func TestStepUpHandler_KeepsState(t *testing.T) {
	t.Parallel()

	cf := newCodeFlow(t)
	q := recordRedirect(t, cf.StepUpHandler("urn:mace:incommon:iap:silver"))

	state := q.Get("state")
	if state == "" {
		t.Error("state is empty")
	}
	// rpkit generates state via base64.RawURLEncoding of 16 random
	// bytes, which decodes to 22 characters. The exact length is an
	// implementation detail; we only assert "long enough to be
	// unguessable" here.
	if len(state) < 16 {
		t.Errorf("state len = %d, want >= 16", len(state))
	}
}

// TestStepUpHandler_PreservesClientAndRedirect pins that the
// authorize URL still carries the client_id and redirect_uri rpkit
// was constructed with, so a step-up redirect drops back into the
// same RP after authentication.
func TestStepUpHandler_PreservesClientAndRedirect(t *testing.T) {
	t.Parallel()

	cf := newCodeFlow(t)
	q := recordRedirect(t, cf.StepUpHandler("urn:example:acr:high"))

	if got := q.Get("client_id"); got != "demo-rp" {
		t.Errorf("client_id = %q, want \"demo-rp\"", got)
	}
	if got := q.Get("redirect_uri"); got != "http://rp.example/callback" {
		t.Errorf("redirect_uri = %q, want \"http://rp.example/callback\"", got)
	}
	if got := q.Get("scope"); !strings.Contains(got, "openid") {
		t.Errorf("scope = %q, missing \"openid\"", got)
	}
}

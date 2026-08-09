//go:build example

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeProvider serves the discovery document newRelyingParty consumes and
// nothing else: the tests below stop at the callback's own checks, so no
// token endpoint is ever answered. Each tweak edits the document before it
// is served, which is how a test changes the provider's advertised
// posture.
func fakeProvider(t *testing.T, tweaks ...func(doc map[string]any)) string {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                                         srv.URL,
			"authorization_endpoint":                         srv.URL + "/authorize",
			"token_endpoint":                                 srv.URL + "/token",
			"jwks_uri":                                       srv.URL + "/jwks",
			"response_types_supported":                       []string{"code"},
			"subject_types_supported":                        []string{"public"},
			"id_token_signing_alg_values_supported":          []string{"ES256"},
			"code_challenge_methods_supported":               []string{"S256"},
			"authorization_response_iss_parameter_supported": true,
		}
		for _, tweak := range tweaks {
			tweak(doc)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	return srv.URL
}

func newTestRelyingParty(t *testing.T, tweaks ...func(doc map[string]any)) (*relyingParty, string) {
	t.Helper()
	issuer := fakeProvider(t, tweaks...)
	rp, err := newRelyingParty(context.Background(), config{
		Issuer:      issuer,
		ClientID:    "sample-rp",
		RedirectURI: "http://127.0.0.1:9090/callback",
	})
	if err != nil {
		t.Fatalf("newRelyingParty: %v", err)
	}
	return rp, issuer
}

// startedState drives /login and returns the state the redirect carried,
// so a callback test exercises a flow this client actually started.
func startedState(t *testing.T, rp *relyingParty) string {
	t.Helper()
	rec := httptest.NewRecorder()
	rp.login(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("/login status = %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("/login redirect carried no state")
	}
	return state
}

func runCallback(t *testing.T, rp *relyingParty, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	rp.callback(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/callback?"+q.Encode(), nil))
	return rec
}

// TestCallbackRejectsForeignIssuer pins the RFC 9207 §2.4 check: a
// response naming a different provider is refused before the code is
// exchanged. Without it the client is open to the mix-up attack, where an
// attacker who steers the authorization request to a provider they run
// gets this client to redeem a code they minted.
func TestCallbackRejectsForeignIssuer(t *testing.T) {
	t.Parallel()

	rp, _ := newTestRelyingParty(t)
	rec := runCallback(t, rp, url.Values{
		"state": {startedState(t, rp)},
		"code":  {"code-from-the-attacker"},
		"iss":   {"https://attacker.example"},
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %q", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "different provider") {
		t.Errorf("body = %q, want it to name the provider mismatch", body)
	}
}

// TestCallbackRejectsMissingIssuer covers the other half: this provider
// advertises that it stamps iss on every response, so a response without
// one did not come from it.
func TestCallbackRejectsMissingIssuer(t *testing.T) {
	t.Parallel()

	rp, _ := newTestRelyingParty(t)
	rec := runCallback(t, rp, url.Values{
		"state": {startedState(t, rp)},
		"code":  {"code-without-an-issuer"},
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %q", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "did not identify itself") {
		t.Errorf("body = %q, want it to report the missing identification", body)
	}
}

// TestCallbackAcceptsMatchingIssuer is the control for the two rejections
// above: with the provider's own issuer the callback proceeds to the token
// exchange, which the fake provider does not answer. The distinct failure
// proves the response was not turned away by the issuer check.
func TestCallbackAcceptsMatchingIssuer(t *testing.T) {
	t.Parallel()

	rp, issuer := newTestRelyingParty(t)
	rec := runCallback(t, rp, url.Values{
		"state": {startedState(t, rp)},
		"code":  {"code-from-the-provider"},
		"iss":   {issuer},
	})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 from the code exchange; body = %q", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "exchange the authorization code") {
		t.Errorf("body = %q, want the code exchange to be what failed", body)
	}
}

// TestCallbackAllowsAbsentIssuerWhenNotAdvertised pins the conditional
// half of the rule: a provider that never announced the parameter is not
// expected to send it, so its absence alone is not a rejection.
func TestCallbackAllowsAbsentIssuerWhenNotAdvertised(t *testing.T) {
	t.Parallel()

	rp, _ := newTestRelyingParty(t, func(doc map[string]any) {
		delete(doc, "authorization_response_iss_parameter_supported")
	})
	rec := runCallback(t, rp, url.Values{
		"state": {startedState(t, rp)},
		"code":  {"code-from-a-legacy-provider"},
	})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 from the code exchange; body = %q", rec.Code, rec.Body.String())
	}
}

// TestPlaintextRedisWarningIsLogged pins that the warning the Redis
// adapter emits reaches the application's log. The sink is a required
// argument of the adapter's escape hatch precisely so an operator learns
// the link is unencrypted; a no-op closure would satisfy the compiler and
// silence exactly the thing the argument exists for.
func TestPlaintextRedisWarningIsLogged(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	const dsn = "redis://sample:sample-secret@127.0.0.1:6379/0" //nolint:gosec // synthetic credential verifies redaction.
	cfg := config{RedisDSN: dsn}

	plaintextRedisWarning(cfg, logger)("oidcredis: TLS is NOT being enforced")

	logged := buf.String()
	if !strings.Contains(logged, "TLS is NOT being enforced") {
		t.Errorf("log = %q, want the adapter's warning", logged)
	}
	if !strings.Contains(logged, "127.0.0.1:6379") {
		t.Errorf("log = %q, want the Redis endpoint named", logged)
	}
	if strings.Contains(logged, "sample-secret") {
		t.Errorf("log = %q, must not carry the DSN credentials", logged)
	}
}

package op_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// /end_session's confirmation step is a browser ceremony, not an API
// call: the OP renders an HTML form carrying a double-submit CSRF token
// and the user posts it back. It therefore shares the /interaction
// routes' trust boundary, and the two must agree on which origins may
// drive a ceremony. When they disagree the wider layer decides what the
// browser is allowed to attempt while the narrower one decides what
// succeeds, which is how an origin ends up being handed a CSRF token it
// can never spend — or, in the other direction, how an origin that only
// ever registered a redirect_uri gains a say in someone's sign-out.
//
// These tests probe the mounted routes rather than the allowlist
// builders: the defect this pins is which list each layer of a route was
// wired with.

const (
	// endSessionCeremonyPath is the default /end_session mount.
	endSessionCeremonyPath = "/oidc/end_session"

	// authorizeCeremonyPath is the default /authorize mount, used to
	// stage the interaction the gate probe posts to.
	authorizeCeremonyPath = "/oidc/auth"

	// logoutConfirmCookie is the double-submit cookie the /end_session
	// interstitial stamps and the confirmation POST replays.
	logoutConfirmCookie = "__Host-oidc_logout_csrf"
)

// serveCeremony dispatches req against provider and returns the recorded
// response. Requests are addressed at the issuer rather than at a
// loopback test server so the OP sees the host it was configured for,
// which is what a deployment behind a reverse proxy presents.
func serveCeremony(tb testing.TB, provider *op.Provider, req *http.Request) *http.Response {
	tb.Helper()
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, req)
	return rec.Result()
}

// endSessionConfirmAdmitted runs the real interstitial GET → confirmation
// POST round-trip with origin on the POST and reports whether the CSRF
// gate admitted it. Admission is read off the endpoint's own contract: an
// admitted confirmation renders the signed-out page (200), a rejected one
// the static error page (400).
//
// The GET carries no Origin header because a top-level navigation does
// not have one; only the POST is a state-changing cross-origin candidate.
func endSessionConfirmAdmitted(tb testing.TB, provider *op.Provider, origin string) bool {
	tb.Helper()

	getResp := serveCeremony(tb, provider, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, validIssuer+endSessionCeremonyPath, http.NoBody,
	))
	defer func() { _ = getResp.Body.Close() }()
	_, _ = io.Copy(io.Discard, getResp.Body)
	var token string
	for _, c := range getResp.Cookies() {
		if c.Name == logoutConfirmCookie {
			token = c.Value
		}
	}
	if token == "" {
		tb.Fatalf("interstitial GET did not stamp %s; cookies=%v", logoutConfirmCookie, getResp.Cookies())
	}

	form := url.Values{
		"logout_csrf":              {token},
		"logout_scope_fingerprint": {"all"},
	}
	postReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		validIssuer+endSessionCeremonyPath, strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Origin", origin)
	postReq.AddCookie(&http.Cookie{Name: logoutConfirmCookie, Value: token})
	postResp := serveCeremony(tb, provider, postReq)
	defer func() { _ = postResp.Body.Close() }()
	body, _ := io.ReadAll(postResp.Body)
	switch postResp.StatusCode {
	case http.StatusOK:
		return true
	case http.StatusBadRequest:
		return false
	default:
		tb.Fatalf("POST %s from %s: status=%d want 200 (admitted) or 400 (rejected); body=%s",
			endSessionCeremonyPath, origin, postResp.StatusCode, body)
		return false
	}
}

// stageInteraction drives /authorize far enough to obtain a live
// interaction: the redirect target and the cookies the OP stamped on the
// way. The interaction endpoint answers 404 to anything not carrying the
// sealed interaction cookie, so the origin gate is only reachable from a
// real ceremony.
func stageInteraction(tb testing.TB, provider *op.Provider) (path string, cookies []*http.Cookie) {
	tb.Helper()

	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"client_id":             {"spa"},
		"response_type":         {"code"},
		"redirect_uri":          {clientRedirectOrigin + "/callback"},
		"scope":                 {"openid"},
		"state":                 {"state-ceremony-parity"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	resp := serveCeremony(tb, provider, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet,
		validIssuer+authorizeCeremonyPath+"?"+values.Encode(), http.NoBody,
	))
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusFound {
		tb.Fatalf("authorize status=%d want 302; body=%s", resp.StatusCode, body)
	}
	location, err := resp.Location()
	if err != nil {
		tb.Fatalf("authorize Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		tb.Fatalf("authorize Location=%s, want an interaction path", location)
	}
	return location.RequestURI(), resp.Cookies()
}

// interactionOriginRefusal is the description /interaction renders when
// the origin gate rejects a submission. Every later ceremony check also
// answers 403, so the status alone does not identify which gate spoke;
// the description does.
const interactionOriginRefusal = "origin not allowed"

// interactionPostAdmitted asks the /interaction gate the same question
// for the same origin. The submission carries no CSRF token, so an
// admitted origin is stopped one step further in — which is exactly the
// observation wanted: the origin gate let it through.
func interactionPostAdmitted(tb testing.TB, provider *op.Provider, origin string) bool {
	tb.Helper()

	path, cookies := stageInteraction(tb, provider)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		validIssuer+path, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp := serveCeremony(tb, provider, req)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	refused := resp.StatusCode == http.StatusForbidden &&
		strings.Contains(string(body), interactionOriginRefusal)
	return !refused
}

// TestEndSessionConfirmation_SharesInteractionOriginAllowlist is the
// acceptance check for the shared list. Under a configuration where the
// three origin classes are distinguishable — the issuer, an origin
// enumerated through [op.WithCORSOrigins], and an origin the OP knows
// only as some client's redirect_uri — both browser ceremonies must
// reach the same verdict on each.
//
// The redirect_uri row is the one that matters. Registering a client is
// not a statement that its callback page may end another user's session;
// hosting the OP's own UI elsewhere is, and that is what
// [op.WithCORSOrigins] says.
func TestEndSessionConfirmation_SharesInteractionOriginAllowlist(t *testing.T) {
	t.Parallel()

	provider := ceremonyCORSProvider(t)
	rows := []struct {
		origin string
		want   bool
	}{
		{origin: ceremonyIssuerOrigin, want: true},
		{origin: ceremonyUIOrigin, want: true},
		{origin: clientRedirectOrigin, want: false},
	}
	for _, row := range rows {
		endSession := endSessionConfirmAdmitted(t, provider, row.origin)
		interaction := interactionPostAdmitted(t, provider, row.origin)
		if endSession != interaction {
			t.Errorf("%s: /end_session admits=%v, /interaction admits=%v; the two ceremony gates "+
				"enforce different origin allowlists", row.origin, endSession, interaction)
		}
		if endSession != row.want {
			t.Errorf("%s: /end_session admits=%v, want %v", row.origin, endSession, row.want)
		}
	}
}

// TestEndSessionRoute_CORSHonoursCeremonyAllowlist pins the other layer
// on the same route. The interstitial body carries the confirmation
// token; a credentialed cross-origin read of it by a non-participant
// origin hands that origin the one secret the double-submit gate exists
// to withhold. SameSite=Strict on the confirmation cookie does not close
// this on its own, because a sibling subdomain is cross-origin but
// same-site.
func TestEndSessionRoute_CORSHonoursCeremonyAllowlist(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(ceremonyCORSProvider(t))
	t.Cleanup(srv.Close)

	what := "GET " + endSessionCeremonyPath
	assertCORSDenied(t, corsHeadersFor(t, srv, endSessionCeremonyPath, clientRedirectOrigin), what, clientRedirectOrigin)
	assertCORSAllowed(t, corsHeadersFor(t, srv, endSessionCeremonyPath, ceremonyIssuerOrigin), what, ceremonyIssuerOrigin)
	assertCORSAllowed(t, corsHeadersFor(t, srv, endSessionCeremonyPath, ceremonyUIOrigin), what, ceremonyUIOrigin)
}

// TestEndSessionRoute_PreflightMatchesConfirmationGate closes the loop
// between the two layers: an origin the confirmation POST would reject
// must not be told by the preflight that the POST is worth sending, and
// an origin it would accept must not be stopped before it arrives.
func TestEndSessionRoute_PreflightMatchesConfirmationGate(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(ceremonyCORSProvider(t))
	t.Cleanup(srv.Close)

	rows := []struct {
		origin     string
		wantStatus int
	}{
		{origin: ceremonyIssuerOrigin, wantStatus: http.StatusNoContent},
		{origin: ceremonyUIOrigin, wantStatus: http.StatusNoContent},
		{origin: clientRedirectOrigin, wantStatus: http.StatusForbidden},
	}
	for _, row := range rows {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodOptions,
			srv.URL+endSessionCeremonyPath, http.NoBody)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Origin", row.origin)
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("preflight from %s: %v", row.origin, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != row.wantStatus {
			t.Errorf("preflight from %s: status=%d, want %d", row.origin, resp.StatusCode, row.wantStatus)
		}
	}
}

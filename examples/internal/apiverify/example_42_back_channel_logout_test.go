//go:build apiverify

package apiverify

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// 42 promises the OP POSTs a signed Logout Token to every client that
// registered a backchannel_logout_uri once the session behind it ends.
// That delivery is the deliverable, and it is unreachable from a probe
// that stops at the login prompt: the fan-out only happens for a request
// that carries the session cookie the sign-in established. So the probe
// walks the whole route the header doc describes — sign in, redeem the
// code, end the session with the resulting id_token as the hint — and
// asserts the RP stub in the same process logged the token it received.
func TestExample42BackChannelLogout(t *testing.T) {
	const (
		baseURL     = "http://127.0.0.1:8080"
		clientID    = "demo-rp"
		secret      = "bcl-demo-secret-rotate-me"
		redirectURI = "http://127.0.0.1:5173/callback"
	)

	p := buildAndStart(t, "../../42-back-channel-logout")
	defer p.kill()

	doc := pollHTTP(t, p, baseURL+"/.well-known/openid-configuration", 20*time.Second)
	authorize := discoveryEndpointPath(t, doc, "authorization_endpoint")
	tokenPath := discoveryEndpointPath(t, doc, "token_endpoint")
	endSession := discoveryEndpointPath(t, doc, "end_session_endpoint")

	// One browser identity for the whole walkthrough: the session the
	// sign-in establishes is the one /end_session has to resolve, and a
	// second client (a bare curl, a fresh jar) resolves no session at
	// all, so the OP returns before it reaches the fan-out.
	b := newBrowser(t, baseURL)
	params := authorizeParams(clientID, redirectURI, "openid profile")
	b.signIn(baseURL+authorize+"?"+params.Encode(), htmlSubmitter{}, exampleUser{
		username: "demo",
		password: "demo-password",
	})

	code := authorizationCode(t, b.finalURL)
	idToken := redeemForIDToken(t, baseURL+tokenPath, clientID, secret, code, redirectURI)

	status, _, body := b.do(http.MethodGet,
		baseURL+endSession+"?"+url.Values{"id_token_hint": {idToken}}.Encode(), "", "", nil)
	if status != http.StatusOK {
		t.Fatalf("GET %s returned %d, want the signed-out page:\n%s\n%s", endSession, status, body, p.readLog())
	}

	// The RP stub prints this line from its own handler, so it is proof
	// the POST arrived — a 200 on /end_session says only that the OP
	// finished the request, which it also does when the fan-out reaches
	// nobody.
	waitForLog(t, p, "RP received Logout Token", 10*time.Second)
}

// authorizationCode pulls the code off the RP callback the authorization
// completed on, failing when the OP redirected somewhere else.
func authorizationCode(t *testing.T, callback string) string {
	t.Helper()
	if callback == "" {
		t.Fatal("the authorization never redirected off the OP, so no code was issued")
	}
	u, err := url.Parse(callback)
	if err != nil {
		t.Fatalf("parse callback %q: %v", callback, err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("callback %q carries no code", callback)
	}
	return code
}

// redeemForIDToken exchanges an authorization code for the ID token
// /end_session takes as its hint.
func redeemForIDToken(t *testing.T, tokenURL, clientID, secret, code, redirectURI string) string {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {pkceVerifier},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var payload struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode token response (status %d): %v", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || payload.IDToken == "" {
		t.Fatalf("token endpoint returned %d with no id_token", resp.StatusCode)
	}
	return payload.IDToken
}

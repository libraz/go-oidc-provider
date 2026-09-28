package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// The canonical acr URIs of AAL1 and AAL2, which is what a session records.
const (
	bronzeACR = "urn:mace:incommon:iap:bronze"
	silverACR = "urn:mace:incommon:iap:silver"
)

// TestEndToEnd_ACRStepUp exercises the RFC 9470 step-up transition end to
// end against a real session. A first login binds the session at AAL1,
// which the session records as that level's canonical acr:
//
//   - a repeat /authorize requesting that acr is served silently (the
//     session already satisfies the request), and
//   - a subsequent /authorize requesting the AAL2 acr forces a re-auth
//     interaction (the session's acr is not in the requested set), after
//     which the configured policy's verdict for the new request is
//     reported. The default policy echoes a requested value once any
//     factor ran, so that verdict is the AAL2 acr.
//
// This is the full-flow counterpart to the decision-matrix unit tests in
// authorize_test.go: it proves the step-up not only redirects to an
// interaction but ends with the requested authentication context on the
// wire.
//
// Tracks: CVE-2026-97176 — a step-up acr requirement was satisfied by a
// session that had only reached a weaker level, letting a stale or
// reused session stand in for the stronger factor a policy demanded.
func TestEndToEnd_ACRStepUp(t *testing.T) {
	t.Parallel()
	clock := fakeClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-stepup",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)

	authorize := func(t *testing.T, acrValues string) *http.Response {
		t.Helper()
		v := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
		v.Set("acr_values", acrValues)
		resp, err := newGet(tk.Server.URL + "/oidc/auth?" + v.Encode()).Do(client)
		if err != nil {
			t.Fatalf("GET /authorize: %v", err)
		}
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("authorize status=%d want 302", resp.StatusCode)
		}
		return resp
	}

	// completeLogin runs the interaction the authorize redirect points to:
	// GET the first prompt, POST the bound subject, approve consent when
	// prompted, and return the authorization code from the RP redirect.
	completeLogin := func(t *testing.T, location *url.URL) string {
		t.Helper()
		stepResp, err := newGet(tk.Server.URL + location.Path).Do(client)
		if err != nil {
			t.Fatalf("GET interaction: %v", err)
		}
		defer stepResp.Body.Close()
		step := decodeMap(t, stepResp)
		stateRef, _ := step["state_ref"].(string)
		csrfCookie := findCookie(stepResp.Cookies(), "__Host-oidc_csrf")
		if csrfCookie == nil {
			t.Fatal("csrf cookie missing")
		}
		raw, err := json.Marshal(map[string]any{
			"state_ref": stateRef,
			"values":    map[string]string{"subject": "user-stepup"},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			tk.Server.URL+location.Path, bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		postReq.Header.Set("Content-Type", "application/json")
		postReq.Header.Set("Origin", tk.Issuer)
		postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
		postReq.AddCookie(csrfCookie)
		postResp, err := client.Do(postReq)
		if err != nil {
			t.Fatalf("POST interaction: %v", err)
		}
		defer postResp.Body.Close()
		finalResp := completeConsentIfPrompted(t, client, tk.Server.URL+location.Path, tk.Issuer, csrfCookie.Value, postResp)
		defer finalResp.Body.Close()
		if finalResp.StatusCode != http.StatusFound {
			dump, _ := io.ReadAll(finalResp.Body)
			t.Fatalf("interaction final status=%d body=%s", finalResp.StatusCode, string(dump))
		}
		rpRedirect, err := finalResp.Location()
		if err != nil {
			t.Fatalf("Location: %v", err)
		}
		code := rpRedirect.Query().Get("code")
		if code == "" {
			t.Fatalf("no code in %s", rpRedirect.String())
		}
		return code
	}

	exchange := func(t *testing.T, code string) map[string]any {
		t.Helper()
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {rp.RedirectURIs[0]},
			"code_verifier": {e2eVerifier},
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("NewRequest token: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(rp.ID, secret)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST /token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			dump, _ := io.ReadAll(resp.Body)
			t.Fatalf("token status=%d body=%s", resp.StatusCode, string(dump))
		}
		tokenBody := decodeMap(t, resp)
		idt, _ := tokenBody["id_token"].(string)
		if idt == "" {
			t.Fatalf("id_token missing: %v", tokenBody)
		}
		return decodeIDTokenPayload(t, idt)
	}

	// Pass 1: no session yet → interaction → id_token acr bronze.
	resp1 := authorize(t, bronzeACR)
	loc1, err := resp1.Location()
	resp1.Body.Close()
	if err != nil {
		t.Fatalf("Location pass 1: %v", err)
	}
	if loc1.Query().Get("code") != "" {
		t.Fatalf("pass 1 expected an interaction redirect, got direct code: %s", loc1.String())
	}
	claims1 := exchange(t, completeLogin(t, loc1))
	if got, _ := claims1["acr"].(string); got != bronzeACR {
		t.Fatalf("pass 1 id_token acr=%q want %s", got, bronzeACR)
	}

	// Pass 2: session satisfies acr_values=bronze → silent code, no interaction.
	resp2 := authorize(t, bronzeACR)
	loc2, err := resp2.Location()
	resp2.Body.Close()
	if err != nil {
		t.Fatalf("Location pass 2: %v", err)
	}
	code2 := loc2.Query().Get("code")
	if code2 == "" {
		t.Fatalf("pass 2 expected a silent code redirect, got: %s", loc2.String())
	}
	if claims2 := exchange(t, code2); claims2["acr"] != bronzeACR {
		t.Errorf("pass 2 id_token acr=%v want %s", claims2["acr"], bronzeACR)
	}

	// Pass 3: session acr bronze is not in acr_values=silver → step-up
	// interaction, then the policy's verdict silver is reported.
	resp3 := authorize(t, silverACR)
	loc3, err := resp3.Location()
	resp3.Body.Close()
	if err != nil {
		t.Fatalf("Location pass 3: %v", err)
	}
	if loc3.Query().Get("code") != "" {
		t.Fatalf("pass 3 expected a step-up interaction, got direct code: %s", loc3.String())
	}
	if !strings.HasPrefix(loc3.Path, "/oidc/interaction") {
		t.Fatalf("pass 3 redirect=%s want interaction path", loc3.String())
	}
	claims3 := exchange(t, completeLogin(t, loc3))
	if got, _ := claims3["acr"].(string); got != silverACR {
		t.Errorf("pass 3 id_token acr=%q want %s (stepped up)", got, silverACR)
	}
}

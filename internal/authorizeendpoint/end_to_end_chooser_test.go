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
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// chooserCookieKey is the deterministic 32-byte AES-256-GCM key the
// chooser end-to-end test injects via [op.WithCookieKeys]. The fixed
// value lets the test build a parallel [sessions.Manager] that the
// running provider's session cookie codec round-trips with.
const chooserCookieKey = "0123456789abcdef0123456789abcdef"

// TestEndToEnd_ChooserSelectAccount_HappyPath drives the chooser flow
// end-to-end. Two accounts are seeded into the same chooser group via a
// parallel [sessions.Manager]; /authorize?prompt=select_account routes
// to the built-in chooser; the SPA picks the second account; the
// orchestrator binds that subject and the consent screen runs because
// the picked subject has no cached grant. The final session cookie
// MUST carry the original chooser_group_id (rebind via
// [sessions.Manager.Switch]) and the picked SessionID.
func TestEndToEnd_ChooserSelectAccount_HappyPath(t *testing.T) {
	t.Parallel()
	clock := fakeClock{now: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}
	cookieKey := []byte(chooserCookieKey)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithCookieKeys(cookieKey)),
	)
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-chooser",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	mgr, sessCodec := newChooserSessionsManager(t, tk.Store.Sessions(), cookieKey, clock)
	ctx := context.Background()
	sessA, err := mgr.Issue(ctx, sessions.Login{Subject: "user-A", AuthTime: clock.now})
	if err != nil {
		t.Fatalf("Issue user-A: %v", err)
	}
	sessB, err := mgr.AddAccount(ctx, sessA.ChooserGroupID, sessions.Login{
		Subject:  "user-B",
		AuthTime: clock.now,
	})
	if err != nil {
		t.Fatalf("AddAccount user-B: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)

	// Hop 1: /authorize?prompt=select_account with the seeded session
	// cookie attached. Cookiejar refuses to deliver Secure cookies on
	// the httptest HTTP origin; every hop in this test attaches the
	// cookies it needs explicitly via req.AddCookie.
	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("prompt", "select_account")
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	authReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d, want 302", authResp.StatusCode)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		t.Fatalf("Location=%s, want /oidc/interaction/...", location.String())
	}
	interactionURL := tk.Server.URL + location.Path
	interactionCookie := findCookie(authResp.Cookies(), cookie.InteractionProfile.Name)
	if interactionCookie == nil {
		t.Fatal("__Host-oidc_interaction cookie missing on authorize 302")
	}

	// Hop 2: GET /interaction → expect chooser prompt enumerating both
	// seeded accounts.
	stepReq, err := http.NewRequestWithContext(ctx, http.MethodGet, interactionURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest GET interaction: %v", err)
	}
	stepReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	stepReq.AddCookie(interactionCookie)
	stepResp, err := client.Do(stepReq)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(stepResp.Body)
		t.Fatalf("interaction GET status=%d body=%s", stepResp.StatusCode, string(dump))
	}
	step := decodeMap(t, stepResp)
	if got, _ := step["type"].(string); got != "interaction.chooser" {
		t.Fatalf("prompt type = %q, want interaction.chooser", got)
	}
	accounts := chooserAccountsFromPrompt(t, step)
	if len(accounts) != 2 {
		t.Fatalf("chooser accounts = %d, want 2: %v", len(accounts), accounts)
	}
	subjectToSession := map[string]string{}
	for _, a := range accounts {
		subj, _ := a["Subject"].(string)
		sid, _ := a["SessionID"].(string)
		subjectToSession[subj] = sid
	}
	if subjectToSession["user-A"] != sessA.SessionID || subjectToSession["user-B"] != sessB.SessionID {
		t.Fatalf("chooser subject->session = %v, want {user-A:%s, user-B:%s}",
			subjectToSession, sessA.SessionID, sessB.SessionID)
	}

	stateRef, _ := step["state_ref"].(string)
	csrfCookie := findCookie(stepResp.Cookies(), cookie.CSRFProfile.Name)
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing on interaction GET")
	}

	// Hop 3: POST submit user-B's session_id to the chooser.
	body := map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"session_id": sessB.SessionID},
	}
	rawBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		interactionURL, bytes.NewReader(rawBody))
	if err != nil {
		t.Fatalf("NewRequest POST interaction: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postReq.AddCookie(csrfCookie)
	postReq.AddCookie(interactionCookie)
	postReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("POST chooser: %v", err)
	}
	defer postResp.Body.Close()

	// completeConsentIfPrompted walks the consent screen with every
	// requested scope approved. The picked subject (user-B) has no
	// cached grant for this client, so the chain pauses at consent.
	finalResp := completeConsentIfPrompted(t, client, interactionURL, tk.Issuer, csrfCookie.Value, postResp)
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("final status=%d body=%s", finalResp.StatusCode, string(dump))
	}
	rpRedirect, err := finalResp.Location()
	if err != nil {
		t.Fatalf("Location after chooser: %v", err)
	}
	code := rpRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", rpRedirect.String())
	}

	// Session cookie MUST carry the original chooser_group_id and
	// point at the picked SessionID — Switch was used, not Issue.
	sessionCookie := findCookie(finalResp.Cookies(), cookie.SessionProfile.Name)
	if sessionCookie == nil {
		t.Fatal("session cookie not refreshed on chooser termination")
	}
	payload, err := sessCodec.Decode(sessionCookie.Value)
	if err != nil {
		t.Fatalf("decode session cookie: %v", err)
	}
	if payload.ChooserGroupID != sessA.ChooserGroupID {
		t.Errorf("ChooserGroupID after chooser = %q, want %q (Switch path, not Issue)",
			payload.ChooserGroupID, sessA.ChooserGroupID)
	}
	if payload.CurrentSessionID != sessB.SessionID {
		t.Errorf("CurrentSessionID = %q, want %q (picked account)",
			payload.CurrentSessionID, sessB.SessionID)
	}

	// Token exchange MUST mint an id_token whose sub is user-B.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rp.RedirectURIs[0]},
		"code_verifier": {e2eVerifier},
	}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(rp.ID, secret)
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("/token status=%d body=%s", tokenResp.StatusCode, string(dump))
	}
	tokenBody := decodeMap(t, tokenResp)
	idt, _ := tokenBody["id_token"].(string)
	if idt == "" {
		t.Fatalf("id_token missing: %v", tokenBody)
	}
	idClaims := decodeIDTokenPayload(t, idt)
	if got, _ := idClaims["sub"].(string); got != "user-B" {
		t.Errorf("id_token sub = %q, want user-B (chooser-picked subject)", got)
	}
}

// TestEndToEnd_ChooserSelectAccount_SeedsACRAMRFromSession pins the
// account-chooser assurance fallback: when the user picks an existing
// session (select_account) no authenticator runs, so the chain carries
// no factors. The terminate path MUST seed acr / amr from the chosen
// session record rather than emitting an empty acr / nil amr, so the
// minted id_token reflects the assurance the picked session already
// achieved.
func TestEndToEnd_ChooserSelectAccount_SeedsACRAMRFromSession(t *testing.T) {
	t.Parallel()
	clock := fakeClock{now: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}
	cookieKey := []byte(chooserCookieKey)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithCookieKeys(cookieKey)),
	)
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-chooser-acr",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	const wantACR = "urn:mace:incommon:iap:silver"
	wantAMR := []string{"pwd", "otp"}

	mgr, _ := newChooserSessionsManager(t, tk.Store.Sessions(), cookieKey, clock)
	ctx := context.Background()
	sessA, err := mgr.Issue(ctx, sessions.Login{Subject: "user-A", AuthTime: clock.now})
	if err != nil {
		t.Fatalf("Issue user-A: %v", err)
	}
	// user-B's session already reached AAL2 (password + TOTP). This is
	// the assurance the chooser re-entry must carry into the id_token.
	sessB, err := mgr.AddAccount(ctx, sessA.ChooserGroupID, sessions.Login{
		Subject:  "user-B",
		AuthTime: clock.now,
		ACR:      wantACR,
		AMR:      wantAMR,
	})
	if err != nil {
		t.Fatalf("AddAccount user-B: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)

	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("prompt", "select_account")
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	authReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	interactionURL := tk.Server.URL + location.Path
	interactionCookie := findCookie(authResp.Cookies(), cookie.InteractionProfile.Name)
	if interactionCookie == nil {
		t.Fatal("__Host-oidc_interaction cookie missing on authorize 302")
	}

	stepReq, err := http.NewRequestWithContext(ctx, http.MethodGet, interactionURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest GET interaction: %v", err)
	}
	stepReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	stepReq.AddCookie(interactionCookie)
	stepResp, err := client.Do(stepReq)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	step := decodeMap(t, stepResp)
	if got, _ := step["type"].(string); got != "interaction.chooser" {
		t.Fatalf("prompt type = %q, want interaction.chooser", got)
	}
	stateRef, _ := step["state_ref"].(string)
	csrfCookie := findCookie(stepResp.Cookies(), cookie.CSRFProfile.Name)
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing on interaction GET")
	}

	body := map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"session_id": sessB.SessionID},
	}
	rawBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, interactionURL, bytes.NewReader(rawBody))
	if err != nil {
		t.Fatalf("NewRequest POST interaction: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postReq.AddCookie(csrfCookie)
	postReq.AddCookie(interactionCookie)
	postReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("POST chooser: %v", err)
	}
	defer postResp.Body.Close()

	finalResp := completeConsentIfPrompted(t, client, interactionURL, tk.Issuer, csrfCookie.Value, postResp)
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("final status=%d body=%s", finalResp.StatusCode, string(dump))
	}
	rpRedirect, err := finalResp.Location()
	if err != nil {
		t.Fatalf("Location after chooser: %v", err)
	}
	code := rpRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", rpRedirect.String())
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rp.RedirectURIs[0]},
		"code_verifier": {e2eVerifier},
	}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(rp.ID, secret)
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("/token status=%d body=%s", tokenResp.StatusCode, string(dump))
	}
	tokenBody := decodeMap(t, tokenResp)
	idt, _ := tokenBody["id_token"].(string)
	if idt == "" {
		t.Fatalf("id_token missing: %v", tokenBody)
	}
	idClaims := decodeIDTokenPayload(t, idt)
	if got, _ := idClaims["sub"].(string); got != "user-B" {
		t.Errorf("id_token sub = %q, want user-B", got)
	}
	if got, _ := idClaims["acr"].(string); got != wantACR {
		t.Errorf("id_token acr = %q, want %q (seeded from chosen session)", got, wantACR)
	}
	rawAMR, _ := idClaims["amr"].([]any)
	gotAMR := make([]string, 0, len(rawAMR))
	for _, v := range rawAMR {
		if s, ok := v.(string); ok {
			gotAMR = append(gotAMR, s)
		}
	}
	if strings.Join(gotAMR, ",") != strings.Join(wantAMR, ",") {
		t.Errorf("id_token amr = %v, want %v (seeded from chosen session)", gotAMR, wantAMR)
	}
}

// TestEndToEnd_ChooserAddAccountURL_AddsAccountToExistingGroup drives the
// public multi-account path rather than seeding the second account directly:
// a chooser prompt renders AddAccountURL, the browser follows it with the
// original session cookie, a fresh login authenticates user-B, and the
// terminal session is added to user-A's chooser group.
func TestEndToEnd_ChooserAddAccountURL_AddsAccountToExistingGroup(t *testing.T) {
	t.Parallel()
	clock := fakeClock{now: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}
	cookieKey := []byte(chooserCookieKey)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithCookieKeys(cookieKey)),
	)
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-add-account",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	mgr, sessCodec := newChooserSessionsManager(t, tk.Store.Sessions(), cookieKey, clock)
	ctx := context.Background()
	sessA, err := mgr.Issue(ctx, sessions.Login{Subject: "user-A", AuthTime: clock.now})
	if err != nil {
		t.Fatalf("Issue user-A: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)

	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("prompt", "select_account")
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize chooser: %v", err)
	}
	authReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET /authorize chooser: %v", err)
	}
	defer authResp.Body.Close()
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("chooser Location: %v", err)
	}
	chooserInteractionURL := tk.Server.URL + location.Path
	chooserInteractionCookie := findCookie(authResp.Cookies(), cookie.InteractionProfile.Name)
	if chooserInteractionCookie == nil {
		t.Fatal("__Host-oidc_interaction cookie missing on chooser authorize")
	}

	stepReq, err := http.NewRequestWithContext(ctx, http.MethodGet, chooserInteractionURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest chooser interaction: %v", err)
	}
	stepReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	stepReq.AddCookie(chooserInteractionCookie)
	stepResp, err := client.Do(stepReq)
	if err != nil {
		t.Fatalf("GET chooser interaction: %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(stepResp.Body)
		t.Fatalf("chooser GET status=%d body=%s", stepResp.StatusCode, string(dump))
	}
	step := decodeMap(t, stepResp)
	addAccountURL := chooserAddAccountURLFromPrompt(t, step)
	if addAccountURL == "" {
		t.Fatalf("AddAccountURL missing from chooser prompt: %v", step)
	}
	addURL, err := url.Parse(addAccountURL)
	if err != nil {
		t.Fatalf("parse AddAccountURL %q: %v", addAccountURL, err)
	}
	if got := addURL.Query().Get("prompt"); got != "login" {
		t.Fatalf("AddAccountURL prompt=%q want login: %s", got, addAccountURL)
	}

	addReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tk.Server.URL+addAccountURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest AddAccountURL: %v", err)
	}
	addReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	addResp, err := client.Do(addReq)
	if err != nil {
		t.Fatalf("GET AddAccountURL: %v", err)
	}
	defer addResp.Body.Close()
	if addResp.StatusCode != http.StatusFound {
		t.Fatalf("AddAccountURL status=%d, want 302", addResp.StatusCode)
	}
	addLocation, err := addResp.Location()
	if err != nil {
		t.Fatalf("AddAccountURL Location: %v", err)
	}
	addInteractionURL := tk.Server.URL + addLocation.Path
	addInteractionCookie := findCookie(addResp.Cookies(), cookie.InteractionProfile.Name)
	if addInteractionCookie == nil {
		t.Fatal("__Host-oidc_interaction cookie missing on add-account authorize")
	}

	authnReq, err := http.NewRequestWithContext(ctx, http.MethodGet, addInteractionURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest add-account interaction: %v", err)
	}
	authnReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	authnReq.AddCookie(addInteractionCookie)
	authnResp, err := client.Do(authnReq)
	if err != nil {
		t.Fatalf("GET add-account interaction: %v", err)
	}
	defer authnResp.Body.Close()
	if authnResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(authnResp.Body)
		t.Fatalf("add-account interaction status=%d body=%s", authnResp.StatusCode, string(dump))
	}
	authnStep := decodeMap(t, authnResp)
	if got, _ := authnStep["type"].(string); got == "interaction.chooser" {
		t.Fatalf("add-account flow rendered chooser again; want authenticator prompt")
	}
	stateRef, _ := authnStep["state_ref"].(string)
	csrfCookie := findCookie(authnResp.Cookies(), cookie.CSRFProfile.Name)
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing on add-account auth prompt")
	}
	body := map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"subject": "user-B"},
	}
	rawBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal auth body: %v", err)
	}
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, addInteractionURL, bytes.NewReader(rawBody))
	if err != nil {
		t.Fatalf("NewRequest add-account POST: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postReq.AddCookie(csrfCookie)
	postReq.AddCookie(addInteractionCookie)
	postReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("POST add-account auth: %v", err)
	}
	defer postResp.Body.Close()

	finalResp := postConsentWithSessionCookie(t, client, ctx, addInteractionURL, tk.Issuer, csrfCookie, addInteractionCookie, sessA.Cookie, postResp)
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("final status=%d body=%s", finalResp.StatusCode, string(dump))
	}
	sessionCookie := findCookie(finalResp.Cookies(), cookie.SessionProfile.Name)
	if sessionCookie == nil {
		t.Fatal("session cookie not refreshed after add-account")
	}
	payload, err := sessCodec.Decode(sessionCookie.Value)
	if err != nil {
		t.Fatalf("decode session cookie: %v", err)
	}
	if payload.ChooserGroupID != sessA.ChooserGroupID {
		t.Fatalf("ChooserGroupID=%q want original group %q", payload.ChooserGroupID, sessA.ChooserGroupID)
	}
	if payload.CurrentSessionID == sessA.SessionID {
		t.Fatal("CurrentSessionID still points at user-A; want newly added user-B session")
	}
	active, err := mgr.Resolve(ctx, sessionCookie.Value)
	if err != nil {
		t.Fatalf("Resolve add-account session: %v", err)
	}
	if active.Session.Subject != "user-B" {
		t.Fatalf("active subject=%q want user-B", active.Session.Subject)
	}
	rows, err := mgr.Accounts(ctx, sessA.ChooserGroupID)
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	subjects := make(map[string]bool, len(rows))
	for _, r := range rows {
		subjects[r.Subject] = true
	}
	if !subjects["user-A"] || !subjects["user-B"] || len(subjects) != 2 {
		t.Fatalf("chooser group subjects=%v, want user-A and user-B", subjects)
	}
}

// TestEndToEnd_FreshLoginDifferentSubjectStartsNewChooserGroup pins the
// session-grafting defence: a prompt=login submission against an
// /authorize request that carries an active cookie for a different
// subject MUST NOT join the existing chooser group. Cookie planting
// would otherwise let an attacker graft a victim's fresh login into the
// attacker's chooser group and switch to it later.
func TestEndToEnd_FreshLoginDifferentSubjectStartsNewChooserGroup(t *testing.T) {
	t.Parallel()
	clock := fakeClock{now: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}
	cookieKey := []byte(chooserCookieKey)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithCookieKeys(cookieKey)),
	)
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-multi",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	mgr, sessCodec := newChooserSessionsManager(t, tk.Store.Sessions(), cookieKey, clock)
	ctx := context.Background()
	sessA, err := mgr.Issue(ctx, sessions.Login{Subject: "user-A", AuthTime: clock.now})
	if err != nil {
		t.Fatalf("Issue user-A: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)

	// Drive /authorize?prompt=login with user-A's session cookie
	// attached. The orchestrator runs the testkit SubjectAuthenticator
	// for "user-B"; ensureSession sees the subject mismatch and MUST
	// issue a fresh chooser group instead of calling AddAccount.
	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("prompt", "login")
	values.Set("nonce", "n-multi")
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	authReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d, want 302", authResp.StatusCode)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	interactionURL := tk.Server.URL + location.Path
	interactionCookie := findCookie(authResp.Cookies(), cookie.InteractionProfile.Name)
	if interactionCookie == nil {
		t.Fatal("__Host-oidc_interaction cookie missing")
	}

	stepReq, err := http.NewRequestWithContext(ctx, http.MethodGet, interactionURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest GET interaction: %v", err)
	}
	stepReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	stepReq.AddCookie(interactionCookie)
	stepResp, err := client.Do(stepReq)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	step := decodeMap(t, stepResp)
	stateRef, _ := step["state_ref"].(string)
	csrfCookie := findCookie(stepResp.Cookies(), cookie.CSRFProfile.Name)
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing")
	}

	body := map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"subject": "user-B"},
	}
	rawBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, interactionURL, bytes.NewReader(rawBody))
	if err != nil {
		t.Fatalf("NewRequest POST: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postReq.AddCookie(csrfCookie)
	postReq.AddCookie(interactionCookie)
	postReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessA.Cookie})
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer postResp.Body.Close()
	// The orchestrator pauses at consent because user-B has no cached
	// grant for this client. Submit the consent prompt inline (rather
	// than via completeConsentIfPrompted) so the request carries
	// user-A's session cookie — this reproduces the cookie-planting
	// shape where a different-subject fresh login completes while an
	// unrelated active session cookie is present.
	finalResp := postConsentWithSessionCookie(t, client, ctx, interactionURL, tk.Issuer, csrfCookie, interactionCookie, sessA.Cookie, postResp)
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("final status=%d body=%s", finalResp.StatusCode, string(dump))
	}

	// The new session cookie MUST allocate a fresh chooser group
	// (Issue path), not join the original group (AddAccount path).
	sessionCookie := findCookie(finalResp.Cookies(), cookie.SessionProfile.Name)
	if sessionCookie == nil {
		t.Fatal("session cookie not refreshed")
	}
	payload, err := sessCodec.Decode(sessionCookie.Value)
	if err != nil {
		t.Fatalf("decode session cookie: %v", err)
	}
	if payload.ChooserGroupID == sessA.ChooserGroupID {
		t.Fatalf("ChooserGroupID after fresh login reused planted group %q; want fresh group", payload.ChooserGroupID)
	}
	if payload.CurrentSessionID == sessA.SessionID {
		t.Error("CurrentSessionID == sessA.SessionID, want a freshly-issued SessionID for user-B")
	}
	active, err := mgr.Resolve(ctx, sessionCookie.Value)
	if err != nil {
		t.Fatalf("Resolve new session: %v", err)
	}
	if active.Session.Subject != "user-B" {
		t.Fatalf("new session subject=%q want user-B", active.Session.Subject)
	}

	// The planted chooser group MUST remain user-A only.
	rows, err := mgr.Accounts(ctx, sessA.ChooserGroupID)
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	subjects := make(map[string]bool, len(rows))
	for _, r := range rows {
		subjects[r.Subject] = true
	}
	if !subjects["user-A"] || subjects["user-B"] {
		t.Errorf("planted chooser group subjects = %v, want only user-A", subjects)
	}
}

// TestEndToEnd_SelectAccount_NoSession_FallsBackToLogin asserts the
// hint matrix routes prompt=select_account with no active session to
// the standard login interaction (PromptLogin), not the chooser. The
// orchestrator-side guard depends on this: the chooser registers
// globally and self-skips when ChooserGroupID is empty, but the HTTP
// layer is what decides whether select_account requests reach the
// chooser at all.
func TestEndToEnd_SelectAccount_NoSession_FallsBackToLogin(t *testing.T) {
	t.Parallel()
	clock := fakeClock{now: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-fallback",
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
	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("prompt", "select_account")

	authResp, err := newGet(tk.Server.URL + "/oidc/auth?" + values.Encode()).Do(client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d, want 302 to /interaction", authResp.StatusCode)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		t.Fatalf("Location=%s want /oidc/interaction/...", location.String())
	}
	interactionCookie := findCookie(authResp.Cookies(), cookie.InteractionProfile.Name)
	if interactionCookie == nil {
		t.Fatal("__Host-oidc_interaction cookie missing on authorize 302")
	}
	stepReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+location.Path, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest interaction: %v", err)
	}
	stepReq.AddCookie(interactionCookie)
	stepResp, err := client.Do(stepReq)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	step := decodeMap(t, stepResp)
	if got, _ := step["type"].(string); got == "interaction.chooser" {
		t.Errorf("prompt type = %q, want the standard login authenticator (no chooser without an active session)", got)
	}
}

// newChooserSessionsManager builds a parallel [sessions.Manager] +
// [sessions.Codec] using the supplied cookie key and clock. The manager
// shares the in-memory [store.SessionStore] with the running provider
// so seeded accounts are visible to the chooser interaction at request
// time.
func newChooserSessionsManager(tb testing.TB, sessStore store.SessionStore, key []byte, clock fakeClock) (*sessions.Manager, *sessions.Codec) {
	tb.Helper()
	cookieCodec, err := cookie.NewCodec(key)
	if err != nil {
		tb.Fatalf("cookie.NewCodec: %v", err)
	}
	sessCodec, err := sessions.NewCodec(cookieCodec)
	if err != nil {
		tb.Fatalf("sessions.NewCodec: %v", err)
	}
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: sessCodec,
		Store: sessStore,
		Clock: func() time.Time { return clock.now },
	})
	if err != nil {
		tb.Fatalf("sessions.NewManager: %v", err)
	}
	return mgr, sessCodec
}

// postConsentWithSessionCookie submits the consent screen with every
// requested scope approved, threading both the interaction cookie and
// a __Host-oidc_session cookie through the request. The standard
// testkit helper (PostConsentApproval) only attaches the CSRF cookie
// because most tests do not exercise the session-cookie roundtrip;
// the chooser fresh-login test does, so it needs this helper.
func postConsentWithSessionCookie(
	tb testing.TB,
	client *http.Client,
	ctx context.Context,
	interactionURL, origin string,
	csrfCookie, interactionCookie *http.Cookie,
	sessionCookieValue string,
	prior *http.Response,
) *http.Response {
	tb.Helper()
	consent, env, err := testkit.IsConsentPrompt(prior)
	if err != nil {
		tb.Fatalf("inspect consent prompt: %v", err)
	}
	if !consent {
		return prior
	}
	stateRef, _ := env["state_ref"].(string)
	if stateRef == "" {
		tb.Fatal("consent prompt missing state_ref")
	}
	// Per-step CSRF scope binding rotates the cookie at each step
	// boundary, so the auth.* token does not verify against the
	// consent.* step. Pull the rotated cookie off the prior response.
	if rotated := findCookie(prior.Cookies(), cookie.CSRFProfile.Name); rotated != nil {
		csrfCookie = rotated
	}
	approved := approvedScopesFromPrompt(env)
	body := map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"approved_scopes": approved},
	}
	rawBody, err := json.Marshal(body)
	if err != nil {
		tb.Fatalf("marshal consent: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, interactionURL, bytes.NewReader(rawBody))
	if err != nil {
		tb.Fatalf("NewRequest consent: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	req.AddCookie(csrfCookie)
	req.AddCookie(interactionCookie)
	req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessionCookieValue})
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("POST consent: %v", err)
	}
	return resp
}

// chooserAccountsFromPrompt extracts the Accounts slice from a
// chooser prompt envelope. The JSON driver renders
// [interaction.ChooserAccount] fields as map[string]any; the helper
// keeps them as such so the test can assert per-row content without
// a typed unmarshal.
func chooserAccountsFromPrompt(tb testing.TB, env map[string]any) []map[string]any {
	tb.Helper()
	data, _ := env["data"].(map[string]any)
	if data == nil {
		tb.Fatalf("prompt envelope missing data: %v", env)
	}
	rawAccounts, _ := data["Accounts"].([]any)
	out := make([]map[string]any, 0, len(rawAccounts))
	for _, a := range rawAccounts {
		entry, _ := a.(map[string]any)
		if entry != nil {
			out = append(out, entry)
		}
	}
	return out
}

func chooserAddAccountURLFromPrompt(tb testing.TB, env map[string]any) string {
	tb.Helper()
	data, _ := env["data"].(map[string]any)
	if data == nil {
		tb.Fatalf("prompt envelope missing data: %v", env)
	}
	out, _ := data["AddAccountURL"].(string)
	return out
}

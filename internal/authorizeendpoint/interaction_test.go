package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// startInteractionFlow drives the GET /authorize → 302 chain so the table
// tests can pick up a valid uid+cookies pair without re-implementing the
// happy path on every row.
type interactionStart struct {
	uid             string
	interactionCk   *http.Cookie
	requestRedirect string
	requestState    string
}

func startInteractionFlow(t *testing.T, h *testHarness) interactionStart {
	t.Helper()
	resp := doAuthorizeGET(t, h, goodAuthorizeValues())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	uid := strings.TrimPrefix(loc.Path, h.interactionPth+"/")
	if uid == "" {
		t.Fatalf("could not extract uid from %s", loc.Path)
	}
	var c *http.Cookie
	for _, cc := range resp.Cookies() {
		if cc.Name == cookie.InteractionProfile.Name {
			c = cc
			break
		}
	}
	if c == nil {
		t.Fatal("interaction cookie missing")
	}
	return interactionStart{
		uid:             uid,
		interactionCk:   c,
		requestRedirect: "https://rp.example.com/cb",
		requestState:    "state-abc",
	}
}

// installInteractionDriver replaces the harness driver with d and rebuilds
// the handler so the table tests can swap behaviour without re-creating
// every dependency.
func TestInteractionGet_ReturnsStepWithCSRF(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.interactionPth+"/"+start.uid, http.NoBody)
	r.AddCookie(start.interactionCk)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, _ := body["csrf"].(string); got == "" {
		t.Errorf("csrf missing: %v", body)
	}
	if hint, ok := body["hint"].(map[string]any); !ok || hint["prompt"] == "" {
		t.Errorf("hint missing: %v", body)
	}
	if !hasCookie(resp, cookie.CSRFProfile.Name) {
		t.Error("csrf cookie missing")
	}
}

func TestInteractionGet_404OnMissingCookie(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.interactionPth+"/"+start.uid, http.NoBody)
	// Deliberately omit the interaction cookie.
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d want 404", resp.StatusCode)
	}
}

func TestInteractionGet_404OnUnknownUID(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.interactionPth+"/unknown", http.NoBody)
	// Cookie does not seal "unknown" → mismatch → 404.
	r.AddCookie(&http.Cookie{Name: cookie.InteractionProfile.Name, Value: "garbage"})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d", resp.StatusCode)
	}
}

func TestInteractionPost_HappyPath_RedirectsWithCode(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)

	// Run GET to mint a CSRF token + cookie.
	csrfCookie, csrfToken := fetchCSRF(t, h, start)

	body := map[string]any{
		"subject_hint":   "user-1",
		"granted_scopes": []string{"openid", "profile"},
		"auth_time":      "2026-04-26T12:00:00Z",
		"amr":            []string{"pwd"},
	}
	resp := postInteraction(t, h, start, csrfCookie, csrfToken, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d body=%s", resp.StatusCode, dumpBody(resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Query().Get("code") == "" {
		t.Errorf("code missing in %s", loc.String())
	}
	if loc.Query().Get("state") != start.requestState {
		t.Errorf("state=%q", loc.Query().Get("state"))
	}
	// Session cookie must now be set.
	if !hasCookie(resp, cookie.SessionProfile.Name) {
		t.Errorf("session cookie missing: %v", resp.Cookies())
	}
}

func TestInteractionPost_AbortRedirectsAccessDenied(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)
	csrfCookie, csrfToken := fetchCSRF(t, h, start)
	body := map[string]any{
		"subject_hint": "user-1",
		"aborted":      true,
	}
	resp := postInteraction(t, h, start, csrfCookie, csrfToken, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Errorf("error=%q", loc.Query().Get("error"))
	}
}

func TestInteractionPost_RejectsMissingOrigin(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)
	csrfCookie, csrfToken := fetchCSRF(t, h, start)

	body, _ := json.Marshal(map[string]any{"subject_hint": "user-1"})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		h.interactionPth+"/"+start.uid, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.AddCookie(start.interactionCk)
	r.AddCookie(csrfCookie)
	// No Origin / Referer header
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want 403", resp.StatusCode)
	}
}

func TestInteractionPost_RejectsBadCSRF(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)
	csrfCookie, _ := fetchCSRF(t, h, start)
	body, _ := json.Marshal(map[string]any{"subject_hint": "user-1"})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		h.interactionPth+"/"+start.uid, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://op.example.com")
	r.Header.Set("X-CSRF-Token", "wrong-token")
	r.AddCookie(start.interactionCk)
	r.AddCookie(csrfCookie)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status=%d", resp.StatusCode)
	}
}

func TestInteractionDelete_Cancels_Returns204(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodDelete,
		h.interactionPth+"/"+start.uid, http.NoBody)
	r.AddCookie(start.interactionCk)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if !hasCookie(resp, cookie.InteractionProfile.Name) {
		// Clear cookie should set the cookie to MaxAge=-1
		t.Errorf("interaction cookie clear missing")
	}
}

// fetchCSRF runs GET /interaction/{uid} to obtain a CSRF cookie+token pair
// the table tests then submit on the matching POST.
func fetchCSRF(t *testing.T, h *testHarness, start interactionStart) (*http.Cookie, string) {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.interactionPth+"/"+start.uid, http.NoBody)
	r.AddCookie(start.interactionCk)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET interaction status=%d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	token, _ := body["csrf"].(string)
	if token == "" {
		t.Fatal("csrf token missing")
	}
	for _, c := range resp.Cookies() {
		if c.Name == cookie.CSRFProfile.Name {
			return c, token
		}
	}
	t.Fatal("csrf cookie missing")
	return nil, ""
}

// postInteraction POSTs the body as JSON, including the CSRF + interaction
// cookies the helpers build up.
func postInteraction(
	t *testing.T,
	h *testHarness,
	start interactionStart,
	csrfCookie *http.Cookie,
	csrfToken string,
	body map[string]any,
) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		h.interactionPth+"/"+start.uid, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://op.example.com")
	r.Header.Set("X-CSRF-Token", csrfToken)
	r.AddCookie(start.interactionCk)
	r.AddCookie(csrfCookie)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w.Result()
}

func dumpBody(resp *http.Response) string {
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return buf.String()
}

// stubAutoConsentDriver always returns a terminal Decision so the
// interaction-completion tests can drive the happy path through Verify.
type stubAutoConsentDriver struct{}

func (stubAutoConsentDriver) Offer(_ context.Context, _ interaction.Request) (interaction.Step, error) {
	return interaction.Step{Hint: interaction.Hint{Prompt: interaction.PromptConsent}}, nil
}

func (stubAutoConsentDriver) Verify(_ context.Context, _ interaction.Request, _ interaction.Result) (interaction.Decision, error) {
	return interaction.Decision{Continue: false}, nil
}

func (stubAutoConsentDriver) Cancel(_ context.Context, _ interaction.Request) error { return nil }

// TestStubAutoConsentDriver_CompilesAsDriver pins the test stub to the
// interaction.Driver contract so accidental signature drift breaks the
// build before the matrix test does.
func TestStubAutoConsentDriver_CompilesAsDriver(t *testing.T) {
	t.Parallel()
	var _ interaction.Driver = stubAutoConsentDriver{}
}

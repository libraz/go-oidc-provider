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
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// interactionStart bundles the post-redirect handle the table tests
// reuse to drive the GET / POST / DELETE phases of the orchestrator-
// backed /interaction endpoint.
type interactionStart struct {
	uid             string
	interactionCk   *http.Cookie
	requestRedirect string
	requestState    string
}

// startInteractionFlow drives GET /authorize so the test arrives at
// the redirect with a valid uid + cookie pair.
func startInteractionFlow(t *testing.T, h *testHarness) interactionStart {
	t.Helper()
	resp := doAuthorizeGET(t, h, goodAuthorizeValues())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", resp.StatusCode, readBody(t, resp))
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

// readBody reads the response body and returns its string form for
// diagnostic logging. It rewinds nothing — the caller has already
// consumed the response.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return buf.String()
}

func TestInteractionGet_RendersOrchestratorPrompt(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.interactionPth+"/"+start.uid, nil)
	req.AddCookie(start.interactionCk)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Type     string `json:"type"`
		StateRef string `json:"state_ref"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rr.Body.String())
	}
	if body.Type != testkit.SubjectPromptType {
		t.Errorf("Type=%q want %q", body.Type, testkit.SubjectPromptType)
	}
	if body.StateRef == "" {
		t.Error("StateRef must be populated")
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type=%q", rr.Header().Get("Content-Type"))
	}
}

func TestInteractionGet_404OnMissingCookie(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.interactionPth+"/"+start.uid, nil)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status=%d want 404", rr.Code)
	}
}

func TestInteractionGet_404OnUnknownUID(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.interactionPth+"/no-such-uid", nil)
	req.AddCookie(start.interactionCk)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status=%d want 404", rr.Code)
	}
}

func TestInteractionPost_HappyPath_RedirectsWithCode(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)

	getResp := doInteractionGet(t, h, start)
	defer getResp.Body.Close()
	stateRef, csrfCookie := readPromptStateRef(t, getResp)

	body := interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{testkit.SubjectFieldName: "user-1"},
	}
	rr := postSubmission(t, h, start, csrfCookie, body)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, start.requestRedirect+"?") {
		t.Errorf("Location=%q want redirect to RP", loc)
	}
	if !strings.Contains(loc, "code=") {
		t.Errorf("Location=%q must carry code", loc)
	}
}

func TestInteractionDelete_Cancels_RedirectsAccessDenied(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, h.interactionPth+"/"+start.uid, nil)
	req.AddCookie(start.interactionCk)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=access_denied") {
		t.Errorf("Location=%q want access_denied", loc)
	}
}

// doInteractionGet runs GET /interaction/{uid} so the table tests
// can pull StateRef + CSRF cookie out of the response without
// repeating the boilerplate.
func doInteractionGet(t *testing.T, h *testHarness, start interactionStart) *http.Response {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.interactionPth+"/"+start.uid, nil)
	req.AddCookie(start.interactionCk)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("interaction GET: status=%d body=%s", rr.Code, rr.Body.String())
	}
	return rr.Result()
}

// readPromptStateRef extracts the StateRef from the JSON envelope
// and the __Host-oidc_csrf cookie set on the response.
func readPromptStateRef(t *testing.T, resp *http.Response) (string, *http.Cookie) {
	t.Helper()
	var prompt struct {
		StateRef string `json:"state_ref"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prompt); err != nil {
		t.Fatalf("decode prompt: %v", err)
	}
	if prompt.StateRef == "" {
		t.Fatal("StateRef missing")
	}
	var csrfCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookie.CSRFProfile.Name {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing")
	}
	return prompt.StateRef, csrfCookie
}

// postSubmission posts a JSON FormSubmission with the matching
// CSRF cookie / header and returns the recorder so the caller can
// assert on the response.
func postSubmission(
	t *testing.T,
	h *testHarness,
	start interactionStart,
	csrfCookie *http.Cookie,
	body interaction.FormSubmission,
) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, h.interactionPth+"/"+start.uid, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://op.example.com")
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	req.AddCookie(start.interactionCk)
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

// Compile-time confirmation that AutoConsentDriver still satisfies
// the new Driver shape.
var _ = func() interaction.Driver { return testkit.AutoConsentDriver{} }

// Used to silence the unused context import after the rewrite.
var _ = context.Background

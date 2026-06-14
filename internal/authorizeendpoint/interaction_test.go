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
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
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

func TestInteractionPost_HappyPath_EmitsSessionAndConsentAudit(t *testing.T) {
	t.Parallel()

	emitter := &recordingEmitter{}
	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Audit = emitter
	})
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

	events := emitter.snapshot()
	sessionEv := findRecordedAuditEvent(events, "session.created")
	if sessionEv == nil {
		t.Fatalf("session.created not emitted; got=%v", events)
	}
	if sessionEv.ActorID != "user-1" {
		t.Errorf("session.created ActorID=%q want user-1", sessionEv.ActorID)
	}
	if sessionEv.SessionID == "" {
		t.Error("session.created SessionID is empty")
	}
	consentEv := findRecordedAuditEvent(events, "consent.granted")
	if consentEv == nil {
		t.Fatalf("consent.granted not emitted; got=%v", events)
	}
	if consentEv.ActorID != "user-1" {
		t.Errorf("consent.granted ActorID=%q want user-1", consentEv.ActorID)
	}
	if consentEv.ClientID != "client-1" {
		t.Errorf("consent.granted ClientID=%q want client-1", consentEv.ClientID)
	}
	if got := consentEv.Extras["grant_id"]; got == "" {
		t.Errorf("consent.granted extras.grant_id=%v want populated", got)
	}
}

func TestInteractionPost_TerminalReplayDoesNotIssueSecondCode(t *testing.T) {
	t.Parallel()

	emitter := &recordingEmitter{}
	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Audit = emitter
	})
	start := startInteractionFlow(t, h)

	getResp := doInteractionGet(t, h, start)
	defer getResp.Body.Close()
	stateRef, csrfCookie := readPromptStateRef(t, getResp)

	body := interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{testkit.SubjectFieldName: "user-1"},
	}
	first := postSubmission(t, h, start, csrfCookie, body)
	if first.Code != http.StatusFound {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	beforeReplayEvents := len(emitter.snapshot())

	second := postSubmission(t, h, start, csrfCookie, body)
	if second.Code == http.StatusFound {
		t.Fatalf("replayed terminal POST returned redirect/code: Location=%q", second.Header().Get("Location"))
	}
	if second.Code != http.StatusNotFound && second.Code != http.StatusGone {
		t.Fatalf("replay status=%d want 404/410 body=%s", second.Code, second.Body.String())
	}
	if after := len(emitter.snapshot()); after != beforeReplayEvents {
		t.Fatalf("replayed terminal POST emitted %d new audit events", after-beforeReplayEvents)
	}
}

// TestInteractionPost_AcceptsCSRFTokenViaFormBody covers the SSR
// fallback path in verifyCSRFToken: a request that posts a
// url-encoded body with the csrf_token field (and no X-CSRF-Token
// header) MUST clear the double-submit check. JSONDriver still
// rejects the body as malformed — that is expected — but the test
// asserts the failure happens in ParseSubmission (400
// invalid_request, "invalid interaction body"), not in the CSRF
// gate.
func TestInteractionPost_AcceptsCSRFTokenViaFormBody(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)

	getResp := doInteractionGet(t, h, start)
	defer getResp.Body.Close()
	stateRef, csrfCookie := readPromptStateRef(t, getResp)

	form := url.Values{
		"state_ref":  {stateRef},
		"csrf_token": {csrfCookie.Value},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, h.interactionPth+"/"+start.uid, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://op.example.com")
	req.AddCookie(start.interactionCk)
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Fatalf("CSRF body fallback did not clear: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(strings.ToLower(rr.Body.String()), "csrf") {
		t.Errorf("response cites csrf despite valid form-body token: body=%s", rr.Body.String())
	}
	// JSONDriver cannot parse a form-encoded body, so the request
	// terminates at ParseSubmission with 400 invalid_request — the
	// signal that the CSRF gate has been cleared.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400 (CSRF cleared, ParseSubmission rejects form body)", rr.Code)
	}
}

// TestInteractionPost_RejectsMissingCSRF confirms a request that
// neither sends X-CSRF-Token nor a csrf_token form field is rejected
// at the CSRF gate. The negative companion to
// [TestInteractionPost_AcceptsCSRFTokenViaFormBody] guards against a
// regression where the body fallback accidentally swallowed the
// missing-token branch.
func TestInteractionPost_RejectsMissingCSRF(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)

	getResp := doInteractionGet(t, h, start)
	defer getResp.Body.Close()
	_, csrfCookie := readPromptStateRef(t, getResp)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, h.interactionPth+"/"+start.uid, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://op.example.com")
	req.AddCookie(start.interactionCk)
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 (no CSRF token supplied)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "csrf token missing") {
		t.Errorf("body=%s want csrf token missing", rr.Body.String())
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

// TestInteractionPost_RotatesSessionIDAfterFreshAuthn pins the H-C1
// session-fixation defence: when a user with an existing session
// completes the login interaction (re-authentication for the same
// subject), the cookie-bound session ID rotates to a fresh value and
// the previous record is deleted from the store. Without rotation the
// pre-fixation cookie value (planted by an attacker who could read or
// observe it before the user logged in) would remain valid.
func TestInteractionPost_RotatesSessionIDAfterFreshAuthn(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	// Seed an active session for the same subject the
	// SubjectAuthenticator binds at the end of the interaction.
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        "grant-1",
		Subject:   "user-1",
		ClientID:  "client-1",
		Scope:     []string{"openid", "profile"},
		CreatedAt: h.clock.now,
		UpdatedAt: h.clock.now,
	}); err != nil {
		t.Fatalf("Save grant: %v", err)
	}
	originalSID := out.SessionID

	// Force the interaction even though a session exists by passing
	// prompt=login. The chain will run SubjectAuthenticator and bind
	// the same subject.
	v := goodAuthorizeValues()
	v.Set("prompt", "login")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	uid := strings.TrimPrefix(loc.Path, h.interactionPth+"/")
	var ic *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookie.InteractionProfile.Name {
			ic = c
			break
		}
	}
	if ic == nil {
		t.Fatal("interaction cookie missing")
	}
	start := interactionStart{
		uid:             uid,
		interactionCk:   ic,
		requestRedirect: "https://rp.example.com/cb",
		requestState:    "state-abc",
	}

	getResp := doInteractionGet(t, h, start)
	defer getResp.Body.Close()
	stateRef, csrfCookie := readPromptStateRef(t, getResp)

	body := interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{testkit.SubjectFieldName: "user-1"},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		h.interactionPth+"/"+start.uid, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://op.example.com")
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	req.AddCookie(start.interactionCk)
	req.AddCookie(csrfCookie)
	// Attach the seeded session cookie so ensureSession sees the
	// active subject and rotates instead of issuing a fresh record.
	req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("post status=%d body=%s", rr.Code, rr.Body.String())
	}

	// The terminal response MUST set a fresh session cookie: a
	// rotation, not a pass-through.
	var newSessionCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookie.SessionProfile.Name {
			newSessionCookie = c
			break
		}
	}
	if newSessionCookie == nil {
		t.Fatal("session cookie missing on terminate (rotation skipped)")
	}
	if newSessionCookie.Value == out.Cookie {
		t.Errorf("session cookie value identical pre/post auth — rotation skipped")
	}

	// Decode the new cookie and confirm the SessionID changed but the
	// ChooserGroupID stayed stable (Rotate preserves the group).
	r2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.authorizePath, http.NoBody)
	r2.AddCookie(newSessionCookie)
	c, err := r2.Cookie(cookie.SessionProfile.Name)
	if err != nil {
		t.Fatalf("read rotated cookie: %v", err)
	}
	active, err := h.sessionMgr.Resolve(context.Background(), c.Value)
	if err != nil {
		t.Fatalf("Resolve rotated cookie: %v", err)
	}
	if active.Session.ID == originalSID {
		t.Errorf("SessionID=%q want a fresh value (was %q)", active.Session.ID, originalSID)
	}
	if active.Session.ChooserGroupID != out.ChooserGroupID {
		t.Errorf("ChooserGroupID=%q want %q (rotation must preserve group)",
			active.Session.ChooserGroupID, out.ChooserGroupID)
	}
	// The original SessionID record must be deleted so the
	// pre-fixation cookie cannot be replayed.
	if _, err := h.store.Sessions().Find(context.Background(), originalSID); err == nil {
		t.Errorf("original session %q still present after rotation", originalSID)
	}
}

package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
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
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
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
	getResp := doInteractionGet(t, h, start)
	_, csrfCookie := readPromptStateRef(t, getResp)
	getResp.Body.Close()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, h.interactionPth+"/"+start.uid, nil)
	req.Header.Set("Origin", "https://op.example.com")
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	req.AddCookie(start.interactionCk)
	req.AddCookie(csrfCookie)
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

func TestInteractionDelete_OriginAndCSRFFailuresDoNotMutate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		origin string
		token  string
	}{
		{name: "foreign-origin", origin: "https://attacker.example", token: ""},
		{name: "wrong-step-token", origin: "https://op.example.com", token: "wrong"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			start := startInteractionFlow(t, h)
			getResp := doInteractionGet(t, h, start)
			_, csrfCookie := readPromptStateRef(t, getResp)
			getResp.Body.Close()

			req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, h.interactionPth+"/"+start.uid, http.NoBody)
			req.Header.Set("Origin", tc.origin)
			req.AddCookie(start.interactionCk)
			req.AddCookie(csrfCookie)
			if tc.token != "" {
				req.Header.Set("X-CSRF-Token", tc.token)
			} else if tc.origin == "https://op.example.com" {
				req.Header.Set("X-CSRF-Token", csrfCookie.Value)
			}
			rr := httptest.NewRecorder()
			h.handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status=%d want 403 body=%s", rr.Code, rr.Body.String())
			}
			if _, err := h.store.Interactions().Find(context.Background(), start.uid); err != nil {
				t.Fatalf("failed DELETE mutated interaction: %v", err)
			}
		})
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

type findFaultSessionStore struct {
	store.SessionStore
	fail atomic.Bool
	err  error
}

type completionFault struct {
	boundary string
	armed    atomic.Bool
}

func (f *completionFault) hit(boundary string) error {
	if f.boundary == boundary && f.armed.CompareAndSwap(true, false) {
		return errors.New("injected completion fault at " + boundary)
	}
	return nil
}

type faultCompletionTransactional struct {
	store.Transactional
	fault *completionFault
}

func (s faultCompletionTransactional) BeginTx(ctx context.Context) (store.Tx, error) {
	if err := s.fault.hit("begin"); err != nil {
		return nil, err
	}
	tx, err := s.Transactional.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return faultCompletionTx{Tx: tx, fault: s.fault}, nil
}

type faultCompletionTx struct {
	store.Tx
	fault *completionFault
}

func (tx faultCompletionTx) AuthorizationCodes() store.AuthorizationCodeStore {
	return faultCompletionCodeStore{
		AuthorizationCodeStore: tx.Tx.AuthorizationCodes(),
		fault:                  tx.fault,
	}
}

func (tx faultCompletionTx) Grants() store.GrantStore {
	return faultCompletionGrantStore{GrantStore: tx.Tx.Grants(), fault: tx.fault}
}

func (tx faultCompletionTx) PushedAuthRequests() store.PushedAuthRequestStore {
	return faultCompletionPARStore{
		PushedAuthRequestStore: tx.Tx.PushedAuthRequests(),
		fault:                  tx.fault,
	}
}

func (tx faultCompletionTx) Commit() error {
	if tx.fault.boundary == "commit_after_success" &&
		tx.fault.armed.CompareAndSwap(true, false) {
		if err := tx.Tx.Commit(); err != nil {
			return err
		}
		return errors.New("injected lost commit acknowledgement")
	}
	if err := tx.fault.hit("commit"); err != nil {
		return err
	}
	return tx.Tx.Commit()
}

type faultCompletionGrantStore struct {
	store.GrantStore
	fault *completionFault
}

func (s faultCompletionGrantStore) Save(ctx context.Context, grant *store.Grant) error {
	if err := s.fault.hit("grant_save"); err != nil {
		return err
	}
	return s.GrantStore.Save(ctx, grant)
}

func (s faultCompletionGrantStore) FindBySubjectClient(
	ctx context.Context,
	subject,
	clientID string,
) (*store.Grant, error) {
	if err := s.fault.hit("grant_find"); err != nil {
		return nil, err
	}
	return s.GrantStore.FindBySubjectClient(ctx, subject, clientID)
}

type faultCompletionCodeStore struct {
	store.AuthorizationCodeStore
	fault *completionFault
}

func (s faultCompletionCodeStore) Save(
	ctx context.Context,
	code *store.AuthorizationCode,
) error {
	if err := s.fault.hit("code_save"); err != nil {
		return err
	}
	return s.AuthorizationCodeStore.Save(ctx, code)
}

type faultCompletionPARStore struct {
	store.PushedAuthRequestStore
	fault *completionFault
}

func (s faultCompletionPARStore) Consume(
	ctx context.Context,
	uri string,
) (*store.PushedAuthRequest, error) {
	if err := s.fault.hit("par_consume"); err != nil {
		return nil, err
	}
	return s.PushedAuthRequestStore.Consume(ctx, uri)
}

type faultCompletionInteractionStore struct {
	store.InteractionStoreCAS
	fault *completionFault
}

func (s faultCompletionInteractionStore) CompareAndSwap(
	ctx context.Context,
	previous,
	next *store.Interaction,
) error {
	if err := s.fault.hit("interaction_claim"); err != nil {
		return err
	}
	return s.InteractionStoreCAS.CompareAndSwap(ctx, previous, next)
}

func (s faultCompletionInteractionStore) Delete(ctx context.Context, id string) error {
	if err := s.fault.hit("interaction_delete"); err != nil {
		return err
	}
	return s.InteractionStoreCAS.Delete(ctx, id)
}

func (s faultCompletionInteractionStore) DeleteIfUnchanged(
	ctx context.Context,
	previous *store.Interaction,
) error {
	if err := s.fault.hit("interaction_delete"); err != nil {
		return err
	}
	return s.InteractionStoreCAS.DeleteIfUnchanged(ctx, previous)
}

type faultCompletionSessionStore struct {
	store.SessionStore
	fault *completionFault
}

type concurrentCompletionInteractionStore struct {
	store.InteractionStoreCAS
	winnerClaimed    chan struct{}
	loserReloaded    chan struct{}
	initialReads     chan struct{}
	initialReadCount atomic.Int32
	conflictPending  atomic.Bool
}

type cancelCompletionRaceStore struct {
	store.InteractionStoreCAS
	cancelReady       chan struct{}
	completionClaimed chan struct{}
	cancelReloaded    chan struct{}
	conflictPending   atomic.Bool
}

func newCancelCompletionRaceStore(inner store.InteractionStoreCAS) *cancelCompletionRaceStore {
	return &cancelCompletionRaceStore{
		InteractionStoreCAS: inner,
		cancelReady:         make(chan struct{}),
		completionClaimed:   make(chan struct{}),
		cancelReloaded:      make(chan struct{}),
	}
}

func (s *cancelCompletionRaceStore) CompareAndSwap(
	ctx context.Context,
	previous,
	next *store.Interaction,
) error {
	state, _ := authorize.UnmarshalState(next.RawState)
	if state.Completion == nil {
		return s.InteractionStoreCAS.CompareAndSwap(ctx, previous, next)
	}
	<-s.cancelReady
	err := s.InteractionStoreCAS.CompareAndSwap(ctx, previous, next)
	if err == nil {
		close(s.completionClaimed)
		<-s.cancelReloaded
	}
	return err
}

func (s *cancelCompletionRaceStore) DeleteIfUnchanged(
	ctx context.Context,
	previous *store.Interaction,
) error {
	state, _ := authorize.UnmarshalState(previous.RawState)
	if state.Completion != nil {
		return s.InteractionStoreCAS.DeleteIfUnchanged(ctx, previous)
	}
	close(s.cancelReady)
	<-s.completionClaimed
	err := s.InteractionStoreCAS.DeleteIfUnchanged(ctx, previous)
	if errors.Is(err, store.ErrConflict) {
		s.conflictPending.Store(true)
	}
	return err
}

func (s *cancelCompletionRaceStore) Find(
	ctx context.Context,
	id string,
) (*store.Interaction, error) {
	rec, err := s.InteractionStoreCAS.Find(ctx, id)
	if s.conflictPending.CompareAndSwap(true, false) {
		close(s.cancelReloaded)
	}
	return rec, err
}

func newConcurrentCompletionInteractionStore(
	inner store.InteractionStoreCAS,
) *concurrentCompletionInteractionStore {
	return &concurrentCompletionInteractionStore{
		InteractionStoreCAS: inner,
		winnerClaimed:       make(chan struct{}),
		loserReloaded:       make(chan struct{}),
		initialReads:        make(chan struct{}),
	}
}

func (s *concurrentCompletionInteractionStore) CompareAndSwap(
	ctx context.Context,
	previous,
	next *store.Interaction,
) error {
	err := s.InteractionStoreCAS.CompareAndSwap(ctx, previous, next)
	switch {
	case err == nil:
		close(s.winnerClaimed)
		<-s.loserReloaded
	case errors.Is(err, store.ErrConflict):
		<-s.winnerClaimed
		s.conflictPending.Store(true)
	}
	return err
}

func (s *concurrentCompletionInteractionStore) Find(
	ctx context.Context,
	id string,
) (*store.Interaction, error) {
	rec, err := s.InteractionStoreCAS.Find(ctx, id)
	if n := s.initialReadCount.Add(1); n <= 2 {
		if n == 2 {
			close(s.initialReads)
		}
		<-s.initialReads
	}
	if s.conflictPending.CompareAndSwap(true, false) {
		close(s.loserReloaded)
	}
	return rec, err
}

func (s faultCompletionSessionStore) Save(ctx context.Context, session *store.Session) error {
	if err := s.fault.hit("session_save"); err != nil {
		return err
	}
	return s.SessionStore.Save(ctx, session)
}

func TestInteractionCompletion_RetriesEveryWriteBoundaryExactlyOnce(t *testing.T) {
	t.Parallel()

	for _, boundary := range []string{
		"interaction_claim",
		"begin",
		"grant_find",
		"grant_save",
		"par_consume",
		"code_save",
		"commit",
		"session_save",
		"interaction_delete",
	} {
		t.Run(boundary, func(t *testing.T) {
			t.Parallel()

			emitter := &recordingEmitter{}
			h := newHarness(t, func(d *authorizeendpoint.Deps) {
				d.Audit = emitter
			})
			start := startInteractionFlow(t, h)
			getResp := doInteractionGet(t, h, start)
			stateRef, csrfCookie := readPromptStateRef(t, getResp)
			getResp.Body.Close()

			if boundary == "par_consume" {
				const requestURI = "urn:ietf:params:oauth:request_uri:retry-boundary"
				if err := h.store.PushedAuthRequests().Save(context.Background(), &store.PushedAuthRequest{
					URI:       requestURI,
					ClientID:  "client-1",
					RawParams: []byte("client_id=client-1"),
					ExpiresAt: h.clock.now.Add(time.Minute),
					CreatedAt: h.clock.now,
				}); err != nil {
					t.Fatalf("Save PAR: %v", err)
				}
				rec, err := h.store.Interactions().Find(context.Background(), start.uid)
				if err != nil {
					t.Fatalf("Find interaction: %v", err)
				}
				state, err := authorize.UnmarshalState(rec.RawState)
				if err != nil {
					t.Fatalf("UnmarshalState: %v", err)
				}
				state.Library.PARRequestURI = requestURI
				rec.RawState, err = authorize.MarshalState(state)
				if err != nil {
					t.Fatalf("MarshalState: %v", err)
				}
				if err := h.store.Interactions().Save(context.Background(), rec); err != nil {
					t.Fatalf("update interaction PAR state: %v", err)
				}
				h.deps.PARs = h.store.PushedAuthRequests()
			}

			fault := &completionFault{boundary: boundary}
			fault.armed.Store(true)
			h.deps.Transactions = faultCompletionTransactional{
				Transactional: h.store,
				fault:         fault,
			}
			h.deps.Interactions = faultCompletionInteractionStore{
				InteractionStoreCAS: h.store.Interactions().(store.InteractionStoreCAS),
				fault:               fault,
			}
			sessionStore := faultCompletionSessionStore{
				SessionStore: h.store.Sessions(),
				fault:        fault,
			}
			sessionManager, err := sessions.NewManager(sessions.Config{
				Codec: faultStoreCodec(t, h.cookieCodec),
				Store: sessionStore,
				Clock: func() time.Time { return h.clock.now },
			})
			if err != nil {
				t.Fatalf("sessions.NewManager: %v", err)
			}
			h.deps.Sessions = sessionManager
			h.sessionMgr = sessionManager
			h.handler = authorizeendpoint.Handler(h.deps)

			submission := interaction.FormSubmission{
				StateRef: stateRef,
				Values:   map[string]string{testkit.SubjectFieldName: "user-1"},
			}
			first := postSubmission(t, h, start, csrfCookie, submission)
			if first.Code != http.StatusInternalServerError {
				t.Fatalf("fault status=%d want 500 body=%s Location=%q",
					first.Code, first.Body.String(), first.Header().Get("Location"))
			}
			if _, err := h.store.Interactions().Find(context.Background(), start.uid); err != nil {
				t.Fatalf("retry anchor lost after %s fault: %v", boundary, err)
			}

			retry := postSubmission(t, h, start, csrfCookie, submission)
			if retry.Code != http.StatusFound {
				t.Fatalf("retry status=%d body=%s", retry.Code, retry.Body.String())
			}
			location, err := url.Parse(retry.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse retry Location: %v", err)
			}
			codeID := location.Query().Get("code")
			if codeID == "" {
				t.Fatalf("retry Location has no code: %q", location.String())
			}
			code, err := h.store.AuthorizationCodes().Find(context.Background(), codeID)
			if err != nil {
				t.Fatalf("Find authorization code: %v", err)
			}
			if code.ID != codeID || code.Subject != "user-1" {
				t.Fatalf("authorization code=%+v", code)
			}
			grants, err := h.store.Grants().ListBySubject(context.Background(), "user-1")
			if err != nil {
				t.Fatalf("ListBySubject: %v", err)
			}
			if len(grants) != 1 || grants[0].ID != code.GrantID {
				t.Fatalf("grants=%v want exactly code grant %q", grants, code.GrantID)
			}
			var sessionCookie *http.Cookie
			for _, candidate := range retry.Result().Cookies() {
				if candidate.Name == cookie.SessionProfile.Name && candidate.MaxAge >= 0 {
					sessionCookie = candidate
					break
				}
			}
			if sessionCookie == nil {
				t.Fatal("retry did not return session cookie")
			}
			active, err := sessionManager.Resolve(context.Background(), sessionCookie.Value)
			if err != nil {
				t.Fatalf("Resolve retry session: %v", err)
			}
			group, err := h.store.Sessions().ListByChooserGroup(
				context.Background(),
				active.Session.ChooserGroupID,
			)
			if err != nil {
				t.Fatalf("ListByChooserGroup: %v", err)
			}
			if len(group) != 1 || group[0].ID != active.Session.ID {
				t.Fatalf("sessions=%v want exactly %q", group, active.Session.ID)
			}
			if _, err := h.store.Interactions().Find(context.Background(), start.uid); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("interaction retry anchor remains after success: %v", err)
			}
			var consentEvents, sessionEvents int
			for _, event := range emitter.snapshot() {
				switch event.Name {
				case "consent.granted":
					consentEvents++
				case "session.created":
					sessionEvents++
				}
			}
			if consentEvents != 1 || sessionEvents != 1 {
				t.Fatalf("audit after retry: consent=%d session=%d want 1/1",
					consentEvents, sessionEvents)
			}
		})
	}
}

func TestInteractionCompletion_ConcurrentTerminalPostsShareImmutableIntent(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)
	getResp := doInteractionGet(t, h, start)
	stateRef, csrfCookie := readPromptStateRef(t, getResp)
	getResp.Body.Close()

	concurrentStore := newConcurrentCompletionInteractionStore(
		h.store.Interactions().(store.InteractionStoreCAS),
	)
	h.deps.Interactions = concurrentStore
	h.handler = authorizeendpoint.Handler(h.deps)
	submission := interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{testkit.SubjectFieldName: "user-1"},
	}
	responses := make([]*httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	wg.Add(len(responses))
	for i := range responses {
		go func(index int) {
			defer wg.Done()
			responses[index] = postSubmission(t, h, start, csrfCookie, submission)
		}(i)
	}
	wg.Wait()

	var sharedCode string
	for i, rr := range responses {
		if rr.Code != http.StatusFound {
			t.Fatalf("response[%d] status=%d body=%s", i, rr.Code, rr.Body.String())
		}
		location, err := url.Parse(rr.Header().Get("Location"))
		if err != nil {
			t.Fatalf("response[%d] parse Location: %v", i, err)
		}
		codeID := location.Query().Get("code")
		if codeID == "" {
			t.Fatalf("response[%d] missing code: %q", i, location.String())
		}
		if sharedCode == "" {
			sharedCode = codeID
		} else if codeID != sharedCode {
			t.Fatalf("concurrent code IDs differ: %q vs %q", sharedCode, codeID)
		}
	}
	code, err := h.store.AuthorizationCodes().Find(context.Background(), sharedCode)
	if err != nil {
		t.Fatalf("Find shared code: %v", err)
	}
	grants, err := h.store.Grants().ListBySubject(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(grants) != 1 || grants[0].ID != code.GrantID {
		t.Fatalf("grants=%v want exactly shared code grant %q", grants, code.GrantID)
	}
	var sessionCookie *http.Cookie
	for _, candidate := range responses[0].Result().Cookies() {
		if candidate.Name == cookie.SessionProfile.Name && candidate.MaxAge >= 0 {
			sessionCookie = candidate
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("concurrent completion omitted session cookie")
	}
	active, err := h.sessionMgr.Resolve(context.Background(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("Resolve shared session: %v", err)
	}
	group, err := h.store.Sessions().ListByChooserGroup(
		context.Background(),
		active.Session.ChooserGroupID,
	)
	if err != nil {
		t.Fatalf("ListByChooserGroup: %v", err)
	}
	if len(group) != 1 || group[0].ID != active.Session.ID {
		t.Fatalf("sessions=%v want exactly %q", group, active.Session.ID)
	}
}

func TestInteractionCompletion_ExpiredRetryAnchorDoesNotMintCode(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)
	getResp := doInteractionGet(t, h, start)
	stateRef, csrfCookie := readPromptStateRef(t, getResp)
	getResp.Body.Close()

	fault := &completionFault{boundary: "code_save"}
	fault.armed.Store(true)
	h.deps.Transactions = faultCompletionTransactional{
		Transactional: h.store,
		fault:         fault,
	}
	h.handler = authorizeendpoint.Handler(h.deps)
	submission := interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{testkit.SubjectFieldName: "user-1"},
	}
	first := postSubmission(t, h, start, csrfCookie, submission)
	if first.Code != http.StatusInternalServerError {
		t.Fatalf("fault status=%d body=%s", first.Code, first.Body.String())
	}
	rec, err := h.store.Interactions().Find(context.Background(), start.uid)
	if err != nil {
		t.Fatalf("Find retry anchor: %v", err)
	}
	state, err := authorize.UnmarshalState(rec.RawState)
	if err != nil {
		t.Fatalf("UnmarshalState: %v", err)
	}
	if state.Completion == nil {
		t.Fatal("fault did not persist completion retry anchor")
	}

	h.clock.now = rec.ExpiresAt.Add(time.Second)
	retry := postSubmission(t, h, start, csrfCookie, submission)
	if retry.Code != http.StatusNotFound {
		t.Fatalf("expired retry status=%d want 404 body=%s", retry.Code, retry.Body.String())
	}
	if _, err := h.store.AuthorizationCodes().Find(
		context.Background(),
		state.Completion.CodeID,
	); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired retry minted code: %v", err)
	}
}

func TestInteractionCompletion_WinsRaceWithStaleCancel(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	start := startInteractionFlow(t, h)
	getResp := doInteractionGet(t, h, start)
	stateRef, csrfCookie := readPromptStateRef(t, getResp)
	getResp.Body.Close()

	raceStore := newCancelCompletionRaceStore(
		h.store.Interactions().(store.InteractionStoreCAS),
	)
	h.deps.Interactions = raceStore
	h.handler = authorizeendpoint.Handler(h.deps)

	deleteReq := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodDelete,
		h.interactionPth+"/"+start.uid,
		http.NoBody,
	)
	deleteReq.Header.Set("Origin", "https://op.example.com")
	deleteReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	deleteReq.AddCookie(start.interactionCk)
	deleteReq.AddCookie(csrfCookie)
	deleteResponse := httptest.NewRecorder()
	deleteDone := make(chan struct{})
	go func() {
		defer close(deleteDone)
		h.handler.ServeHTTP(deleteResponse, deleteReq)
	}()
	<-raceStore.cancelReady

	postResponse := postSubmission(t, h, start, csrfCookie, interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{testkit.SubjectFieldName: "user-1"},
	})
	<-deleteDone
	if postResponse.Code != http.StatusFound {
		t.Fatalf("completion status=%d body=%s", postResponse.Code, postResponse.Body.String())
	}
	if deleteResponse.Code != http.StatusFound {
		t.Fatalf("cancel status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
	postLocation, err := url.Parse(postResponse.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse completion Location: %v", err)
	}
	deleteLocation, err := url.Parse(deleteResponse.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse cancel Location: %v", err)
	}
	postCode := postLocation.Query().Get("code")
	if postCode == "" || deleteLocation.Query().Get("code") != postCode {
		t.Fatalf("race outcomes differ: completion=%q cancel=%q",
			postLocation.String(), deleteLocation.String())
	}
	if got := deleteLocation.Query().Get("error"); got != "" {
		t.Fatalf("stale cancel emitted error=%q after completion claim", got)
	}
}

func (s *findFaultSessionStore) Find(ctx context.Context, id string) (*store.Session, error) {
	if s.fail.Load() {
		return nil, s.err
	}
	return s.SessionStore.Find(ctx, id)
}

// TestInteractionPost_RotatesSessionIDAfterFreshAuthn pins the
// session-fixation defence: when a user with an existing session
// completes the login interaction (re-authentication for the same
// subject), the cookie-bound session ID rotates to a fresh value and
// the previous record is deleted from the store. Without rotation the
// pre-fixation cookie value (planted by an attacker who could read or
// observe it before the user logged in) would remain valid.
//
// Tracks: CVE-2026-7507 (Keycloak OIDC-login session fixation → account
// takeover) — the authenticated session was not rebound across the
// privilege transition, so a pre-seeded session ID survived login. The
// structural property pinned here is that a fresh authn factor at the
// authorize / interaction boundary rotates the session ID (fresh
// cookie, old record deleted), not only at a later verification step.
func TestInteractionPost_RotatesSessionIDAfterFreshAuthn(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	// Seed an active session for the same subject the
	// SubjectAuthenticator binds at the end of the interaction.
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now.Add(-time.Hour),
	}, h.clock.now)
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

func TestInteractionPost_SessionLookupFaultFailsClosedOverHTTP(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now.Add(-time.Hour),
	}, h.clock.now)
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        "grant-session-fault",
		Subject:   "user-1",
		ClientID:  "client-1",
		Scope:     []string{"openid", "profile"},
		CreatedAt: h.clock.now,
		UpdatedAt: h.clock.now,
	}); err != nil {
		t.Fatalf("Save grant: %v", err)
	}

	faultStore := &findFaultSessionStore{
		SessionStore: h.store.Sessions(),
		err:          errors.New("injected session store failure"),
	}
	faultManager, err := sessions.NewManager(sessions.Config{
		Codec: faultStoreCodec(t, h.cookieCodec),
		Store: faultStore,
		Clock: func() time.Time { return h.clock.now },
	})
	if err != nil {
		t.Fatalf("sessions.NewManager: %v", err)
	}
	h.deps.Sessions = faultManager
	h.handler = authorizeendpoint.Handler(h.deps)

	server := httptest.NewServer(h.handler)
	t.Cleanup(server.Close)
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	values := goodAuthorizeValues()
	values.Set("prompt", "login")
	authReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		server.URL+h.authorizePath+"?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest authorize: %v", err)
	}
	authReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", authResp.StatusCode, readBody(t, authResp))
	}
	loc := mustParseLocation(t, authResp)
	start := interactionStart{
		uid:             strings.TrimPrefix(loc.Path, h.interactionPth+"/"),
		requestRedirect: "https://rp.example.com/cb",
		requestState:    "state-abc",
	}
	for _, c := range authResp.Cookies() {
		if c.Name == cookie.InteractionProfile.Name {
			start.interactionCk = c
			break
		}
	}
	if start.interactionCk == nil {
		t.Fatal("interaction cookie missing")
	}

	promptReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		server.URL+h.interactionPth+"/"+start.uid, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest interaction GET: %v", err)
	}
	promptReq.AddCookie(start.interactionCk)
	promptResp, err := client.Do(promptReq)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	if promptResp.StatusCode != http.StatusOK {
		defer promptResp.Body.Close()
		t.Fatalf("interaction status=%d body=%s", promptResp.StatusCode, readBody(t, promptResp))
	}
	stateRef, csrfCookie := readPromptStateRef(t, promptResp)
	promptResp.Body.Close()

	faultStore.fail.Store(true)
	raw, err := json.Marshal(interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{testkit.SubjectFieldName: "user-1"},
	})
	if err != nil {
		t.Fatalf("marshal submission: %v", err)
	}
	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		server.URL+h.interactionPth+"/"+start.uid, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest interaction POST: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", "https://op.example.com")
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postReq.AddCookie(start.interactionCk)
	postReq.AddCookie(csrfCookie)
	postReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("POST interaction: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusFound {
		t.Fatalf("post status=%d body=%s", postResp.StatusCode, readBody(t, postResp))
	}
	errorLocation, err := url.Parse(postResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse error Location: %v", err)
	}
	if got := errorLocation.Query().Get("error"); got != "server_error" {
		t.Errorf("error=%q want server_error", got)
	}
	for _, c := range postResp.Cookies() {
		if c.Name == cookie.SessionProfile.Name && c.MaxAge >= 0 {
			t.Errorf("session cookie issued after lookup fault: %+v", c)
		}
	}

	if _, err := h.store.Sessions().Find(context.Background(), out.SessionID); err != nil {
		t.Fatalf("original session no longer available: %v", err)
	}
	group, err := h.store.Sessions().ListByChooserGroup(context.Background(), out.ChooserGroupID)
	if err != nil {
		t.Fatalf("ListByChooserGroup: %v", err)
	}
	if len(group) != 1 || group[0].ID != out.SessionID {
		t.Fatalf("sessions after lookup fault=%v want only original %q", group, out.SessionID)
	}
}

func faultStoreCodec(t *testing.T, codec *cookie.Codec) *sessions.Codec {
	t.Helper()
	sessionCodec, err := sessions.NewCodec(codec)
	if err != nil {
		t.Fatalf("sessions.NewCodec: %v", err)
	}
	return sessionCodec
}

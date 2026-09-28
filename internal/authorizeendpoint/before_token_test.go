package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// deviceTrustInteraction is a two-screen [op.TriggerBeforeToken]
// interaction: Begin asks for the device, the first Continue asks for
// confirmation, and the second Continue completes.
type deviceTrustInteraction struct{ continued atomic.Int32 }

func (*deviceTrustInteraction) Name() string                   { return "myorg.device.trust" }
func (*deviceTrustInteraction) Trigger() op.InteractionTrigger { return op.TriggerBeforeToken }

func (*deviceTrustInteraction) Begin(context.Context, op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{Type: "myorg.device.pick"}}, nil
}

func (d *deviceTrustInteraction) Continue(context.Context, op.ContinueInput) (interaction.Step, error) {
	if d.continued.Add(1) == 1 {
		return interaction.Step{Prompt: &interaction.Prompt{Type: "myorg.device.confirm"}}, nil
	}
	return interaction.Step{Result: &interaction.Result{}}, nil
}

// consentScreenInteraction stands in for the built-in consent step: it
// registers under the reserved name and always prompts, so any chain
// that reaches it surfaces a "consent.scope" prompt.
type consentScreenInteraction struct{}

func (consentScreenInteraction) Name() string                   { return authn.BuiltinConsentName }
func (consentScreenInteraction) Trigger() op.InteractionTrigger { return op.TriggerAfterAuthn }

func (consentScreenInteraction) Begin(context.Context, op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{Type: "consent.scope"}}, nil
}

func (consentScreenInteraction) Continue(context.Context, op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{Result: &interaction.Result{Scope: []string{"openid", "profile"}}}, nil
}

// withBeforeTokenOrchestrator installs a chain carrying a consent screen
// and a device-trust interaction.
func withBeforeTokenOrchestrator(t *testing.T) func(*authorizeendpoint.Deps) {
	t.Helper()
	signer, err := authn.NewStateRefSigner(bytes.Repeat([]byte{0xCD}, 32))
	if err != nil {
		t.Fatalf("authn.NewStateRefSigner: %v", err)
	}
	orch, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{testkit.SubjectAuthenticator{}},
		Interactions:   []op.Interaction{consentScreenInteraction{}, &deviceTrustInteraction{}},
		StateRefSigner: signer,
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}
	return func(d *authorizeendpoint.Deps) { d.Authn = orch }
}

// newBeforeTokenHarness is [newHarness] with the device-trust chain
// installed, plus a live session for user-1 and a grant that already
// covers the canonical request's scope — the state in which /authorize
// would otherwise mint a code silently.
func newBeforeTokenHarness(t *testing.T) (*testHarness, *http.Cookie) {
	t.Helper()
	h := newHarness(t, withBeforeTokenOrchestrator(t))
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now.Add(-time.Minute),
	}, h.clock.now)
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        "grant-1",
		Subject:   "user-1",
		ClientID:  "client-1",
		Scope:     []string{"openid", "profile", "email"},
		CreatedAt: h.clock.now,
		UpdatedAt: h.clock.now,
	}); err != nil {
		t.Fatalf("Save grant: %v", err)
	}
	return h, &http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie}
}

func TestAuthorize_BeforeTokenInteractionGatesCachedGrantReuse(t *testing.T) {
	t.Parallel()

	h, sessionCk := newBeforeTokenHarness(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+goodAuthorizeValues().Encode(), http.NoBody)
	r.AddCookie(sessionCk)
	code := driveBeforeTokenCeremony(t, h, sessionCk, r)
	if code.Subject != "user-1" || code.GrantID != "grant-1" {
		t.Errorf("code subject=%q grant=%q; want the session subject on the cached grant", code.Subject, code.GrantID)
	}
}

// The first-party auto-grant takes the same route as the cached grant:
// the device-trust prompt appears, the consent screen does not, and the
// completion writes the grant the silent mint would have written.
func TestAuthorize_BeforeTokenInteractionGatesFirstPartyAutoGrant(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t, withBeforeTokenOrchestrator(t))
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
		AMR:      []string{"pwd"},
		ACR:      "urn:test:acr:loa1",
	}, h.clock.now)
	sessionCk := &http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+goodAuthorizeValues().Encode(), http.NoBody)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(sessionCk)
	code := driveBeforeTokenCeremony(t, h.testHarness, sessionCk, r)

	if code.Subject != "user-fp" || code.GrantID == "" {
		t.Fatalf("code subject=%q grant=%q; want the session subject on a persisted grant", code.Subject, code.GrantID)
	}
	g, err := h.store.Grants().Find(context.Background(), code.GrantID)
	if err != nil {
		t.Fatalf("Find grant: %v", err)
	}
	if g.Subject != "user-fp" || g.ClientID != "client-1" || !slices.Contains(g.Scope, "openid") || !slices.Contains(g.Scope, "profile") {
		t.Errorf("grant=%+v; want user-fp/client-1 covering openid profile", g)
	}
	if g.ACR != "urn:test:acr:loa1" {
		t.Errorf("Grant.ACR=%q want urn:test:acr:loa1 (copied from session)", g.ACR)
	}
	events := h.emitter.snapshot()
	if findRecordedAuditEvent(events, string(op.AuditConsentGrantedFirstParty)) == nil {
		t.Errorf("no first-party auto-grant audit event in %+v", events)
	}
	if findRecordedAuditEvent(events, string(op.AuditConsentGranted)) != nil {
		t.Errorf("a consent.granted event was emitted for an auto-granted chain: %+v", events)
	}
}

// driveBeforeTokenCeremony sends the /authorize request r, asserts it
// is redirected to an interaction rather than answered with a code,
// answers the device-trust screens (and only those), and returns the
// code the final submission issues.
func driveBeforeTokenCeremony(t *testing.T, h *testHarness, sessionCk *http.Cookie, r *http.Request) *store.AuthorizationCode {
	t.Helper()
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	loc := mustParseLocation(t, resp)
	if loc.Query().Get("code") != "" || !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("Location=%s; want an interaction redirect, not a silent code", loc)
	}
	start := interactionStart{
		uid:             strings.TrimPrefix(loc.Path, h.interactionPth+"/"),
		interactionCk:   findCookie(resp.Cookies(), cookie.InteractionProfile.Name),
		requestRedirect: "https://rp.example.com/cb",
	}
	if start.interactionCk == nil {
		t.Fatal("interaction cookie missing")
	}

	get := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.interactionPth+"/"+start.uid, nil)
	get.AddCookie(start.interactionCk)
	get.AddCookie(sessionCk)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, get)
	stateRef, csrfCk := expectPrompt(t, rr, "myorg.device.pick", nil)

	rr = postWithSession(t, h, start, sessionCk, csrfCk, stateRef)
	stateRef, csrfCk = expectPrompt(t, rr, "myorg.device.confirm", csrfCk)

	rr = postWithSession(t, h, start, sessionCk, csrfCk, stateRef)
	if rr.Code != http.StatusFound {
		t.Fatalf("final submission: status=%d body=%s", rr.Code, rr.Body.String())
	}
	final := mustParseLocation(t, rr.Result())
	codeID := final.Query().Get("code")
	if codeID == "" || !strings.HasPrefix(final.String(), start.requestRedirect+"?") {
		t.Fatalf("Location=%s; want the RP redirect with a code", final)
	}
	code, err := h.store.AuthorizationCodes().Find(context.Background(), codeID)
	if err != nil {
		t.Fatalf("Find code: %v", err)
	}
	return code
}

func TestAuthorize_BeforeTokenInteractionPromptNoneIsInteractionRequired(t *testing.T) {
	t.Parallel()

	h, sessionCk := newBeforeTokenHarness(t)
	v := goodAuthorizeValues()
	v.Set("prompt", "none")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.AddCookie(sessionCk)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	loc := mustParseLocation(t, resp)
	if loc.Query().Get("code") != "" {
		t.Fatalf("Location=%s; prompt=none must not mint past a BeforeToken interaction", loc)
	}
	if got := loc.Query().Get("error"); got != "interaction_required" {
		t.Errorf("error=%q want interaction_required", got)
	}
}

// expectPrompt asserts rr carries a prompt of type want and returns its
// StateRef with the CSRF cookie to submit against it; a response that
// sets no fresh cookie keeps prev.
func expectPrompt(t *testing.T, rr *httptest.ResponseRecorder, want string, prev *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("want prompt %q: status=%d body=%s", want, rr.Code, rr.Body.String())
	}
	var prompt struct {
		Type     string `json:"type"`
		StateRef string `json:"state_ref"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &prompt); err != nil {
		t.Fatalf("decode prompt: %v body=%s", err, rr.Body.String())
	}
	if prompt.Type != want || prompt.StateRef == "" {
		t.Fatalf("prompt type=%q state_ref=%q; want %q", prompt.Type, prompt.StateRef, want)
	}
	csrfCk := findCookie(rr.Result().Cookies(), cookie.CSRFProfile.Name)
	if csrfCk == nil {
		csrfCk = prev
	}
	if csrfCk == nil {
		t.Fatal("csrf cookie missing")
	}
	return prompt.StateRef, csrfCk
}

// postWithSession is [postSubmission] for a ceremony served from the
// browser session: the completing request carries the session cookie
// the terminal gate reads the authentication from.
func postWithSession(
	t *testing.T,
	h *testHarness,
	start interactionStart,
	sessionCk, csrfCk *http.Cookie,
	stateRef string,
) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(interaction.FormSubmission{StateRef: stateRef})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, h.interactionPth+"/"+start.uid, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://op.example.com")
	req.Header.Set("X-CSRF-Token", csrfCk.Value)
	req.AddCookie(start.interactionCk)
	req.AddCookie(csrfCk)
	req.AddCookie(sessionCk)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

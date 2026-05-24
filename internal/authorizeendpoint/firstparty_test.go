package authorizeendpoint_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authorizationdetails"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// recordingEmitter captures every audit.Event emitted during a test
// run. It is concurrency-safe so tests that drive multiple authorize
// requests in parallel can still inspect the recorded list.
type recordingEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingEmitter) Emit(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingEmitter) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

// firstPartyHarness extends testHarness with the inputs the first-party
// skip test rows need: the configured FirstPartyClients map and the
// recording emitter that captures consent.granted.first_party events.
type firstPartyHarness struct {
	*testHarness
	emitter *recordingEmitter
}

// newFirstPartyHarness builds an authorize handler whose Deps mark
// "client-1" as first party AND wire a recording audit emitter so test
// rows can assert on the emitted events.
func newFirstPartyHarness(t *testing.T, customise ...func(*authorizeendpoint.Deps)) *firstPartyHarness {
	t.Helper()
	clock := &fakeClock{now: fixedNow()}
	st := inmem.New(inmem.WithClock(clock))
	if err := st.RegisterClient(context.Background(), &store.Client{
		ID:                      "client-1",
		RedirectURIs:            []string{"https://rp.example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Source:                  store.ClientSourceStatic,
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	cookieKey := make([]byte, 32)
	for i := range cookieKey {
		cookieKey[i] = byte(i + 1)
	}
	cookieCodec, err := cookie.NewCodec(cookieKey)
	if err != nil {
		t.Fatalf("cookie.NewCodec: %v", err)
	}
	sessCodec, err := sessions.NewCodec(cookieCodec)
	if err != nil {
		t.Fatalf("sessions.NewCodec: %v", err)
	}
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: sessCodec,
		Store: st.Sessions(),
		Clock: clock.Now,
	})
	if err != nil {
		t.Fatalf("sessions.NewManager: %v", err)
	}
	csrfKey := make([]byte, 32)
	for i := range csrfKey {
		csrfKey[i] = byte(i + 100)
	}
	signer, err := csrf.NewSigner(csrfKey)
	if err != nil {
		t.Fatalf("csrf.NewSigner: %v", err)
	}
	allow, err := csrf.NewAllowlist([]string{"https://op.example.com"})
	if err != nil {
		t.Fatalf("csrf.NewAllowlist: %v", err)
	}

	emitter := &recordingEmitter{}
	orch := buildTestOrchestrator(t)
	deps := authorizeendpoint.Deps{
		Clients:           st.Clients(),
		Codes:             st.AuthorizationCodes(),
		Grants:            st.Grants(),
		Interactions:      st.Interactions(),
		Sessions:          mgr,
		CookieCodec:       cookieCodec,
		CSRF:              signer,
		Origins:           allow,
		Driver:            interaction.JSONDriver{},
		Authn:             orch,
		AuthorizePath:     "/oidc/auth",
		InteractionPath:   "/oidc/interaction",
		Clock:             clock,
		FirstPartyClients: map[string]struct{}{"client-1": {}},
		Audit:             emitter,
	}
	for _, c := range customise {
		if c != nil {
			c(&deps)
		}
	}

	return &firstPartyHarness{
		testHarness: &testHarness{
			handler:        authorizeendpoint.Handler(deps),
			store:          st,
			cookieCodec:    cookieCodec,
			sessionMgr:     mgr,
			csrfSigner:     signer,
			driver:         interaction.JSONDriver{},
			orchestrator:   orch,
			clock:          clock,
			authorizePath:  deps.AuthorizePath,
			interactionPth: deps.InteractionPath,
		},
		emitter: emitter,
	}
}

// TestAuthorize_FirstParty_SkipsConsentAndMintsCode is the happy path:
// a session-bound first-party client with no prior grant lands on a
// silent code redirect rather than an interaction. The grant is
// persisted, the authorization code references it, and the audit
// emitter records consent.granted.first_party.
func TestAuthorize_FirstParty_SkipsConsentAndMintsCode(t *testing.T) {
	t.Parallel()

	testAuthorizeFirstPartySkipsConsentAndMintsCode(t, "same-origin")
}

// TestAuthorize_FirstParty_SameSiteSkipsConsentWhenRedirectOriginMatches
// covers the common deployment shape where the OP and first-party RP live on
// sibling hosts under the same registrable domain, e.g. id.example.jp and
// ec.example.jp. The same-site navigation is trusted only when the browser's
// source origin matches the requested redirect_uri origin.
func TestAuthorize_FirstParty_SameSiteSkipsConsentWhenRedirectOriginMatches(t *testing.T) {
	t.Parallel()

	testAuthorizeFirstPartySkipsConsentAndMintsCode(t, "same-site")
}

func testAuthorizeFirstPartySkipsConsentAndMintsCode(t *testing.T, secFetchSite string) {
	t.Helper()
	h := newFirstPartyHarness(t)
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
		AMR:      []string{"pwd"},
		ACR:      "urn:test:acr:loa1",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+goodAuthorizeValues().Encode(), http.NoBody)
	r.Header.Set("Sec-Fetch-Site", secFetchSite)
	if secFetchSite == "same-site" {
		r.Header.Set("Referer", "https://rp.example.com/shop")
	}
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("code missing from %s", loc.String())
	}
	if loc.Host != "rp.example.com" {
		t.Fatalf("redirect host=%q want rp.example.com (skip should not detour to /interaction)", loc.Host)
	}
	if strings.HasPrefix(loc.Path, h.interactionPth) {
		t.Fatalf("Location=%s; first-party skip should bypass interaction", loc.String())
	}

	rec, err := h.store.AuthorizationCodes().Find(context.Background(), code)
	if err != nil {
		t.Fatalf("Find code: %v", err)
	}
	if rec.GrantID == "" {
		t.Fatalf("authorization code carries empty GrantID: %+v", rec)
	}
	if rec.Subject != "user-fp" {
		t.Errorf("Subject=%q want user-fp (the active session subject)", rec.Subject)
	}

	g, err := h.store.Grants().Find(context.Background(), rec.GrantID)
	if err != nil {
		t.Fatalf("Find grant: %v", err)
	}
	if g.ClientID != "client-1" {
		t.Errorf("Grant.ClientID=%q want client-1", g.ClientID)
	}
	wantScope := map[string]bool{"openid": true, "profile": true}
	gotScope := map[string]bool{}
	for _, s := range g.Scope {
		gotScope[s] = true
	}
	for s := range wantScope {
		if !gotScope[s] {
			t.Errorf("Grant.Scope=%v missing %q", g.Scope, s)
		}
	}
	if g.ACR != "urn:test:acr:loa1" {
		t.Errorf("Grant.ACR=%q want urn:test:acr:loa1 (copied from session)", g.ACR)
	}
	if len(g.AMR) == 0 || g.AMR[0] != "pwd" {
		t.Errorf("Grant.AMR=%v want [pwd] (copied from session)", g.AMR)
	}

	events := h.emitter.snapshot()
	var first *audit.Event
	for i := range events {
		if events[i].Name == "consent.granted.first_party" {
			first = &events[i]
			break
		}
	}
	if first == nil {
		t.Fatalf("audit emitter did not record consent.granted.first_party; got %d events", len(events))
	}
	if first.ClientID != "client-1" {
		t.Errorf("audit ClientID=%q want client-1", first.ClientID)
	}
	if first.ActorID != "user-fp" {
		t.Errorf("audit ActorID=%q want user-fp", first.ActorID)
	}
	if first.Extras["grant_id"] != rec.GrantID {
		t.Errorf("audit grant_id=%v want %q", first.Extras["grant_id"], rec.GrantID)
	}
}

func testAuthorizeFirstPartyFallsThroughToInteraction(t *testing.T, secFetchSite string) {
	t.Helper()
	h := newFirstPartyHarness(t)
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+goodAuthorizeValues().Encode(), http.NoBody)
	r.Header.Set("Sec-Fetch-Site", secFetchSite)
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("Location=%s want interaction redirect", loc.String())
	}
	for _, ev := range h.emitter.snapshot() {
		if ev.Name == "consent.granted.first_party" {
			t.Fatalf("first-party audit fired for %s request: %+v", secFetchSite, ev)
		}
	}
}

// TestAuthorize_FirstParty_PromptConsentSuppressesSkip pins the
// override: when the RP explicitly asks for prompt=consent, the
// first-party flag does NOT silently auto-grant. The dispatcher must
// drive the consent prompt instead.
func TestAuthorize_FirstParty_PromptConsentSuppressesSkip(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t)
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	v := goodAuthorizeValues()
	v.Set("prompt", "consent")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("Location=%s want interaction redirect (prompt=consent overrides first-party skip)", loc.String())
	}

	for _, ev := range h.emitter.snapshot() {
		if ev.Name == "consent.granted.first_party" {
			t.Fatalf("first-party audit fired despite prompt=consent override: %+v", ev)
		}
	}
}

// TestAuthorize_FirstParty_AuthorizationDetailsSuppressesSkip pins that a
// first-party, same-origin request carrying RFC 9396 authorization_details
// does NOT silently auto-grant: rich, consent-bearing authorizations always
// get an explicit consent ceremony. Without the len(req.AuthorizationDetails)
// guard in firstPartyShouldSkipConsent the dispatcher would mint a code and
// grant the payment authorization without the user ever seeing it.
func TestAuthorize_FirstParty_AuthorizationDetailsSuppressesSkip(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t, func(d *authorizeendpoint.Deps) {
		d.AuthorizationDetailTypes = map[string]authorizationdetails.Validator{
			"payment_initiation": func(context.Context, map[string]any, *store.Client) error { return nil },
		}
	})
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	v := goodAuthorizeValues()
	v.Set("authorization_details", `[{"type":"payment_initiation","amount":"100"}]`)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if loc.Query().Get("code") != "" {
		t.Fatalf("Location=%s; RAR request must not silent-mint a code", loc.String())
	}
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("Location=%s want interaction redirect (RAR suppresses first-party skip)", loc.String())
	}
	for _, ev := range h.emitter.snapshot() {
		if ev.Name == "consent.granted.first_party" {
			t.Fatalf("first-party auto-grant fired for a RAR request: %+v", ev)
		}
	}
}

// TestAuthorize_NewAuthorizationDetailsForcesConsent pins that a returning
// user whose existing grant already covers the requested scope, but who now
// presents a NEW authorization_details element, is NOT silent-minted: the
// dispatcher routes to an interaction so consent can capture the new rich
// authorization. This exercises the authorizationDetailsCovered gate inside
// buildHintState at the full-dispatch level (a non-first-party client, so
// the first-party skip path is not involved).
func TestAuthorize_NewAuthorizationDetailsForcesConsent(t *testing.T) {
	t.Parallel()

	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.AuthorizationDetailTypes = map[string]authorizationdetails.Validator{
			"payment_initiation": func(context.Context, map[string]any, *store.Client) error { return nil },
		}
	})
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-rar",
		AuthTime: h.clock.now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Seed a grant that already covers the requested scope but carries no
	// authorization_details, so only the new RAR element should force a prompt.
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        "g-existing",
		Subject:   "user-rar",
		ClientID:  "client-1",
		Scope:     []string{"openid", "profile"},
		CreatedAt: h.clock.now.Add(-time.Hour),
		UpdatedAt: h.clock.now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Save grant: %v", err)
	}

	v := goodAuthorizeValues()
	v.Set("authorization_details", `[{"type":"payment_initiation","amount":"100"}]`)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if loc.Query().Get("code") != "" {
		t.Fatalf("Location=%s; a new authorization_details element must not silent-mint", loc.String())
	}
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("Location=%s want interaction redirect (new RAR is not covered by the grant)", loc.String())
	}
}

// TestAuthorize_FirstParty_NoSessionFallsThroughToLogin pins that the
// first-party flag does not invent a subject. With no session cookie
// the dispatcher MUST still redirect to /interaction so the user
// authenticates. Auto-consent requires a known subject.
func TestAuthorize_FirstParty_NoSessionFallsThroughToLogin(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t)
	resp := doAuthorizeGET(t, h.testHarness, goodAuthorizeValues())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("Location=%s want interaction redirect (no session = login first)", loc.String())
	}

	for _, ev := range h.emitter.snapshot() {
		if ev.Name == "consent.granted.first_party" {
			t.Fatalf("first-party audit fired with no session: %+v", ev)
		}
	}
}

// TestAuthorize_FirstParty_PromptNoneSilentMint pins the prompt=none
// branch: with a session-bound first-party client and no prior grant,
// prompt=none normally surfaces consent_required. The skip path
// upgrades that to a silent code mint because auto-consent applies.
func TestAuthorize_FirstParty_PromptNoneSilentMint(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t)
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	v := goodAuthorizeValues()
	v.Set("prompt", "none")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if got := loc.Query().Get("error"); got != "" {
		t.Fatalf("error=%q; first-party skip should turn prompt=none into a silent mint", got)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("code missing from %s", loc.String())
	}
}

// TestAuthorize_FirstParty_NotInSetGoesThroughInteraction pins the
// negative side of the lookup: a client_id that is NOT in the
// FirstPartyClients map is unaffected by the skip path even when the
// dispatcher would otherwise prompt for consent.
func TestAuthorize_FirstParty_NotInSetGoesThroughInteraction(t *testing.T) {
	t.Parallel()

	h := newHarness(t) // baseline harness — empty FirstPartyClients
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+goodAuthorizeValues().Encode(), http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("Location=%s; non-first-party clients must still see consent prompt", loc.String())
	}
}

// TestAuthorize_FirstParty_CrossSiteFetchMetadataSuppressesSkip pins the
// CSRF boundary around first-party auto-consent. A cross-site top-level
// navigation to /authorize is a normal OAuth entry point, but it must not
// silently mint a code when consent would otherwise be the only user
// interaction gate.
func TestAuthorize_FirstParty_CrossSiteFetchMetadataSuppressesSkip(t *testing.T) {
	t.Parallel()

	testAuthorizeFirstPartyFallsThroughToInteraction(t, "cross-site")
}

func TestAuthorize_FirstParty_SameSiteDifferentOriginSuppressesSkip(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t)
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+goodAuthorizeValues().Encode(), http.NoBody)
	r.Header.Set("Sec-Fetch-Site", "same-site")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("Referer", "https://marketing.example.com/promo")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("Location=%s want interaction redirect", loc.String())
	}
	for _, ev := range h.emitter.snapshot() {
		if ev.Name == "consent.granted.first_party" {
			t.Fatalf("first-party audit fired for same-site foreign origin: %+v", ev)
		}
	}
}

// TestAuthorize_FirstParty_OfflineAccessSuppressesSkip keeps long-lived
// credentials behind an explicit consent ceremony even for first-party
// clients.
func TestAuthorize_FirstParty_OfflineAccessSuppressesSkip(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t)
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	v := goodAuthorizeValues()
	v.Set("scope", "openid profile offline_access")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("Location=%s want interaction redirect (offline_access must not auto-grant)", loc.String())
	}
	for _, ev := range h.emitter.snapshot() {
		if ev.Name == "consent.granted.first_party" {
			t.Fatalf("first-party audit fired for offline_access request: %+v", ev)
		}
	}
}

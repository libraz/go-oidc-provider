package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorizationdetails"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
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
		Clients:            st.Clients(),
		Codes:              st.AuthorizationCodes(),
		Grants:             st.Grants(),
		Transactions:       st,
		Interactions:       st.Interactions(),
		Sessions:           mgr,
		CookieCodec:        cookieCodec,
		CSRF:               signer,
		InteractionOrigins: allow,
		Driver:             interaction.JSONDriver{},
		Authn:              orch,
		AuthorizePath:      "/oidc/auth",
		InteractionPath:    "/oidc/interaction",
		Clock:              clock,
		CompletionKey:      bytes.Repeat([]byte{0xE2}, 32),
		FirstPartyClients:  map[string]struct{}{"client-1": {}},
		Audit:              emitter,
	}
	for _, c := range customise {
		if c != nil {
			c(&deps)
		}
	}

	return &firstPartyHarness{
		testHarness: &testHarness{
			handler:        authorizeendpoint.Handler(deps),
			deps:           deps,
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

func TestAuthorize_FirstParty_GrantAndCodeRollbackTogether(t *testing.T) {
	t.Parallel()

	for _, boundary := range []string{"code_save", "commit"} {
		t.Run(boundary, func(t *testing.T) {
			t.Parallel()

			h := newFirstPartyHarness(t)
			session := establishFresh(t, h.sessionMgr, sessions.Login{
				Subject:  "user-fp",
				AuthTime: h.clock.now.Add(-time.Minute),
				AMR:      []string{"pwd"},
			}, h.clock.now)
			fault := &completionFault{boundary: boundary}
			fault.armed.Store(true)
			h.deps.Transactions = faultCompletionTransactional{
				Transactional: h.store,
				fault:         fault,
			}
			h.handler = authorizeendpoint.Handler(h.deps)

			request := func() *httptest.ResponseRecorder {
				req := httptest.NewRequestWithContext(
					context.Background(),
					http.MethodGet,
					h.authorizePath+"?"+goodAuthorizeValues().Encode(),
					http.NoBody,
				)
				req.Header.Set("Sec-Fetch-Site", "same-origin")
				req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: session.Cookie})
				rr := httptest.NewRecorder()
				h.handler.ServeHTTP(rr, req)
				return rr
			}
			first := request()
			if first.Code != http.StatusFound {
				t.Fatalf("fault status=%d body=%s", first.Code, first.Body.String())
			}
			if got := mustParseLocation(t, first.Result()).Query().Get("error"); got != "server_error" {
				t.Fatalf("fault error=%q want server_error", got)
			}
			if _, err := h.store.Grants().FindBySubjectClient(
				context.Background(),
				"user-fp",
				"client-1",
			); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("grant partially committed after %s: %v", boundary, err)
			}
			if findRecordedAuditEvent(h.emitter.snapshot(), "consent.granted.first_party") != nil {
				t.Fatalf("first-party consent audit emitted before %s rollback", boundary)
			}

			retry := request()
			if retry.Code != http.StatusFound {
				t.Fatalf("retry status=%d body=%s", retry.Code, retry.Body.String())
			}
			location := mustParseLocation(t, retry.Result())
			codeID := location.Query().Get("code")
			if codeID == "" {
				t.Fatalf("retry missing code: %s", location.String())
			}
			code, err := h.store.AuthorizationCodes().Find(context.Background(), codeID)
			if err != nil {
				t.Fatalf("Find retry code: %v", err)
			}
			grant, err := h.store.Grants().FindBySubjectClient(
				context.Background(),
				"user-fp",
				"client-1",
			)
			if err != nil {
				t.Fatalf("Find retry grant: %v", err)
			}
			if code.GrantID != grant.ID {
				t.Fatalf("code GrantID=%q want %q", code.GrantID, grant.ID)
			}
			if findRecordedAuditEvent(h.emitter.snapshot(), "consent.granted.first_party") == nil {
				t.Fatal("retry did not emit first-party consent audit")
			}
		})
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
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
		AMR:      []string{"pwd"},
		ACR:      "urn:test:acr:loa1",
	}, h.clock.now)

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
	// The raw session subject, not a per-client projection: the grant is
	// looked up by (Subject, ClientID) and every egress point projects
	// again, so a projected value stored here would be projected twice
	// and would never match the lookup.
	if g.Subject != "user-fp" {
		t.Errorf("Grant.Subject=%q want user-fp (the raw OP-internal session subject)", g.Subject)
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

func testAuthorizeFirstPartyFallsThroughToInteraction(t *testing.T, secFetchSite string, customise ...func(*authorizeendpoint.Deps)) {
	t.Helper()
	h := newFirstPartyHarness(t, customise...)
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	}, h.clock.now)
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

// TestAuthorize_FirstParty_UnvettedSourceSuppressesSkip pins that the
// skip is decided on the client record resolved for the request: a
// dynamic or metadata-document record under a listed first-party id
// still gets the consent prompt.
func TestAuthorize_FirstParty_UnvettedSourceSuppressesSkip(t *testing.T) {
	t.Parallel()

	for _, source := range []store.ClientSource{store.ClientSourceDynamic, store.ClientSourceMetadataDocument} {
		t.Run(string(source), func(t *testing.T) {
			t.Parallel()
			testAuthorizeFirstPartyFallsThroughToInteraction(t, "same-origin", func(d *authorizeendpoint.Deps) {
				st := inmem.New()
				if err := st.RegisterClient(context.Background(), &store.Client{
					ID:                      "client-1",
					RedirectURIs:            []string{"https://rp.example.com/cb"},
					GrantTypes:              []string{"authorization_code"},
					ResponseTypes:           []string{"code"},
					Scopes:                  []string{"openid", "profile", "email", "offline_access"},
					TokenEndpointAuthMethod: "client_secret_basic",
					Source:                  source,
				}); err != nil {
					t.Fatalf("RegisterClient: %v", err)
				}
				d.Clients = st.Clients()
			})
		})
	}
}

// TestAuthorize_FirstParty_PromptConsentSuppressesSkip pins the
// override: when the RP explicitly asks for prompt=consent, the
// first-party flag does NOT silently auto-grant. The dispatcher must
// drive the consent prompt instead.
func TestAuthorize_FirstParty_PromptConsentSuppressesSkip(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t)
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	}, h.clock.now)

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
// guard in firstPartyAutoConsentEligible the dispatcher would mint a code and
// grant the payment authorization without the user ever seeing it.
func TestAuthorize_FirstParty_AuthorizationDetailsSuppressesSkip(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t, func(d *authorizeendpoint.Deps) {
		d.ExtensionPolicy.AuthorizationDetailTypes = map[string]authorizationdetails.Validator{
			"payment_initiation": func(context.Context, map[string]any, *store.Client) error { return nil },
		}
	})
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	}, h.clock.now)

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
		d.ExtensionPolicy.AuthorizationDetailTypes = map[string]authorizationdetails.Validator{
			"payment_initiation": func(context.Context, map[string]any, *store.Client) error { return nil },
		}
	})
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-rar",
		AuthTime: h.clock.now.Add(-time.Minute),
	}, h.clock.now)
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
// authenticates, and nothing is granted at /authorize: the auto-grant
// lands at completion, for the subject the sign-in binds (see
// TestAuthorize_FirstParty_FreshLoginSkipsConsent).
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
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	}, h.clock.now)

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
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	}, h.clock.now)
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
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	}, h.clock.now)
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
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	}, h.clock.now)
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

// TestAuthorize_FirstParty_FreshLoginSkipsConsent pins the first-login
// path: with no session, the first-party client's interaction signs the
// user in and goes straight to the RP with a code. The consent screen is
// never shown, the grant belongs to the subject the sign-in bound, and
// the auto-grant is audited exactly once.
func TestAuthorize_FirstParty_FreshLoginSkipsConsent(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t, withFirstPartyConsentScreen(t, false))
	start := startFirstPartyInteraction(t, h, goodAuthorizeValues(), "same-origin", nil)
	rr := signInFirstParty(t, h, start, nil, testkit.SubjectPromptType, testkit.SubjectFieldName, "user-fresh")
	assertFirstPartyLoginSkippedConsent(t, h, rr, "user-fresh")
}

// TestAuthorize_FirstParty_PromptLoginWithSessionSkipsConsent pins the
// re-authentication branch: prompt=login over a live session still runs
// the sign-in, and the consent it would otherwise reach is auto-granted.
func TestAuthorize_FirstParty_PromptLoginWithSessionSkipsConsent(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t, withFirstPartyConsentScreen(t, false))
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	}, h.clock.now)
	sessionCk := &http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie}
	v := goodAuthorizeValues()
	v.Set("prompt", interaction.PromptLogin)
	start := startFirstPartyInteraction(t, h, v, "same-origin", sessionCk)
	rr := signInFirstParty(t, h, start, sessionCk, testkit.SubjectPromptType, testkit.SubjectFieldName, "user-fp")
	assertFirstPartyLoginSkippedConsent(t, h, rr, "user-fp")
}

// TestAuthorize_FirstParty_FreshLoginOfflineAccessStillPrompts keeps
// offline_access behind an explicit consent screen on the sign-in path too.
func TestAuthorize_FirstParty_FreshLoginOfflineAccessStillPrompts(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t, withFirstPartyConsentScreen(t, false))
	v := goodAuthorizeValues()
	v.Set("scope", "openid profile offline_access")
	start := startFirstPartyInteraction(t, h, v, "same-origin", nil)
	rr := signInFirstParty(t, h, start, nil, testkit.SubjectPromptType, testkit.SubjectFieldName, "user-fresh")
	assertFirstPartyConsentPrompted(t, h, rr)
}

// TestAuthorize_FirstParty_FreshLoginCrossSiteStillPrompts pins the Fetch
// Metadata gate on the sign-in path: a cross-site navigation signs the
// user in and then shows the consent screen.
func TestAuthorize_FirstParty_FreshLoginCrossSiteStillPrompts(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t, withFirstPartyConsentScreen(t, false))
	start := startFirstPartyInteraction(t, h, goodAuthorizeValues(), "cross-site", nil)
	rr := signInFirstParty(t, h, start, nil, testkit.SubjectPromptType, testkit.SubjectFieldName, "user-fresh")
	assertFirstPartyConsentPrompted(t, h, rr)
}

// TestAuthorize_FirstParty_PromptCreateStillPrompts pins that registration
// is outside the auto-grant: the account it creates sees the consent
// screen.
func TestAuthorize_FirstParty_PromptCreateStillPrompts(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t, withFirstPartyConsentScreen(t, true))
	v := goodAuthorizeValues()
	v.Set("prompt", interaction.PromptCreate)
	start := startFirstPartyInteraction(t, h, v, "same-origin", nil)
	rr := signInFirstParty(t, h, start, nil, registerPromptType, registerFieldName, promptCreateSubject)
	assertFirstPartyConsentPrompted(t, h, rr)
}

// TestAuthorize_FirstParty_FreshLoginSelectAccountStillPrompts pins that a
// request asking for the account chooser stays outside the auto-grant
// even when, with no session to choose from, it runs a plain sign-in.
func TestAuthorize_FirstParty_FreshLoginSelectAccountStillPrompts(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t, withFirstPartyConsentScreen(t, false))
	v := goodAuthorizeValues()
	v.Set("prompt", interaction.PromptSelectAccount)
	start := startFirstPartyInteraction(t, h, v, "same-origin", nil)
	rr := signInFirstParty(t, h, start, nil, testkit.SubjectPromptType, testkit.SubjectFieldName, "user-fresh")
	assertFirstPartyConsentPrompted(t, h, rr)
}

// TestAuthorize_FirstParty_AddAccountStillPrompts pins that the chooser's
// add-account sign-in (prompt=login plus the OP-private add-account
// markers) stays outside the auto-grant: it joins another account to the
// group, and that account sees the consent screen.
func TestAuthorize_FirstParty_AddAccountStillPrompts(t *testing.T) {
	t.Parallel()

	h := newFirstPartyHarness(t, withFirstPartyConsentScreen(t, false))
	out := establishFresh(t, h.sessionMgr, sessions.Login{
		Subject:  "user-fp",
		AuthTime: h.clock.now.Add(-time.Minute),
	}, h.clock.now)
	sessionCk := &http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie}
	v := goodAuthorizeValues()
	v.Set("prompt", interaction.PromptLogin)
	v.Set("_oidc_add_account", "1")
	v.Set("_oidc_chooser_group", out.ChooserGroupID)
	start := startFirstPartyInteraction(t, h, v, "same-origin", sessionCk)
	rr := signInFirstParty(t, h, start, sessionCk, testkit.SubjectPromptType, testkit.SubjectFieldName, "user-second")
	assertFirstPartyConsentPrompted(t, h, rr)
}

// withFirstPartyConsentScreen installs a chain whose consent step always
// prompts, so a ceremony that reaches consent surfaces "consent.scope"
// instead of completing. registration adds a Registration step and admits
// prompt=create.
func withFirstPartyConsentScreen(t *testing.T, registration bool) func(*authorizeendpoint.Deps) {
	t.Helper()
	signer, err := authn.NewStateRefSigner(bytes.Repeat([]byte{0xCD}, 32))
	if err != nil {
		t.Fatalf("authn.NewStateRefSigner: %v", err)
	}
	primary := testkit.SubjectAuthenticator{}
	spec := authn.LoginFlowSpec{
		Primary: authn.LoginFlowStep{Kind: string(primary.Type()), Authenticator: primary},
	}
	if registration {
		spec.Registration = authn.LoginFlowStep{
			Kind:          "test.register",
			Authenticator: registrationEcho{clock: newMovableClock(fixedNow())},
		}
	}
	flow, err := authn.CompileLoginFlow(spec)
	if err != nil {
		t.Fatalf("authn.CompileLoginFlow: %v", err)
	}
	orch, err := authn.New(authn.Config{
		LoginFlow:      flow,
		Interactions:   []op.Interaction{consentScreenInteraction{}},
		StateRefSigner: signer,
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}
	return func(d *authorizeendpoint.Deps) {
		d.Authn = orch
		d.RequestPolicy.PromptCreate = registration
	}
}

// startFirstPartyInteraction sends /authorize with values, the given
// Sec-Fetch-Site and an optional session cookie, asserts it is redirected
// to an interaction rather than answered with a code, and returns the
// interaction handle.
func startFirstPartyInteraction(
	t *testing.T,
	h *firstPartyHarness,
	values url.Values,
	secFetchSite string,
	sessionCk *http.Cookie,
) interactionStart {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+values.Encode(), http.NoBody)
	r.Header.Set("Sec-Fetch-Site", secFetchSite)
	if sessionCk != nil {
		r.AddCookie(sessionCk)
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	loc := mustParseLocation(t, resp)
	if loc.Query().Get("code") != "" || !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("Location=%s; want an interaction redirect", loc)
	}
	interactionCk := findCookie(resp.Cookies(), cookie.InteractionProfile.Name)
	if interactionCk == nil {
		t.Fatal("interaction cookie missing")
	}
	if findRecordedAuditEvent(h.emitter.snapshot(), string(op.AuditConsentGrantedFirstParty)) != nil {
		t.Fatal("first-party auto-grant audited at /authorize, before any subject was bound")
	}
	return interactionStart{
		uid:             strings.TrimPrefix(loc.Path, h.interactionPth+"/"),
		interactionCk:   interactionCk,
		requestRedirect: "https://rp.example.com/cb",
		requestState:    "state-abc",
	}
}

// signInFirstParty opens the interaction, expects the sign-in prompt
// promptType, submits subject in field and returns the response to that
// submission: the RP redirect when the chain is done, or the next prompt.
func signInFirstParty(
	t *testing.T,
	h *firstPartyHarness,
	start interactionStart,
	sessionCk *http.Cookie,
	promptType, field, subject string,
) *httptest.ResponseRecorder {
	t.Helper()
	get := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.interactionPth+"/"+start.uid, nil)
	get.AddCookie(start.interactionCk)
	if sessionCk != nil {
		get.AddCookie(sessionCk)
	}
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, get)
	stateRef, csrfCk := expectPrompt(t, rr, promptType, nil)

	raw, err := json.Marshal(interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{field: subject},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	post := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		h.interactionPth+"/"+start.uid, bytes.NewReader(raw))
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Origin", "https://op.example.com")
	post.Header.Set("X-CSRF-Token", csrfCk.Value)
	post.AddCookie(start.interactionCk)
	post.AddCookie(csrfCk)
	if sessionCk != nil {
		post.AddCookie(sessionCk)
	}
	rr = httptest.NewRecorder()
	h.handler.ServeHTTP(rr, post)
	return rr
}

// assertFirstPartyLoginSkippedConsent checks that the sign-in submission
// went straight to the RP with a code for subject, that the code's grant
// belongs to subject and covers the request, and that the auto-grant was
// audited once and no ordinary consent grant was.
func assertFirstPartyLoginSkippedConsent(t *testing.T, h *firstPartyHarness, rr *httptest.ResponseRecorder, subject string) {
	t.Helper()
	if rr.Code != http.StatusFound {
		t.Fatalf("sign-in submission status=%d body=%s; want the RP redirect, not a consent prompt", rr.Code, rr.Body.String())
	}
	final := mustParseLocation(t, rr.Result())
	codeID := final.Query().Get("code")
	if codeID == "" || !strings.HasPrefix(final.String(), "https://rp.example.com/cb?") {
		t.Fatalf("Location=%s; want the RP redirect with a code", final)
	}
	code, err := h.store.AuthorizationCodes().Find(context.Background(), codeID)
	if err != nil {
		t.Fatalf("Find code: %v", err)
	}
	if code.Subject != subject || code.GrantID == "" {
		t.Fatalf("code subject=%q grant=%q; want %q on a persisted grant", code.Subject, code.GrantID, subject)
	}
	g, err := h.store.Grants().Find(context.Background(), code.GrantID)
	if err != nil {
		t.Fatalf("Find grant: %v", err)
	}
	if g.Subject != subject || g.ClientID != "client-1" {
		t.Errorf("grant subject=%q client=%q; want %q / client-1", g.Subject, g.ClientID, subject)
	}
	if !slices.Contains(g.Scope, "openid") || !slices.Contains(g.Scope, "profile") {
		t.Errorf("grant scope=%v; want openid profile", g.Scope)
	}

	var autoGrants []audit.Event
	for _, ev := range h.emitter.snapshot() {
		switch ev.Name {
		case string(op.AuditConsentGrantedFirstParty):
			autoGrants = append(autoGrants, ev)
		case string(op.AuditConsentGranted):
			t.Errorf("ordinary consent grant audited for an auto-granted chain: %+v", ev)
		}
	}
	if len(autoGrants) != 1 {
		t.Fatalf("first-party auto-grant audited %d times; want once", len(autoGrants))
	}
	if autoGrants[0].ActorID != subject || autoGrants[0].ClientID != "client-1" || autoGrants[0].Extras["grant_id"] != code.GrantID {
		t.Errorf("auto-grant audit=%+v; want actor %q, client-1, grant %q", autoGrants[0], subject, code.GrantID)
	}
}

// assertFirstPartyConsentPrompted checks that the sign-in submission was
// answered with the consent screen and that nothing was auto-granted.
func assertFirstPartyConsentPrompted(t *testing.T, h *firstPartyHarness, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-in submission status=%d body=%s; want the consent prompt", rr.Code, rr.Body.String())
	}
	var prompt struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &prompt); err != nil {
		t.Fatalf("decode prompt: %v body=%s", err, rr.Body.String())
	}
	if prompt.Type != "consent.scope" {
		t.Fatalf("prompt type=%q; want consent.scope", prompt.Type)
	}
	if ev := findRecordedAuditEvent(h.emitter.snapshot(), string(op.AuditConsentGrantedFirstParty)); ev != nil {
		t.Fatalf("first-party auto-grant audited: %+v", ev)
	}
}

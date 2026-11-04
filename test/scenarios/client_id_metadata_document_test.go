package scenarios_test

// Catalog: test/scenarios/catalog/client_id_metadata_document.yaml (CIMD-NNN)
// Spec:
//   - draft-ietf-oauth-client-id-metadata-document
//   - RFC 7591 §2 — Client Metadata Field Definitions
//   - OpenID Connect Core 1.0 §16.16, §16.17
//   - RFC 8414 — Authorization Server Metadata
//   - RFC 7517 — JWK / jwks_uri
//   - RFC 6749 §3.1.2 — redirect_uri matching
//
// Each test publishes the client ID metadata document from an httptest
// server and lets the OP fetch it under the dev-only private-network
// option (the document is served over http on 127.0.0.1). A fake clock
// drives cache expiry, so no row waits on wall time except the fetch
// timeout row. A rejection leaves nothing on the wire beyond a generic
// unknown-client answer; the cause is pinned through the cimd.* audit
// events instead.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	cdLoopbackCB = "http://127.0.0.1:53111/callback"
	cdWebCB      = "https://mcp.example.com/callback"
	cdResource   = "https://mcp.example.com/mcp"
	cdFetched    = "cimd.fetched"
	cdFailed     = "cimd.fetch_failed"
	cdDenied     = "cimd.client_denied"
)

// cdClock is the mutable clock the OP and its metadata-document cache run
// on; rows advance it to cross cache lifetimes exactly.
type cdClock struct {
	mu  sync.Mutex
	now time.Time
}

func newCDClock() *cdClock {
	return &cdClock{now: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *cdClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *cdClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// cdServerOpts shapes what a document server answers.
type cdServerOpts struct {
	// overrides replaces (or, for a nil value, deletes) members of the
	// default document. client_id defaults to the URL the request used.
	overrides map[string]any
	status    int
	// contentType defaults to application/json.
	contentType string
	headers     func() http.Header
	// padTo pads the default document with an unknown member to exactly
	// this many bytes.
	padTo int
	// raw replaces the whole body.
	raw []byte
	// custom takes over the handler entirely.
	custom func(w http.ResponseWriter, r *http.Request)
}

// cdServer serves metadata documents (any path) and counts requests.
type cdServer struct {
	srv  *httptest.Server
	opts cdServerOpts
	mu   sync.Mutex
	path map[string]int
	hits atomic.Int32
	// accepts counts TCP connections the listener accepted, whether or not
	// a request followed.
	accepts atomic.Int32
}

// countingListener tallies accepted connections.
type countingListener struct {
	net.Listener
	n *atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func newCDServer(t *testing.T, opts cdServerOpts) *cdServer {
	t.Helper()
	s := &cdServer{opts: opts, path: map[string]int{}}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		s.path[r.URL.Path]++
		s.mu.Unlock()
		if s.opts.custom != nil {
			s.opts.custom(w, r)
			return
		}
		s.serve(w, r)
	}))
	s.srv.Listener = &countingListener{Listener: s.srv.Listener, n: &s.accepts}
	s.srv.Start()
	t.Cleanup(s.srv.Close)
	return s
}

func (s *cdServer) serve(w http.ResponseWriter, r *http.Request) {
	body := s.opts.raw
	if body == nil {
		body = s.document("http://" + r.Host + r.RequestURI)
	}
	if s.opts.headers != nil {
		for k, vs := range s.opts.headers() {
			w.Header()[k] = vs
		}
	}
	ct := s.opts.contentType
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	status := s.opts.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// document renders the default document for id with the overrides applied.
func (s *cdServer) document(id string) []byte {
	doc := map[string]any{
		"client_id":     id,
		"client_name":   "Example MCP Client",
		"logo_uri":      "https://mcp.example.com/logo.png",
		"redirect_uris": []string{cdLoopbackCB},
	}
	for k, v := range s.opts.overrides {
		if v == nil {
			delete(doc, k)
			continue
		}
		doc[k] = v
	}
	if s.opts.padTo > 0 {
		doc["x_pad"] = ""
		base, _ := json.Marshal(doc)
		doc["x_pad"] = strings.Repeat("a", max(0, s.opts.padTo-len(base)))
	}
	out, _ := json.Marshal(doc)
	return out
}

// url returns the document URL for path.
func (s *cdServer) url(path string) string { return s.srv.URL + path }

func (s *cdServer) pathHits(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path[path]
}

// cdCfg selects the OP configuration under test.
type cdCfg struct {
	// strict drops the dev private-network option, leaving the production
	// fetch envelope (https only, no private targets).
	strict    bool
	allow     func(ctx context.Context, clientID string) bool
	resources []string
	par       bool
	extra     []op.Option
}

// cdEnv is one provider with CIMD enabled, its fake clock and audit capture.
type cdEnv struct {
	tk    *testkit.Provider
	audit *scenariokit.AuditCapture
	clock *cdClock
	jti   atomic.Int64
}

func newCDEnv(t *testing.T, cfg cdCfg) *cdEnv {
	t.Helper()
	clock := newCDClock()
	capture := scenariokit.NewAuditCapture()
	opts := []op.Option{
		op.WithClientIDMetadataDocuments(op.ClientIDMetadataDocuments{Allow: cfg.allow}),
		op.WithAuditLogger(capture.Logger()),
	}
	if !cfg.strict {
		opts = append(opts, op.WithAllowPrivateNetwork(op.OutboundClientIDMetadata))
	}
	if len(cfg.resources) > 0 {
		rs := make([]op.ProtectedResource, 0, len(cfg.resources))
		for _, r := range cfg.resources {
			rs = append(rs, op.ProtectedResource{Resource: r})
		}
		opts = append(opts, op.WithProtectedResources(rs...))
	}
	if cfg.par {
		opts = append(opts, op.WithFeature(feature.PAR))
	}
	opts = append(opts, cfg.extra...)
	tk := testkit.NewProvider(t, testkit.WithClock(clock), testkit.WithOptions(opts...))
	return &cdEnv{tk: tk, audit: capture, clock: clock}
}

// auditValue reads key from an audit event, descending into the extras group.
func auditValue(ev scenariokit.AuditEvent, key string) string {
	var walk func(attrs []slog.Attr) (string, bool)
	walk = func(attrs []slog.Attr) (string, bool) {
		for _, a := range attrs {
			if a.Key == key {
				return a.Value.String(), true
			}
			switch a.Value.Kind() {
			case slog.KindGroup:
				if v, ok := walk(a.Value.Group()); ok {
					return v, true
				}
			case slog.KindAny:
				if m, ok := a.Value.Any().(map[string]any); ok {
					if v, ok := m[key]; ok {
						return fmt.Sprint(v), true
					}
				}
			default:
			}
		}
		return "", false
	}
	v, _ := walk(ev.Attrs)
	return v
}

// eventsFor returns the named audit events recorded for clientID.
func (e *cdEnv) eventsFor(name, clientID string) []scenariokit.AuditEvent {
	var out []scenariokit.AuditEvent
	for _, ev := range e.audit.EventsByName(name) {
		if auditValue(ev, "client_id") == clientID {
			out = append(out, ev)
		}
	}
	return out
}

// cimdEvents counts every cimd.* audit event.
func (e *cdEnv) cimdEvents() int {
	return len(e.audit.EventsByName(cdFetched)) + len(e.audit.EventsByName(cdFailed)) + len(e.audit.EventsByName(cdDenied))
}

// requireFetched asserts exactly one successful fetch for clientID.
func (e *cdEnv) requireFetched(t *testing.T, clientID string) {
	t.Helper()
	if got := len(e.eventsFor(cdFetched, clientID)); got != 1 {
		t.Fatalf("cimd.fetched for %s = %d events, want 1 (failures: %v)", clientID, got, e.failureReasons(clientID))
	}
}

// failureReasons lists the reason of every cimd.fetch_failed for clientID.
func (e *cdEnv) failureReasons(clientID string) []string {
	evs := e.eventsFor(cdFailed, clientID)
	out := make([]string, 0, len(evs))
	for _, ev := range evs {
		out = append(out, auditValue(ev, "reason"))
	}
	return out
}

// requireFailure asserts exactly one cimd.fetch_failed for clientID with the
// given reason, and returns its error_code attribute.
func (e *cdEnv) requireFailure(t *testing.T, clientID, reason string) string {
	t.Helper()
	evs := e.eventsFor(cdFailed, clientID)
	if len(evs) != 1 {
		t.Fatalf("cimd.fetch_failed for %s = %d events, want 1 (fetched: %d)", clientID, len(evs), len(e.eventsFor(cdFetched, clientID)))
	}
	if got := auditValue(evs[0], "reason"); got != reason {
		t.Fatalf("cimd.fetch_failed reason = %q, want %q", got, reason)
	}
	return auditValue(evs[0], "error_code")
}

// cdFlow drives /authorize, the interaction, /par and /token for one client_id.
type cdFlow struct {
	e        *cdEnv
	client   *http.Client
	clientID string
	redirect string
}

func (e *cdEnv) newFlow(t *testing.T, clientID, redirect string) *cdFlow {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	if redirect == "" {
		redirect = cdLoopbackCB
	}
	return &cdFlow{e: e, client: e.tk.HTTPClient(jar), clientID: clientID, redirect: redirect}
}

func (f *cdFlow) do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

// authorizeQuery builds a code-flow /authorize query with S256 PKCE.
func (f *cdFlow) authorizeQuery(scope string) url.Values {
	if scope == "" {
		scope = "openid"
	}
	pkce := scenariokit.NewPKCEPair("")
	return url.Values{
		"client_id":             {f.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {f.redirect},
		"scope":                 {scope},
		"state":                 {"state-cimd"},
		"nonce":                 {"nonce-cimd"},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
	}
}

// cdProbe is the observable outcome of one /authorize request.
type cdProbe struct {
	status   int
	location *url.URL
	body     string
}

// interacted reports whether /authorize accepted the request and moved on to
// the interaction.
func (p cdProbe) interacted() bool {
	return p.status == http.StatusFound && p.location != nil && strings.HasPrefix(p.location.Path, "/oidc/interaction/")
}

func (f *cdFlow) authorize(t *testing.T, q url.Values) cdProbe {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		f.e.tk.Server.URL+"/oidc/auth?"+q.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("build /authorize: %v", err)
	}
	resp := f.do(t, req)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	loc, _ := resp.Location()
	return cdProbe{status: resp.StatusCode, location: loc, body: string(body)}
}

// requireUnknown asserts /authorize answered with the generic 400 page: no
// redirect to the redirect_uri, which an unresolved client must never get.
func (p cdProbe) requireUnknown(t *testing.T) {
	t.Helper()
	if p.status != http.StatusBadRequest || p.location != nil {
		t.Fatalf("/authorize status=%d location=%v, want 400 without a redirect", p.status, p.location)
	}
}

func (p cdProbe) requireInteraction(t *testing.T) {
	t.Helper()
	if !p.interacted() {
		t.Fatalf("/authorize status=%d location=%v body=%s, want a redirect to the interaction", p.status, p.location, p.body)
	}
}

// probe sends a plain /authorize for clientID with the default redirect.
func (e *cdEnv) probe(t *testing.T, clientID string) cdProbe {
	t.Helper()
	f := e.newFlow(t, clientID, "")
	return f.authorize(t, f.authorizeQuery(""))
}

// login submits the testkit subject and returns the consent envelope, the
// interaction URL and the current CSRF value.
func (f *cdFlow) login(t *testing.T, interactionPath string) (envelope map[string]any, interactionURL, csrf string) {
	t.Helper()
	interactionURL = f.e.tk.Server.URL + interactionPath
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, interactionURL, http.NoBody)
	if err != nil {
		t.Fatalf("build interaction GET: %v", err)
	}
	prompt := f.do(t, req)
	var step map[string]any
	err = json.NewDecoder(prompt.Body).Decode(&step)
	_ = prompt.Body.Close()
	if err != nil {
		t.Fatalf("decode interaction prompt: %v", err)
	}
	stateRef, _ := step["state_ref"].(string)
	var cookie *http.Cookie
	for _, c := range prompt.Cookies() {
		if c.Name == "__Host-oidc_csrf" {
			cookie = c
		}
	}
	if stateRef == "" || cookie == nil {
		t.Fatalf("interaction prompt missing state_ref/csrf: %v", step)
	}
	raw, err := json.Marshal(map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{testkit.SubjectFieldName: "user-cimd"},
	})
	if err != nil {
		t.Fatalf("marshal interaction body: %v", err)
	}
	post, err := http.NewRequestWithContext(context.Background(), http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("build interaction POST: %v", err)
	}
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Origin", f.e.tk.Issuer)
	post.Header.Set("X-CSRF-Token", cookie.Value)
	post.AddCookie(&http.Cookie{Name: "__Host-oidc_csrf", Value: cookie.Value})
	resp := f.do(t, post)
	defer func() { _ = resp.Body.Close() }()
	consent, envelope, err := testkit.IsConsentPrompt(resp)
	if err != nil || !consent {
		t.Fatalf("expected consent prompt (err=%v): %v", err, envelope)
	}
	csrf = cookie.Value
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-oidc_csrf" {
			csrf = c.Value
		}
	}
	return envelope, interactionURL, csrf
}

// consentClient extracts the client view from a consent prompt.
func consentClient(t *testing.T, prompt map[string]any) map[string]any {
	t.Helper()
	data, _ := prompt["data"].(map[string]any)
	client, _ := data["client"].(map[string]any)
	if client == nil {
		t.Fatalf("consent prompt carries no client view: %v", prompt)
	}
	return client
}

// approve submits consent for scope and returns the authorization code.
func (f *cdFlow) approve(t *testing.T, prompt map[string]any, interactionURL, csrf, scope string) string {
	t.Helper()
	if scope == "" {
		scope = "openid"
	}
	stateRef, _ := prompt["state_ref"].(string)
	final := testkit.PostConsentApproval(t, f.client, interactionURL, f.e.tk.Issuer, csrf, stateRef, scope)
	defer func() { _ = final.Body.Close() }()
	if final.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(final.Body)
		t.Fatalf("consent status=%d body=%s", final.StatusCode, body)
	}
	loc, err := final.Location()
	if err != nil {
		t.Fatalf("consent Location: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != f.redirect {
		t.Fatalf("callback=%s want %s", got, f.redirect)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in callback %s", loc)
	}
	return code
}

// post sends a form to an endpoint and returns the status and JSON body.
func (f *cdFlow) post(t *testing.T, path string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.e.tk.Server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build %s request: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := f.do(t, req)
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s response %q: %v", path, raw, err)
	}
	return resp.StatusCode, out
}

// assertion returns the client_assertion parameters for the keypair.
func (e *cdEnv) assertion(t *testing.T, kp *pkjwtKeypair, clientID string) url.Values {
	t.Helper()
	claims := pkjwtClaims(clientID, e.tk.Issuer, e.clock.Now())
	claims["jti"] = fmt.Sprintf("cd-%d", e.jti.Add(1))
	return url.Values{
		"client_assertion":      {signedClientAssertion(t, kp, claims)},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
	}
}

// cdRun describes one end-to-end authorization-code round trip.
type cdRun struct {
	kp       *pkjwtKeypair
	par      bool
	resource string
	redirect string
	scope    string
}

// authorizeCode drives authorize (or PAR then authorize), login and consent,
// returning the flow and the authorization code.
func (e *cdEnv) authorizeCode(t *testing.T, clientID string, r cdRun) (*cdFlow, string) {
	t.Helper()
	f := e.newFlow(t, clientID, r.redirect)
	q := f.authorizeQuery(r.scope)
	if r.resource != "" {
		q.Set("resource", r.resource)
	}
	authQ := q
	if r.par {
		form := url.Values{}
		for k, v := range q {
			form[k] = v
		}
		if r.kp != nil {
			for k, v := range e.assertion(t, r.kp, clientID) {
				form[k] = v
			}
		}
		status, body := f.post(t, "/oidc/par", form)
		requestURI, _ := body["request_uri"].(string)
		if status != http.StatusCreated || requestURI == "" {
			t.Fatalf("/par status=%d body=%v, want 201 with a request_uri", status, body)
		}
		authQ = url.Values{"client_id": {clientID}, "request_uri": {requestURI}}
	}
	probe := f.authorize(t, authQ)
	probe.requireInteraction(t)
	prompt, interactionURL, csrf := f.login(t, probe.location.Path)
	return f, f.approve(t, prompt, interactionURL, csrf, r.scope)
}

// redeem exchanges code at /token, authenticating with kp when set.
func (f *cdFlow) redeem(t *testing.T, code string, kp *pkjwtKeypair) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.clientID},
		"code":          {code},
		"redirect_uri":  {f.redirect},
		"code_verifier": {scenariokit.NewPKCEPair("").Verifier},
	}
	if kp != nil {
		for k, v := range f.e.assertion(t, kp, f.clientID) {
			form[k] = v
		}
	}
	return f.post(t, "/oidc/token", form)
}

// run drives one full round trip and returns the /token status and body.
func (e *cdEnv) run(t *testing.T, clientID string, r cdRun) (int, map[string]any) {
	t.Helper()
	f, code := e.authorizeCode(t, clientID, r)
	return f.redeem(t, code, r.kp)
}

// requireTokens asserts a successful token response and returns it.
func requireTokens(t *testing.T, status int, body map[string]any) map[string]any {
	t.Helper()
	if at, _ := body["access_token"].(string); status != http.StatusOK || at == "" {
		t.Fatalf("/token status=%d body=%v, want 200 with an access_token", status, body)
	}
	return body
}

// accessTokenAudience returns the aud claim of a JWT access token.
func accessTokenAudience(t *testing.T, body map[string]any) []string {
	t.Helper()
	at, _ := body["access_token"].(string)
	claims := scenariokit.DecodeJWSClaims(t, at)
	switch v := claims["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, a := range v {
			out = append(out, fmt.Sprint(a))
		}
		return out
	}
	return nil
}

// requireInvalidClient asserts the token endpoint's unknown-client answer.
func cdRequireInvalidClient(t *testing.T, status int, body map[string]any) {
	t.Helper()
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("/token status=%d body=%v, want 401 invalid_client", status, body)
	}
}

// newDoc starts a default document server and applies overrides built from
// the document URL (served under /client.json).
func newDoc(t *testing.T, mk func(id string) map[string]any) (*cdServer, string) {
	t.Helper()
	srv := newCDServer(t, cdServerOpts{})
	id := srv.url("/client.json")
	if mk != nil {
		srv.opts.overrides = mk(id)
	}
	return srv, id
}

// requireRefusedUnfetched asserts the URL was refused before any fetch: a
// generic unknown-client answer, no request to the server, no cimd.* audit.
func requireRefusedUnfetched(t *testing.T, e *cdEnv, srv *cdServer, id string) {
	t.Helper()
	e.probe(t, id).requireUnknown(t)
	if got := srv.hits.Load(); got != 0 {
		t.Errorf("%q: document server saw %d requests, want 0", id, got)
	}
	if got := e.cimdEvents(); got != 0 {
		t.Errorf("%q: %d cimd.* audit events, want 0 (URL-rule refusals are not audited)", id, got)
	}
}

func TestScenario_CIMD_URL_01_HTTPSchemeRejected(t *testing.T) {
	t.Parallel()
	srv, id := newDoc(t, nil)
	strict := newCDEnv(t, cdCfg{strict: true})
	requireRefusedUnfetched(t, strict, srv, id)

	// The dev option is the only thing that admits http.
	dev := newCDEnv(t, cdCfg{})
	dev.probe(t, id).requireInteraction(t)
	dev.requireFetched(t, id)
	if got := srv.hits.Load(); got != 1 {
		t.Errorf("dev option: document fetched %d times, want 1", got)
	}
}

func TestScenario_CIMD_URL_02_PathRequired(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	srv, id := newDoc(t, nil)
	for _, bad := range []string{srv.srv.URL, srv.srv.URL + "/"} {
		requireRefusedUnfetched(t, e, srv, bad)
	}
	e.probe(t, id).requireInteraction(t)
	e.requireFetched(t, id)
}

func TestScenario_CIMD_URL_03_DotSegmentsRejected(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	srv, _ := newDoc(t, nil)
	for _, path := range []string{"/a/../client.json", "/./client.json", "/a/%2e%2e/client.json", "/%2E/client.json", "/a/.."} {
		requireRefusedUnfetched(t, e, srv, srv.url(path))
	}
}

func TestScenario_CIMD_URL_04_FragmentRejected(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	srv, _ := newDoc(t, nil)
	requireRefusedUnfetched(t, e, srv, srv.url("/client.json#frag"))
}

func TestScenario_CIMD_URL_05_UserinfoRejected(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	srv, _ := newDoc(t, nil)
	host := strings.TrimPrefix(srv.srv.URL, "http://")
	for _, userinfo := range []string{"user@", "user:pass@"} {
		requireRefusedUnfetched(t, e, srv, "http://"+userinfo+host+"/client.json")
	}
}

func TestScenario_CIMD_URL_06_QueryRefusedPortAccepted(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	srv, id := newDoc(t, nil)
	for _, bad := range []string{srv.url("/client.json?id=123"), srv.url("/client.json?")} {
		requireRefusedUnfetched(t, e, srv, bad)
	}

	// The test server always listens on an explicit port; the consent
	// screen names it so two clients on one host stay distinguishable.
	f := e.newFlow(t, id, "")
	probe := f.authorize(t, f.authorizeQuery(""))
	probe.requireInteraction(t)
	prompt, _, _ := f.login(t, probe.location.Path)
	host := strings.TrimPrefix(srv.srv.URL, "http://")
	if !strings.Contains(host, ":") {
		t.Fatalf("test server URL %q carries no explicit port", srv.srv.URL)
	}
	if got := consentClient(t, prompt)["metadata_document_host"]; got != host {
		t.Errorf("metadata_document_host = %v, want %q", got, host)
	}
}

func TestScenario_CIMD_URL_07_NonURLTreatedAsRegularClientID(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	for _, id := range []string{"nonexistent-client", "mcp.example.com/client.json", "urn:example:client"} {
		e.probe(t, id).requireUnknown(t)
	}
	if got := e.cimdEvents(); got != 0 {
		t.Errorf("%d cimd.* audit events for non-URL client_ids, want 0", got)
	}
}

func TestScenario_CIMD_URL_08_LengthHostAndEncoding(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	srv, _ := newDoc(t, nil)

	// 255 bytes is the longest id that fits the persisted client_id column.
	prefix := srv.url("/")
	id255 := prefix + strings.Repeat("a", 255-len(prefix))
	if len(id255) != 255 {
		t.Fatalf("id255 length = %d", len(id255))
	}
	e.probe(t, id255).requireInteraction(t)
	e.requireFetched(t, id255)
	requireRefusedBeyondLimit := e.probe(t, id255+"a")
	requireRefusedBeyondLimit.requireUnknown(t)
	if got := len(e.eventsFor(cdFetched, id255+"a")) + len(e.eventsFor(cdFailed, id255+"a")); got != 0 {
		t.Errorf("a 256-byte client_id produced %d cimd.* events, want 0", got)
	}

	// A non-ASCII host is refused without a fetch.
	idn := "http://münchen.example/client.json"
	e.probe(t, idn).requireUnknown(t)
	if got := len(e.eventsFor(cdFetched, idn)) + len(e.eventsFor(cdFailed, idn)); got != 0 {
		t.Errorf("a non-ASCII host produced %d cimd.* events, want 0", got)
	}

	// Percent-encoding in the path is part of the identifier string.
	encoded := srv.url("/a%20b.json")
	e.probe(t, encoded).requireInteraction(t)
	e.requireFetched(t, encoded)
	if got := srv.pathHits("/a b.json"); got != 1 {
		t.Errorf("percent-encoded path fetched %d times, want 1", got)
	}
}

func TestScenario_CIMD_RES_01_RegisteredClientWinsOverCIMD(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	srv, id := newDoc(t, nil)
	e.tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      id,
		RedirectURIs:            []string{cdLoopbackCB},
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
	})
	f := e.newFlow(t, id, "")
	probe := f.authorize(t, f.authorizeQuery(""))
	probe.requireInteraction(t)
	prompt, _, _ := f.login(t, probe.location.Path)
	if got := srv.hits.Load(); got != 0 {
		t.Errorf("document fetched %d times for a registered client_id, want 0", got)
	}
	if got := e.cimdEvents(); got != 0 {
		t.Errorf("%d cimd.* audit events for a registered client_id, want 0", got)
	}
	client := consentClient(t, prompt)
	if client["metadata_document_host"] != "" || client["redirect_host"] != "" || client["redirect_loopback"] != false {
		t.Errorf("registered client projected like a document client: %v", client)
	}
	if client["name"] == "Example MCP Client" {
		t.Errorf("consent shows the document's name %v for a registered client", client["name"])
	}
}

func TestScenario_CIMD_RES_02_RedirectsForbidden(t *testing.T) {
	t.Parallel()
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			t.Parallel()
			e := newCDEnv(t, cdCfg{})
			var srv *cdServer
			srv = newCDServer(t, cdServerOpts{custom: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/final.json" {
					srv.serve(w, r)
					return
				}
				http.Redirect(w, r, "/final.json", code)
			}})
			id := srv.url("/client.json")
			srv.opts.overrides = map[string]any{"client_id": id}
			e.probe(t, id).requireUnknown(t)
			if got := srv.pathHits("/final.json"); got != 0 {
				t.Errorf("redirect target requested %d times, want 0", got)
			}
			e.requireFailure(t, id, "status")
		})
	}
}

func TestScenario_CIMD_RES_03_ContentTypeMustBeJSON(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		contentType string
		accepted    bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/oauth-client-id+json", true},
		{"text/plain", false},
		{"text/html", false},
		{"application/x-www-form-urlencoded", false},
	} {
		t.Run(tc.contentType, func(t *testing.T) {
			t.Parallel()
			e := newCDEnv(t, cdCfg{})
			srv := newCDServer(t, cdServerOpts{contentType: tc.contentType})
			id := srv.url("/client.json")
			p := e.probe(t, id)
			if tc.accepted {
				p.requireInteraction(t)
				e.requireFetched(t, id)
				return
			}
			p.requireUnknown(t)
			e.requireFailure(t, id, "content_type")
		})
	}
}

func TestScenario_CIMD_RES_04_NonOKStatusRejected(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusCreated, http.StatusNoContent, http.StatusNotFound, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()
			e := newCDEnv(t, cdCfg{})
			srv := newCDServer(t, cdServerOpts{status: status})
			id := srv.url("/client.json")
			e.probe(t, id).requireUnknown(t)
			e.requireFailure(t, id, "status")
		})
	}
}

func TestScenario_CIMD_RES_05_InvalidJSONRejected(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	for _, tc := range []struct {
		name, body, reason string
	}{
		{"truncated object", `{"client_id": "x"`, "json"},
		{"not json", `<html>`, "json"},
		{"empty body", ``, "json"},
		{"array root", `[1,2]`, "validation"},
		{"number root", `42`, "validation"},
		{"empty object", `{}`, "validation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newCDServer(t, cdServerOpts{raw: []byte(tc.body)})
			id := srv.url("/client.json")
			e.probe(t, id).requireUnknown(t)
			code := e.requireFailure(t, id, tc.reason)
			if tc.reason == "validation" && code != "invalid_client_metadata" {
				t.Errorf("error_code = %q, want invalid_client_metadata", code)
			}
		})
	}
}

func TestScenario_CIMD_RES_06_BodySizeLimitEnforced(t *testing.T) {
	t.Parallel()
	const limit = 5 * 1024

	t.Run("at the limit", func(t *testing.T) {
		t.Parallel()
		e := newCDEnv(t, cdCfg{})
		srv := newCDServer(t, cdServerOpts{padTo: limit})
		id := srv.url("/client.json")
		e.probe(t, id).requireInteraction(t)
		e.requireFetched(t, id)
	})
	t.Run("one byte over", func(t *testing.T) {
		t.Parallel()
		e := newCDEnv(t, cdCfg{})
		srv := newCDServer(t, cdServerOpts{padTo: limit + 1})
		id := srv.url("/client.json")
		e.probe(t, id).requireUnknown(t)
		e.requireFailure(t, id, "too_large")
	})
	t.Run("chunked stream without a length", func(t *testing.T) {
		t.Parallel()
		e := newCDEnv(t, cdCfg{})
		srv := newCDServer(t, cdServerOpts{custom: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			chunk := []byte(strings.Repeat(" ", 1024))
			_, _ = w.Write([]byte("{"))
			for range 16 {
				if _, err := w.Write(chunk); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
			_, _ = w.Write([]byte("}"))
		}})
		id := srv.url("/client.json")
		e.probe(t, id).requireUnknown(t)
		e.requireFailure(t, id, "too_large")
	})
}

func TestScenario_CIMD_RES_07_NetworkFailureMappedToInvalidClient(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	srv := newCDServer(t, cdServerOpts{})
	id := srv.url("/client.json")
	srv.srv.Close()

	f := e.newFlow(t, id, "")
	f.authorize(t, f.authorizeQuery("")).requireUnknown(t)
	e.requireFailure(t, id, "network")

	// The token endpoint folds the same failure into invalid_client.
	status, body := f.post(t, "/oidc/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {id}, "code": {"c"},
		"redirect_uri": {cdLoopbackCB}, "code_verifier": {scenariokit.NewPKCEPair("").Verifier},
	})
	cdRequireInvalidClient(t, status, body)
}

func TestScenario_CIMD_RES_08_CacheControlHonoured(t *testing.T) {
	t.Parallel()
	const hour = time.Hour
	for _, tc := range []struct {
		name string
		hdr  func(now time.Time) http.Header
		ttl  time.Duration
	}{
		{"no directives uses the floor", func(time.Time) http.Header { return nil }, time.Minute},
		{"max-age=0 is raised to the floor", cc("max-age=0"), time.Minute},
		{"max-age=10 is raised to the floor", cc("max-age=10"), time.Minute},
		{"max-age=300", cc("max-age=300"), 5 * time.Minute},
		{"max-age=100000 is capped at a day", cc("max-age=100000"), 24 * hour},
		{"no-store pins the floor", cc("no-store, max-age=3600"), time.Minute},
		{"no-cache pins the floor", cc("no-cache, max-age=3600"), time.Minute},
		{"private pins the floor", cc("private, max-age=3600"), time.Minute},
		{"Expires alone", func(now time.Time) http.Header {
			return http.Header{"Expires": {now.Add(10 * time.Minute).UTC().Format(http.TimeFormat)}}
		}, 10 * time.Minute},
		{"max-age wins over Expires", func(now time.Time) http.Header {
			return http.Header{
				"Cache-Control": {"max-age=120"},
				"Expires":       {now.Add(hour).UTC().Format(http.TimeFormat)},
			}
		}, 2 * time.Minute},
		{"Expires in the past uses the floor", func(now time.Time) http.Header {
			return http.Header{"Expires": {now.Add(-hour).UTC().Format(http.TimeFormat)}}
		}, time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newCDEnv(t, cdCfg{})
			srv := newCDServer(t, cdServerOpts{headers: func() http.Header { return tc.hdr(e.clock.Now()) }})
			id := srv.url("/client.json")

			e.probe(t, id).requireInteraction(t)
			e.clock.advance(tc.ttl - time.Second)
			e.probe(t, id).requireInteraction(t)
			if got := srv.hits.Load(); got != 1 {
				t.Fatalf("1s before the lifetime ends: %d fetches, want 1 (served from cache)", got)
			}
			e.clock.advance(2 * time.Second)
			e.probe(t, id).requireInteraction(t)
			if got := srv.hits.Load(); got != 2 {
				t.Fatalf("1s after the lifetime ends: %d fetches, want 2 (refetched)", got)
			}
		})
	}
}

// cc returns a header builder carrying only a Cache-Control value.
func cc(value string) func(time.Time) http.Header {
	return func(time.Time) http.Header { return http.Header{"Cache-Control": {value}} }
}

// cdAllowRecorder is an Allow hook that records its calls and can deny.
type cdAllowRecorder struct {
	mu     sync.Mutex
	calls  []string
	denied atomic.Bool
}

func (a *cdAllowRecorder) allow(_ context.Context, clientID string) bool {
	a.mu.Lock()
	a.calls = append(a.calls, clientID)
	a.mu.Unlock()
	return !a.denied.Load()
}

func (a *cdAllowRecorder) snapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

func TestScenario_CIMD_RES_09_AllowHookGatesRequest(t *testing.T) {
	t.Parallel()
	rec := &cdAllowRecorder{}
	e := newCDEnv(t, cdCfg{allow: rec.allow})
	srv, id := newDoc(t, nil)

	// The hook sees the URL on a miss and again on a cache hit.
	e.probe(t, id).requireInteraction(t)
	e.probe(t, id).requireInteraction(t)
	if got := rec.snapshot(); len(got) != 2 || got[0] != id || got[1] != id {
		t.Errorf("Allow calls = %v, want the client_id twice", got)
	}
	if got := srv.hits.Load(); got != 1 {
		t.Errorf("document fetched %d times, want 1", got)
	}

	// A refusal leaves the request before the fetch.
	rec.denied.Store(true)
	other := srv.url("/other.json")
	e.probe(t, other).requireUnknown(t)
	if got := srv.pathHits("/other.json"); got != 0 {
		t.Errorf("a denied URL was fetched %d times, want 0", got)
	}
	if got := len(e.eventsFor(cdDenied, other)); got != 1 {
		t.Errorf("cimd.client_denied events = %d, want 1", got)
	}

	// The hook only ever sees conforming URLs: a plain client_id is not its business.
	before := len(rec.snapshot())
	e.probe(t, "nonexistent-client").requireUnknown(t)
	if got := len(rec.snapshot()); got != before {
		t.Errorf("Allow called for a non-URL client_id")
	}
}

func TestScenario_CIMD_RES_10_AllowNarrowingTakesEffectOnWarmCache(t *testing.T) {
	t.Parallel()
	rec := &cdAllowRecorder{}
	e := newCDEnv(t, cdCfg{allow: rec.allow})
	srv, id := newDoc(t, nil)

	e.probe(t, id).requireInteraction(t)
	e.requireFetched(t, id)

	// The document is cached, yet narrowing the allow-list refuses the
	// client on the very next request; there is no later, per-document hook.
	rec.denied.Store(true)
	e.probe(t, id).requireUnknown(t)
	if got := srv.hits.Load(); got != 1 {
		t.Errorf("document fetched %d times, want 1 (the denial must not refetch)", got)
	}
	if got := len(e.eventsFor(cdDenied, id)); got != 1 {
		t.Errorf("cimd.client_denied events = %d, want 1", got)
	}

	rec.denied.Store(false)
	e.probe(t, id).requireInteraction(t)
}

// Tracks: CVE-2026-1180 (another OP; client-supplied URL fetched without a
// private-range check). Here the URL is the client_id itself.
func TestScenario_CIMD_RES_11_SSRFBlocksPrivateRanges(t *testing.T) {
	t.Parallel()
	srv, _ := newDoc(t, nil)
	port := srv.srv.Listener.Addr().(interface{ String() string }).String()
	port = port[strings.LastIndex(port, ":")+1:]

	// Production envelope: loopback targets are refused at dial time, for a
	// literal address and for a name that resolves to one.
	strict := newCDEnv(t, cdCfg{strict: true})
	for _, id := range []string{
		"https://127.0.0.1:" + port + "/client.json",
		"https://localhost:" + port + "/client.json",
		"https://[::1]:" + port + "/client.json",
		"https://10.0.0.1/client.json",
		"https://192.168.1.1/client.json",
		"https://169.254.169.254/latest/meta-data",
		"https://0.0.0.0:" + port + "/client.json",
	} {
		strict.probe(t, id).requireUnknown(t)
		strict.requireFailure(t, id, "network")
	}
	if got := srv.accepts.Load(); got != 0 {
		t.Errorf("document server accepted %d connections through the production envelope, want 0", got)
	}

	// Control: with the dev option the same address is dialled, so the
	// counter above is able to move.
	dialled := newCDEnv(t, cdCfg{})
	dialled.probe(t, "https://127.0.0.1:"+port+"/client.json")
	if srv.accepts.Load() == 0 {
		t.Error("the dev envelope never connected to the loopback server; the strict check above cannot fail")
	}

	// The same name is reachable only once the dev option lifts the loopback ban...
	dev := newCDEnv(t, cdCfg{})
	viaName := "http://localhost:" + port + "/client.json"
	dev.probe(t, viaName).requireInteraction(t)
	dev.requireFetched(t, viaName)

	// ...and even then the cloud metadata address stays refused.
	meta := "http://169.254.169.254/latest/meta-data"
	dev.probe(t, meta).requireUnknown(t)
	dev.requireFailure(t, meta, "network")
}

func TestScenario_CIMD_RES_12_FetchTimeoutIsFixed(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	release := make(chan struct{})
	srv := newCDServer(t, cdServerOpts{custom: func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}})
	t.Cleanup(func() { close(release) })
	id := srv.url("/client.json")

	start := time.Now()
	e.probe(t, id).requireUnknown(t)
	if elapsed := time.Since(start); elapsed < 4*time.Second || elapsed > 10*time.Second {
		t.Errorf("a stalled document was abandoned after %s, want the fixed 5s timeout", elapsed)
	}
	e.requireFailure(t, id, "network")
	if got := srv.hits.Load(); got != 1 {
		t.Errorf("stalled document requested %d times, want 1", got)
	}
}

// cdDocCase is one metadata-document validation row: code is the expected
// audit error_code, empty when the document is accepted.
type cdDocCase struct {
	name     string
	mk       func(id string) map[string]any
	code     string
	redirect string
}

const cdInvalidMetadata = "invalid_client_metadata"

// runDocCases serves each document, resolves it through /authorize and checks
// the accept / refuse verdict against the audit trail.
func runDocCases(t *testing.T, cases []cdDocCase) {
	t.Helper()
	e := newCDEnv(t, cdCfg{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, id := newDoc(t, tc.mk)
			f := e.newFlow(t, id, tc.redirect)
			p := f.authorize(t, f.authorizeQuery(""))
			if tc.code == "" {
				e.requireFetched(t, id)
				if tc.redirect != "" {
					p.requireInteraction(t)
				}
				return
			}
			p.requireUnknown(t)
			if got := e.requireFailure(t, id, "validation"); got != tc.code {
				t.Errorf("error_code = %q, want %q", got, tc.code)
			}
		})
	}
}

func TestScenario_CIMD_META_01_ClientIDFieldMatchesURL(t *testing.T) {
	t.Parallel()
	runDocCases(t, []cdDocCase{
		{"matching", func(string) map[string]any { return nil }, "", ""},
		{"another URL", func(string) map[string]any {
			return map[string]any{"client_id": "https://other.example.com/client.json"}
		}, cdInvalidMetadata, ""},
		{"trailing slash", func(id string) map[string]any { return map[string]any{"client_id": id + "/"} }, cdInvalidMetadata, ""},
		{"case differs", func(id string) map[string]any { return map[string]any{"client_id": strings.ToUpper(id)} }, cdInvalidMetadata, ""},
		{"missing", func(string) map[string]any { return map[string]any{"client_id": nil} }, cdInvalidMetadata, ""},
		{"empty", func(string) map[string]any { return map[string]any{"client_id": ""} }, cdInvalidMetadata, ""},
		{"not a string", func(string) map[string]any { return map[string]any{"client_id": 7} }, cdInvalidMetadata, ""},
	})
}

func TestScenario_CIMD_META_02_AuthMethodLimitedToNoneAndPrivateKeyJWT(t *testing.T) {
	t.Parallel()
	kp := newPKJWTKeypair(t, "cd-meta-02")
	jwks := kp.PublicJWKSet(t)
	method := func(m string, extra map[string]any) func(string) map[string]any {
		return func(string) map[string]any {
			out := map[string]any{"token_endpoint_auth_method": m}
			for k, v := range extra {
				out[k] = v
			}
			return out
		}
	}
	runDocCases(t, []cdDocCase{
		{"none", method("none", nil), "", ""},
		{"omitted defaults to none", method("", nil), "", ""},
		{"private_key_jwt with jwks", method("private_key_jwt", map[string]any{"jwks": json.RawMessage(jwks)}), "", ""},
		{"private_key_jwt with jwks_uri", method("private_key_jwt", map[string]any{"jwks_uri": "https://mcp.example.com/jwks.json"}), "", ""},
		{"private_key_jwt without keys", method("private_key_jwt", nil), cdInvalidMetadata, ""},
		{"private_key_jwt with a private key", method("private_key_jwt", map[string]any{
			"jwks": map[string]any{"keys": []any{map[string]any{
				"kty": "EC", "crv": "P-256", "kid": "k", "d": "AQAB",
				"x": "Ic7hdc2EYvl1G6v4UzZhXxDpVPMkMfJzad8tjzD7R80", "y": "WEdXWZ-oH_wg4OQA124qdcN2Fs9iBINN-EfV0ewy6V0",
			}}},
		}), cdInvalidMetadata, ""},
		{"client_secret_basic", method("client_secret_basic", nil), cdInvalidMetadata, ""},
		{"client_secret_post", method("client_secret_post", nil), cdInvalidMetadata, ""},
		{"client_secret_jwt", method("client_secret_jwt", nil), cdInvalidMetadata, ""},
		{"tls_client_auth", method("tls_client_auth", map[string]any{"tls_client_auth_subject_dn": "CN=client"}), cdInvalidMetadata, ""},
		{"self_signed_tls_client_auth", method("self_signed_tls_client_auth", nil), cdInvalidMetadata, ""},
		{"unknown method", method("magic", nil), cdInvalidMetadata, ""},
	})
}

func TestScenario_CIMD_META_03_ClientSecretFieldRejected(t *testing.T) {
	t.Parallel()
	runDocCases(t, []cdDocCase{
		{"client_secret", func(string) map[string]any { return map[string]any{"client_secret": "s3cr3t"} }, cdInvalidMetadata, ""},
		{"client_secret_expires_at", func(string) map[string]any { return map[string]any{"client_secret_expires_at": 0} }, cdInvalidMetadata, ""},
		{"empty client_secret", func(string) map[string]any { return map[string]any{"client_secret": ""} }, cdInvalidMetadata, ""},
	})
}

func TestScenario_CIMD_META_04_URIFieldsRequireHTTPS(t *testing.T) {
	t.Parallel()
	uri := func(k, v string) func(string) map[string]any {
		return func(string) map[string]any { return map[string]any{k: v} }
	}
	runDocCases(t, []cdDocCase{
		{"https URIs", func(string) map[string]any {
			return map[string]any{
				"client_uri": "https://mcp.example.com", "logo_uri": "https://mcp.example.com/logo.png",
				"tos_uri": "https://mcp.example.com/tos", "policy_uri": "https://mcp.example.com/policy",
			}
		}, "", ""},
		{"client_uri over http", uri("client_uri", "http://mcp.example.com"), cdInvalidMetadata, ""},
		{"logo_uri over http", uri("logo_uri", "http://mcp.example.com/logo.png"), cdInvalidMetadata, ""},
		{"tos_uri over http", uri("tos_uri", "http://mcp.example.com/tos"), cdInvalidMetadata, ""},
		{"policy_uri over http", uri("policy_uri", "http://mcp.example.com/policy"), cdInvalidMetadata, ""},
		{"jwks_uri over http", func(string) map[string]any {
			return map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "http://mcp.example.com/jwks.json"} //nolint:gosec // G101: auth method name, not a credential.
		}, cdInvalidMetadata, ""},
		{"logo_uri is not a URL", uri("logo_uri", "javascript:alert(1)"), cdInvalidMetadata, ""},
	})
}

func TestScenario_CIMD_META_05_RedirectURIsValidated(t *testing.T) {
	t.Parallel()
	uris := func(v ...string) func(string) map[string]any {
		return func(string) map[string]any { return map[string]any{"redirect_uris": v} }
	}
	runDocCases(t, []cdDocCase{
		{"https redirect", uris(cdWebCB), "", cdWebCB},
		{"loopback 127.0.0.1", uris("http://127.0.0.1:3000/callback"), "", "http://127.0.0.1:3000/callback"},
		{"loopback localhost", uris("http://localhost:3000/callback"), "", "http://localhost:3000/callback"},
		{"loopback IPv6", uris("http://[::1]:3000/callback"), "", "http://[::1]:3000/callback"},
		{"both loopback spellings", uris("http://127.0.0.1:3000/callback", "http://localhost:3000/callback"), "", "http://localhost:3000/callback"},
		{"missing", func(string) map[string]any { return map[string]any{"redirect_uris": nil} }, "invalid_redirect_uri", ""},
		{"empty list", uris(), "invalid_redirect_uri", ""},
		{"one bad entry sinks the document", uris(cdWebCB, "http://evil.example.com/callback"), "invalid_redirect_uri", ""},
		{"http non-loopback", uris("http://app.example.com/callback"), "invalid_redirect_uri", ""},
		{"fragment", uris("https://app.example.com/callback#frag"), "invalid_redirect_uri", ""},
		{"not a URL", uris("not a url"), "invalid_redirect_uri", ""},
	})
}

func TestScenario_CIMD_META_06_UnsupportedGrantTypesDropped(t *testing.T) {
	t.Parallel()
	grants := func(v ...string) func(string) map[string]any {
		return func(string) map[string]any { return map[string]any{"grant_types": v} }
	}
	runDocCases(t, []cdDocCase{
		{"authorization_code", grants("authorization_code"), "", ""},
		{"authorization_code and refresh_token", grants("authorization_code", "refresh_token"), "", ""},
		{"unsupported grants are dropped", grants("authorization_code", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"), "", ""},
		{"client_credentials only", grants("client_credentials"), cdInvalidMetadata, ""},
		{"device_code only", grants("urn:ietf:params:oauth:grant-type:device_code"), cdInvalidMetadata, ""},
		{"empty list falls back to authorization_code", grants(), "", ""},
	})

	// A dropped grant is not merely hidden: the client cannot use it.
	e := newCDEnv(t, cdCfg{})
	_, id := newDoc(t, func(string) map[string]any {
		return map[string]any{"grant_types": []string{"authorization_code", "client_credentials"}}
	})
	f := e.newFlow(t, id, "")
	status, body := f.post(t, "/oidc/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {id}})
	if status == http.StatusOK || body["access_token"] != nil {
		t.Fatalf("client_credentials for a document client: status=%d body=%v, want a refusal", status, body)
	}
}

func TestScenario_CIMD_META_07_ResponseTypesLimitedToCode(t *testing.T) {
	t.Parallel()
	types := func(v ...string) func(string) map[string]any {
		return func(string) map[string]any { return map[string]any{"response_types": v} }
	}
	runDocCases(t, []cdDocCase{
		{"code", types("code"), "", ""},
		{"omitted", func(string) map[string]any { return nil }, "", ""},
		{"token", types("token"), cdInvalidMetadata, ""},
		{"id_token", types("id_token"), cdInvalidMetadata, ""},
		{"code id_token", types("code id_token"), cdInvalidMetadata, ""},
		{"code beside token", types("code", "token"), cdInvalidMetadata, ""},
	})
}

func TestScenario_CIMD_META_08_UnknownMembersIgnored(t *testing.T) {
	t.Parallel()
	runDocCases(t, []cdDocCase{
		{"unknown scalar and object members", func(string) map[string]any {
			return map[string]any{
				"code_challenge_methods_used": []string{"S256"},
				"x_vendor":                    map[string]any{"a": 1},
			}
		}, "", ""},
		{"response_modes is not a document member", func(string) map[string]any {
			return map[string]any{"response_modes": []string{"query", "fragment", "bogus"}}
		}, "", ""},
	})
}

func TestScenario_CIMD_META_09_GrantsAndResponseTypesAligned(t *testing.T) {
	t.Parallel()
	runDocCases(t, []cdDocCase{
		{"code with authorization_code", func(string) map[string]any {
			return map[string]any{"response_types": []string{"code"}, "grant_types": []string{"authorization_code"}}
		}, "", ""},
		{"code with refresh_token only", func(string) map[string]any {
			return map[string]any{"response_types": []string{"code"}, "grant_types": []string{"refresh_token"}}
		}, cdInvalidMetadata, ""},
		{"implicit grant with token", func(string) map[string]any {
			return map[string]any{"response_types": []string{"token"}, "grant_types": []string{"implicit"}}
		}, cdInvalidMetadata, ""},
	})
}

func TestScenario_CIMD_META_10_JWKSAndJWKSURIExclusive(t *testing.T) {
	t.Parallel()
	kp := newPKJWTKeypair(t, "cd-meta-10")
	jwks := json.RawMessage(kp.PublicJWKSet(t))
	runDocCases(t, []cdDocCase{
		{"jwks alone", func(string) map[string]any {
			return map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks": jwks} //nolint:gosec // G101: auth method name, not a credential.
		}, "", ""},
		{"jwks and jwks_uri", func(string) map[string]any {
			return map[string]any{ //nolint:gosec // G101: auth method name, not a credential.
				"token_endpoint_auth_method": "private_key_jwt", "jwks": jwks,
				"jwks_uri": "https://mcp.example.com/jwks.json",
			}
		}, cdInvalidMetadata, ""},
		{"jwks and jwks_uri on a none client", func(string) map[string]any {
			return map[string]any{"jwks": jwks, "jwks_uri": "https://mcp.example.com/jwks.json"}
		}, cdInvalidMetadata, ""},
	})
}

func TestScenario_CIMD_META_11_NativeRedirectURIsLimited(t *testing.T) {
	t.Parallel()
	app := func(typ string, uris ...string) func(string) map[string]any {
		return func(string) map[string]any { return map[string]any{"application_type": typ, "redirect_uris": uris} }
	}
	runDocCases(t, []cdDocCase{
		{"native loopback", app("native", "http://127.0.0.1:4000/cb"), "", "http://127.0.0.1:4000/cb"},
		{"native localhost", app("native", "http://localhost:4000/cb"), "", "http://localhost:4000/cb"},
		{"native http non-loopback", app("native", "http://app.example.com/cb"), "invalid_redirect_uri", ""},
		{"web http non-loopback", app("web", "http://app.example.com/cb"), "invalid_redirect_uri", ""},
	})

	// Omitted application_type with only loopback redirects is treated as
	// native: the port is free to vary (RFC 8252 §7.3). A web client's
	// redirect_uri is an exact match.
	e := newCDEnv(t, cdCfg{})
	_, native := newDoc(t, func(string) map[string]any {
		return map[string]any{"redirect_uris": []string{"http://localhost:3000/callback"}}
	})
	f := e.newFlow(t, native, "http://localhost:61234/callback")
	f.authorize(t, f.authorizeQuery("")).requireInteraction(t)

	_, web := newDoc(t, func(string) map[string]any {
		return map[string]any{"redirect_uris": []string{cdWebCB}}
	})
	f = e.newFlow(t, web, "https://mcp.example.com:8443/callback")
	f.authorize(t, f.authorizeQuery("")).requireUnknown(t)
}

func TestScenario_CIMD_META_12_MCPExampleDocumentAccepted(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	srv := newCDServer(t, cdServerOpts{})
	id := srv.url("/oauth/client-metadata.json")
	srv.opts.raw = []byte(`{
  "client_id": "` + id + `",
  "client_name": "Example MCP Client",
  "client_uri": "https://app.example.com",
  "logo_uri": "https://app.example.com/logo.png",
  "redirect_uris": ["http://127.0.0.1:3000/callback", "http://localhost:3000/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}`)
	for _, redirect := range []string{"http://127.0.0.1:3000/callback", "http://localhost:3000/callback"} {
		f := e.newFlow(t, id, redirect)
		f.authorize(t, f.authorizeQuery("")).requireInteraction(t)
	}
	e.requireFetched(t, id)
	status, body := e.run(t, id, cdRun{redirect: "http://localhost:3000/callback"})
	requireTokens(t, status, body)
}

func TestScenario_CIMD_META_13_ScopeBoundedByDocumentAndOP(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	_, withScope := newDoc(t, func(string) map[string]any {
		return map[string]any{"scope": "openid internal:admin"}
	})
	f := e.newFlow(t, withScope, "")
	p := f.authorize(t, f.authorizeQuery("openid internal:admin"))
	if p.status != http.StatusFound || p.location == nil || p.location.Query().Get("error") != "invalid_scope" {
		t.Fatalf("a scope outside the OP's public scopes: status=%d location=%v, want an invalid_scope redirect", p.status, p.location)
	}
	if got := p.location.Scheme + "://" + p.location.Host + p.location.Path; got != cdLoopbackCB {
		t.Errorf("error redirected to %s, want the document's redirect_uri", got)
	}

	// A scope the document did not declare is not granted either.
	_, narrow := newDoc(t, func(string) map[string]any { return map[string]any{"scope": "openid"} })
	f = e.newFlow(t, narrow, "")
	p = f.authorize(t, f.authorizeQuery("openid profile"))
	if p.status != http.StatusFound || p.location == nil || p.location.Query().Get("error") != "invalid_scope" {
		t.Fatalf("a scope beyond the document's own: status=%d location=%v, want an invalid_scope redirect", p.status, p.location)
	}

	// With no scope member the document takes the OP's public scopes.
	_, open := newDoc(t, nil)
	f = e.newFlow(t, open, "")
	f.authorize(t, f.authorizeQuery("openid profile")).requireInteraction(t)
}

func TestScenario_CIMD_DISC_01_FeatureFlagAdvertised(t *testing.T) {
	t.Parallel()
	doc := cdDiscovery(t, newCDEnv(t, cdCfg{}).tk)
	if got := doc["client_id_metadata_document_supported"]; got != true {
		t.Errorf("client_id_metadata_document_supported = %v, want true", got)
	}
	if methods := toStrings(doc["token_endpoint_auth_methods_supported"]); !slices.Contains(methods, "none") {
		t.Errorf("token_endpoint_auth_methods_supported = %v, want none", methods)
	}
	if methods := toStrings(doc["code_challenge_methods_supported"]); !slices.Contains(methods, "S256") {
		t.Errorf("code_challenge_methods_supported = %v, want S256", methods)
	}
}

func TestScenario_CIMD_DISC_02_FlagOmittedWhenDisabled(t *testing.T) {
	t.Parallel()
	doc := cdDiscovery(t, testkit.NewProvider(t))
	if v, present := doc["client_id_metadata_document_supported"]; present {
		t.Errorf("client_id_metadata_document_supported = %v on an OP without the feature, want the member absent", v)
	}
}

func TestScenario_CIMD_DISC_03_FAPIProfileRefused(t *testing.T) {
	t.Parallel()
	for _, p := range []profile.Profile{profile.FAPI2Baseline} {
		_, err := op.New(testkit.MinimalOptions(t,
			op.WithProfile(p),
			op.WithClientIDMetadataDocuments(op.ClientIDMetadataDocuments{}),
		)...)
		if err == nil || !strings.Contains(err.Error(), "WithClientIDMetadataDocuments") {
			t.Errorf("profile %s: op.New = %v, want a WithClientIDMetadataDocuments configuration error", p, err)
		}
	}
}

// cdDiscovery fetches the OIDC discovery document.
func cdDiscovery(t *testing.T, tk *testkit.Provider) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tk.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("build discovery request: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return doc
}

func TestScenario_CIMD_CACHE_01_CacheKeyIsExactString(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	srv := newCDServer(t, cdServerOpts{})
	port := srv.srv.Listener.Addr().String()
	port = port[strings.LastIndex(port, ":")+1:]
	lower := "http://localhost:" + port + "/client.json"
	upper := "http://LOCALHOST:" + port + "/client.json"
	srv.opts.overrides = map[string]any{"client_id": lower}

	e.probe(t, lower).requireInteraction(t)
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("after the first id: %d fetches, want 1", got)
	}

	// The upper-case spelling is a different identifier: not served from the
	// lower-case entry, and compared byte-for-byte with the document's client_id.
	e.probe(t, upper).requireUnknown(t)
	if got := srv.hits.Load(); got != 2 {
		t.Fatalf("after the upper-case spelling: %d fetches, want 2 (its own cache entry)", got)
	}
	if code := e.requireFailure(t, upper, "validation"); code != cdInvalidMetadata {
		t.Errorf("error_code = %q, want %s", code, cdInvalidMetadata)
	}

	// Each spelling is then answered from its own entry.
	e.probe(t, lower).requireInteraction(t)
	e.probe(t, upper).requireUnknown(t)
	if got := srv.hits.Load(); got != 2 {
		t.Errorf("repeat requests: %d fetches, want 2 (both cached)", got)
	}
}

func TestScenario_CIMD_CACHE_02_ConcurrentFetchesCoalesce(t *testing.T) {
	t.Parallel()
	const callers = 12
	rec := &cdAllowRecorder{}
	e := newCDEnv(t, cdCfg{allow: rec.allow})
	gate := make(chan struct{})
	var srv *cdServer
	srv = newCDServer(t, cdServerOpts{custom: func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
		srv.serve(w, r)
	}})
	id := srv.url("/client.json")

	var wg sync.WaitGroup
	results := make([]bool, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := e.newFlow(t, id, "")
			results[i] = f.authorize(t, f.authorizeQuery("")).interacted()
		}()
	}
	// Every caller passes the allow hook before it can join or start the
	// fetch, which the gate holds open; wait for all of them to arrive.
	deadline := time.Now().Add(30 * time.Second)
	for len(rec.snapshot()) < callers && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(rec.snapshot()); got < callers {
		t.Fatalf("only %d of %d callers reached the fetch", got, callers)
	}
	close(gate)
	wg.Wait()

	for i, ok := range results {
		if !ok {
			t.Errorf("caller %d was not admitted", i)
		}
	}
	if got := srv.hits.Load(); got != 1 {
		t.Errorf("%d concurrent resolutions made %d fetches, want 1", callers, got)
	}
}

func TestScenario_CIMD_CACHE_03_StrictExpiryNoStaleServing(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	var status atomic.Int32
	status.Store(http.StatusOK)
	var srv *cdServer
	srv = newCDServer(t, cdServerOpts{
		headers: func() http.Header { return http.Header{"Cache-Control": {"max-age=300"}} },
		custom: func(w http.ResponseWriter, r *http.Request) {
			if code := int(status.Load()); code != http.StatusOK {
				w.WriteHeader(code)
				return
			}
			srv.serve(w, r)
		},
	})
	id := srv.url("/client.json")

	e.probe(t, id).requireInteraction(t)
	e.clock.advance(299 * time.Second)
	e.probe(t, id).requireInteraction(t)
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("inside max-age: %d fetches, want 1", got)
	}

	// Past max-age the entry is gone: a document that now fails is not
	// answered from the stale copy.
	status.Store(http.StatusInternalServerError)
	e.clock.advance(2 * time.Second)
	e.probe(t, id).requireUnknown(t)
	if got := srv.hits.Load(); got != 2 {
		t.Errorf("after max-age: %d fetches, want 2", got)
	}
	e.requireFailure(t, id, "status")
}

func TestScenario_CIMD_CACHE_04_FailuresCachedBriefly(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	var status atomic.Int32
	status.Store(http.StatusServiceUnavailable)
	var srv *cdServer
	srv = newCDServer(t, cdServerOpts{custom: func(w http.ResponseWriter, r *http.Request) {
		if code := int(status.Load()); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		srv.serve(w, r)
	}})
	id := srv.url("/client.json")

	e.probe(t, id).requireUnknown(t)
	e.clock.advance(4 * time.Second)
	e.probe(t, id).requireUnknown(t)
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("inside the 5s failure window: %d fetches, want 1", got)
	}

	// Once the window passes, a recovered document is picked up.
	status.Store(http.StatusOK)
	e.clock.advance(2 * time.Second)
	e.probe(t, id).requireInteraction(t)
	if got := srv.hits.Load(); got != 2 {
		t.Errorf("after the failure window: %d fetches, want 2", got)
	}
}

func TestScenario_CIMD_FLOW_01_ResolvedBeforeLogin(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	srv, id := newDoc(t, nil)

	// The document is fetched while /authorize runs, before the user has
	// authenticated anything.
	e.probe(t, id).requireInteraction(t)
	if got := srv.hits.Load(); got != 1 {
		t.Errorf("document fetched %d times by /authorize, want 1", got)
	}
	e.requireFetched(t, id)

	// A document that cannot be used ends the request before any interaction.
	bad := newCDServer(t, cdServerOpts{status: http.StatusNotFound})
	e.probe(t, bad.url("/client.json")).requireUnknown(t)
}

func TestScenario_CIMD_FLOW_02_FetchedClientIsEphemeral(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	_, id := newDoc(t, nil)
	status, body := e.run(t, id, cdRun{})
	requireTokens(t, status, body)
	for _, member := range []string{"registration_access_token", "registration_client_uri", "client_secret"} {
		if _, present := body[member]; present {
			t.Errorf("token response carries %s for a document client", member)
		}
	}
	if _, err := e.tk.Store.Clients().GetClient(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("store.GetClient(%s) = %v, want store.ErrNotFound (a document client is never persisted)", id, err)
	}
}

func TestScenario_CIMD_FLOW_03_RedirectURIMatchingStandard(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	_, web := newDoc(t, func(string) map[string]any { return map[string]any{"redirect_uris": []string{cdWebCB}} })
	for _, tc := range []struct {
		name, redirect string
		ok             bool
	}{
		{"exact", cdWebCB, true},
		{"different path", cdWebCB + "/extra", false},
		{"added query", cdWebCB + "?a=b", false},
		{"different port", "https://mcp.example.com:8443/callback", false},
		{"different host", "https://evil.example.com/callback", false},
		{"different scheme", "http://mcp.example.com/callback", false},
	} {
		f := e.newFlow(t, web, tc.redirect)
		p := f.authorize(t, f.authorizeQuery(""))
		if tc.ok {
			p.requireInteraction(t)
			continue
		}
		// A redirect_uri the document does not list is never redirected to.
		if p.status != http.StatusBadRequest || p.location != nil {
			t.Errorf("%s: status=%d location=%v, want 400 without a redirect", tc.name, p.status, p.location)
		}
	}

	// A loopback redirect may vary its port (RFC 8252 §7.3); nothing else.
	_, loop := newDoc(t, nil)
	for _, tc := range []struct {
		redirect string
		ok       bool
	}{
		{"http://127.0.0.1:53111/callback", true},
		{"http://127.0.0.1:60001/callback", true},
		{"http://127.0.0.1:60001/other", false},
		{"http://127.0.0.2:53111/callback", false},
	} {
		f := e.newFlow(t, loop, tc.redirect)
		p := f.authorize(t, f.authorizeQuery(""))
		if p.interacted() != tc.ok {
			t.Errorf("loopback %s: interacted=%v, want %v (status=%d)", tc.redirect, p.interacted(), tc.ok, p.status)
		}
	}
}

// cdPKJWTDoc returns a document override for a private_key_jwt client.
func cdPKJWTDoc(kp *pkjwtKeypair, t *testing.T, extra map[string]any) func(string) map[string]any {
	jwks := json.RawMessage(kp.PublicJWKSet(t))
	return func(string) map[string]any {
		out := map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks": jwks} //nolint:gosec // G101: auth method name, not a credential.
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
}

func TestScenario_CIMD_FLOW_04_PARAcceptsCIMDClients(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{par: true})

	_, none := newDoc(t, nil)
	status, body := e.run(t, none, cdRun{par: true})
	requireTokens(t, status, body)

	kp := newPKJWTKeypair(t, "cd-flow-04")
	_, pk := newDoc(t, cdPKJWTDoc(kp, t, nil))
	status, body = e.run(t, pk, cdRun{par: true, kp: kp})
	requireTokens(t, status, body)

	// An unresolvable client_id is refused at /par itself.
	bad := newCDServer(t, cdServerOpts{status: http.StatusNotFound}).url("/client.json")
	f := e.newFlow(t, bad, "")
	st, out := f.post(t, "/oidc/par", f.authorizeQuery(""))
	if st < 400 || out["request_uri"] != nil {
		t.Errorf("/par for an unresolvable client_id: status=%d body=%v, want a refusal", st, out)
	}
}

func TestScenario_CIMD_FLOW_05_TokenEndpointResolvesCIMD(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})

	_, none := newDoc(t, nil)
	status, body := e.run(t, none, cdRun{})
	requireTokens(t, status, body)
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", body["token_type"])
	}

	kp := newPKJWTKeypair(t, "cd-flow-05")
	_, pk := newDoc(t, cdPKJWTDoc(kp, t, nil))
	f, code := e.authorizeCode(t, pk, cdRun{kp: kp})

	// An assertion signed by a key the document does not publish.
	wrong := newPKJWTKeypair(t, "cd-flow-05")
	st, out := f.redeem(t, code, wrong)
	cdRequireInvalidClient(t, st, out)
	// No assertion at all.
	st, out = f.redeem(t, code, nil)
	cdRequireInvalidClient(t, st, out)
	// The code survives both refusals and redeems with the right key.
	st, out = f.redeem(t, code, kp)
	requireTokens(t, st, out)
}

func TestScenario_CIMD_FLOW_06_TokenExchangeUnauthorized(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{extra: []op.Option{op.WithTokenExchangeGrant(op.TokenExchangeGrant{Policy: cdAllowAllExchange{}})}})
	_, id := newDoc(t, func(string) map[string]any {
		return map[string]any{"grant_types": []string{"authorization_code", op.TokenExchangeGrantType}}
	})
	status, tokens := e.run(t, id, cdRun{})
	requireTokens(t, status, tokens)

	f := e.newFlow(t, id, "")
	st, out := f.post(t, "/oidc/token", url.Values{
		"grant_type":         {op.TokenExchangeGrantType},
		"client_id":          {id},
		"subject_token":      {tokens["access_token"].(string)},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	if st != http.StatusBadRequest || out["error"] != "unauthorized_client" {
		t.Fatalf("token exchange status=%d body=%v, want 400 unauthorized_client", st, out)
	}
}

type cdAllowAllExchange struct{}

func (cdAllowAllExchange) Allow(context.Context, op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	return &op.TokenExchangeDecision{}, nil
}

func TestScenario_CIMD_FLOW_07_NeverFirstParty(t *testing.T) {
	t.Parallel()
	const id = "https://mcp.example.com/client.json"
	_, err := op.New(testkit.MinimalOptions(t,
		op.WithClientIDMetadataDocuments(op.ClientIDMetadataDocuments{}),
		op.WithFirstPartyClients(id),
	)...)
	if err == nil || !strings.Contains(err.Error(), id) {
		t.Fatalf("op.New = %v, want the unknown first-party client_id %s named in the error", err, id)
	}

	// A document client's first authorization stops at the consent screen:
	// no first-party shortcut can skip it.
	e := newCDEnv(t, cdCfg{})
	_, doc := newDoc(t, nil)
	f := e.newFlow(t, doc, "")
	probe := f.authorize(t, f.authorizeQuery(""))
	probe.requireInteraction(t)
	prompt, _, _ := f.login(t, probe.location.Path)
	if typ, _ := prompt["type"].(string); typ != "consent.scope" {
		t.Errorf("first authorization prompt type = %q, want consent.scope", typ)
	}
}

func TestScenario_CIMD_FLOW_08_PKCERequired(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	kp := newPKJWTKeypair(t, "cd-flow-08")
	_, none := newDoc(t, func(string) map[string]any { return map[string]any{"redirect_uris": []string{cdWebCB}} })
	_, pk := newDoc(t, cdPKJWTDoc(kp, t, map[string]any{"redirect_uris": []string{cdWebCB}}))

	for name, id := range map[string]string{"none": none, "private_key_jwt": pk} {
		f := e.newFlow(t, id, cdWebCB)
		q := f.authorizeQuery("")
		q.Del("code_challenge")
		q.Del("code_challenge_method")
		p := f.authorize(t, q)
		if p.status != http.StatusFound || p.location == nil ||
			p.location.Query().Get("error") != "invalid_request" ||
			!strings.Contains(p.location.Query().Get("error_description"), "code_challenge") {
			t.Errorf("%s without PKCE: status=%d location=%v, want an invalid_request redirect naming code_challenge", name, p.status, p.location)
		}
	}
}

func TestScenario_CIMD_FLOW_09_ResourceFromProtectedResources(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{resources: []string{cdResource}})
	_, id := newDoc(t, nil)

	status, body := e.run(t, id, cdRun{resource: cdResource})
	requireTokens(t, status, body)
	if aud := accessTokenAudience(t, body); len(aud) != 1 || aud[0] != cdResource {
		t.Errorf("access token aud = %v, want [%s]", aud, cdResource)
	}

	// A resource the OP does not declare is refused at /authorize.
	f := e.newFlow(t, id, "")
	q := f.authorizeQuery("")
	q.Set("resource", "https://other.example.com/api")
	p := f.authorize(t, q)
	if p.status != http.StatusFound || p.location == nil || p.location.Query().Get("error") != "invalid_target" {
		t.Errorf("undeclared resource: status=%d location=%v, want an invalid_target redirect", p.status, p.location)
	}
}

func TestScenario_CIMD_FLOW_10_ConsentNamesHostAndRedirect(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	for _, tc := range []struct {
		name     string
		redirect string
		host     string
		loopback bool
	}{
		{"loopback ip", "http://127.0.0.1:53111/callback", "127.0.0.1", true},
		{"loopback name", "http://localhost:53111/callback", "localhost", true},
		{"web", cdWebCB, "mcp.example.com", false},
	} {
		srv, id := newDoc(t, func(string) map[string]any {
			return map[string]any{"redirect_uris": []string{tc.redirect}}
		})
		f := e.newFlow(t, id, tc.redirect)
		probe := f.authorize(t, f.authorizeQuery(""))
		probe.requireInteraction(t)
		prompt, _, _ := f.login(t, probe.location.Path)
		client := consentClient(t, prompt)
		for key, want := range map[string]any{
			"client_id":              id,
			"name":                   "Example MCP Client",
			"metadata_document_host": strings.TrimPrefix(srv.srv.URL, "http://"),
			"redirect_host":          tc.host,
			"redirect_loopback":      tc.loopback,
			"logo_url":               "",
		} {
			if got := client[key]; got != want {
				t.Errorf("%s: consent client.%s = %v, want %v", tc.name, key, got, want)
			}
		}
	}
}

func TestScenario_CIMD_FLOW_11_RefreshFollowsTheDocument(t *testing.T) {
	t.Parallel()
	e := newCDEnv(t, cdCfg{})
	var gone atomic.Bool
	var srv *cdServer
	srv = newCDServer(t, cdServerOpts{custom: func(w http.ResponseWriter, r *http.Request) {
		if gone.Load() {
			http.NotFound(w, r)
			return
		}
		srv.serve(w, r)
	}})
	id := srv.url("/client.json")
	srv.opts.overrides = map[string]any{"grant_types": []string{"authorization_code", "refresh_token"}}

	f, code := e.authorizeCode(t, id, cdRun{scope: "openid offline_access"})
	st, tokens := f.redeem(t, code, nil)
	requireTokens(t, st, tokens)
	refresh, _ := tokens["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh_token issued: %v", tokens)
	}

	st, rotated := f.post(t, "/oidc/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {refresh}})
	requireTokens(t, st, rotated)
	next, _ := rotated["refresh_token"].(string)
	if next == "" || next == refresh {
		t.Fatalf("refresh did not rotate the token: %v", rotated)
	}

	// Once the document is gone and its cache entry has lapsed, the client
	// no longer resolves, so the refresh token cannot be redeemed.
	gone.Store(true)
	e.clock.advance(2 * time.Minute)
	st, out := f.post(t, "/oidc/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {next}})
	cdRequireInvalidClient(t, st, out)
	e.requireFailure(t, id, "status")
}

// cdPairwiseRows is a hand-built all-pairs covering array over
// auth method {none, private_key_jwt} x route {plain, PAR} x
// resource {absent, present} x cache {miss, hit, expired}. Six rows are the
// minimum for a three-level factor against two-level ones; the table below
// covers every pair of values from two different factors.
//
//	pair      covered by rows
//	A x B     none/plain 1,5   none/PAR 3   pkjwt/plain 4   pkjwt/PAR 2,6
//	A x C     none/absent 1    none/present 3,5   pkjwt/absent 4,6   pkjwt/present 2
//	B x C     plain/absent 1,4   plain/present 5   PAR/absent 6   PAR/present 2,3
//	A x D     none: miss 1, hit 3, expired 5   pkjwt: miss 2, hit 4, expired 6
//	B x D     plain: miss 1, hit 4, expired 5   PAR: miss 2, hit 3, expired 6
//	C x D     absent: miss 1, hit 4, expired 6   present: miss 2, hit 3, expired 5
var cdPairwiseRows = []struct {
	name     string
	pkjwt    bool
	par      bool
	resource bool
	cache    string
}{
	{"1 none plain absent miss", false, false, false, "miss"},
	{"2 pkjwt PAR present miss", true, true, true, "miss"},
	{"3 none PAR present hit", false, true, true, "hit"},
	{"4 pkjwt plain absent hit", true, false, false, "hit"},
	{"5 none plain present expired", false, false, true, "expired"},
	{"6 pkjwt PAR absent expired", true, true, false, "expired"},
}

func TestScenario_CIMD_FLOW_12_PairwiseAuthRouteResourceCache(t *testing.T) {
	t.Parallel()
	for _, row := range cdPairwiseRows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			e := newCDEnv(t, cdCfg{par: true, resources: []string{cdResource}})
			var mk func(string) map[string]any
			var kp *pkjwtKeypair
			if row.pkjwt {
				kp = newPKJWTKeypair(t, "cd-flow-12")
				mk = cdPKJWTDoc(kp, t, nil)
			}
			srv, id := newDoc(t, mk)

			wantFetches := int32(1)
			switch row.cache {
			case "hit":
				e.probe(t, id).requireInteraction(t)
			case "expired":
				e.probe(t, id).requireInteraction(t)
				e.clock.advance(61 * time.Second)
				wantFetches = 2
			}
			run := cdRun{kp: kp, par: row.par}
			if row.resource {
				run.resource = cdResource
			}
			status, body := e.run(t, id, run)
			requireTokens(t, status, body)

			aud := accessTokenAudience(t, body)
			if row.resource && (len(aud) != 1 || aud[0] != cdResource) {
				t.Errorf("aud = %v, want [%s]", aud, cdResource)
			}
			if !row.resource && slices.Contains(aud, cdResource) {
				t.Errorf("aud = %v names a resource that was not requested", aud)
			}
			if got := srv.hits.Load(); got != wantFetches {
				t.Errorf("document fetched %d times, want %d for cache state %s", got, wantFetches, row.cache)
			}
		})
	}
}

// TestScenario_CIMD_FLOW_13_DocumentChangeKeepsGrants is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_FLOW_13_DocumentChangeKeepsGrants(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-FLOW-13 (see catalog out_of_scope_reason)")
}

// TestScenario_CIMD_RES_13_NoPerOriginFetchBudget is OOS — see catalog out_of_scope_reason.
func TestScenario_CIMD_RES_13_NoPerOriginFetchBudget(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIMD-RES-13 (see catalog out_of_scope_reason)")
}

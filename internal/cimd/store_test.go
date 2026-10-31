//nolint:testpackage // white-box: drives the unexported test seams on Config.
package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/remotecache"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const documentPath = "/client.json"

var testPublicScopes = []string{"openid", "profile", "mcp:tools"}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// recorder is an audit sink that keeps every event for inspection.
type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Emit(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recorder) named(name auditevent.Name) []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Event
	for _, ev := range r.events {
		if ev.Name == string(name) {
			out = append(out, ev)
		}
	}
	return out
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// codeErr is a validator error carrying a wire error code.
type codeErr string

func (e codeErr) Error() string     { return string(e) }
func (e codeErr) ErrorCode() string { return string(e) }

// testValidate stands in for the registration-endpoint validator: object
// root, exact client_id match, redirect_uris required.
func testValidate(raw []byte, url string) (*store.Client, error) {
	var doc struct {
		ClientID     string   `json:"client_id"`
		Scope        string   `json:"scope"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, codeErr("invalid_client_metadata")
	}
	if doc.ClientID != url {
		return nil, codeErr("invalid_client_metadata")
	}
	if len(doc.RedirectURIs) == 0 {
		return nil, codeErr("invalid_redirect_uri")
	}
	return &store.Client{ID: url, RedirectURIs: doc.RedirectURIs, Scopes: strings.Fields(doc.Scope)}, nil
}

// documentFor renders a document whose client_id is id, merged with extra.
func documentFor(id string, extra map[string]any) []byte {
	doc := map[string]any{
		"client_id":     id,
		"client_name":   "Test MCP client",
		"redirect_uris": []string{"http://127.0.0.1:3000/callback"},
	}
	for k, v := range extra {
		doc[k] = v
	}
	out, _ := json.Marshal(doc)
	return out
}

// requestURL reconstructs the client_id URL a document request was made for.
func requestURL(r *http.Request) string {
	return "http://" + r.Host + r.URL.Path
}

// docServer serves documents produced by handle and counts requests.
type docServer struct {
	srv  *httptest.Server
	hits atomic.Int32
}

func (d *docServer) id() string { return d.srv.URL + documentPath }

func newDocServer(t *testing.T, handle func(w http.ResponseWriter, r *http.Request)) *docServer {
	t.Helper()
	d := &docServer{}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.hits.Add(1)
		handle(w, r)
	}))
	t.Cleanup(d.srv.Close)
	return d
}

// serveDocument answers with a valid document for the requested URL.
func serveDocument(extra map[string]any, header http.Header) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		for k, vs := range header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		_, _ = w.Write(documentFor(requestURL(r), extra))
	}
}

type harness struct {
	store *Store
	inner *inmem.Store
	rec   *recorder
	clock *fakeClock
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	h := &harness{inner: inmem.New(), rec: &recorder{}, clock: newFakeClock()}
	cfg := Config{
		Inner:        h.inner,
		Validate:     testValidate,
		AllowPrivate: true, // httptest binds a loopback http listener.
		Audit:        h.rec,
		Clock:        h.clock,
		Resources:    []string{"https://mcp.example/"},
		PublicScopes: testPublicScopes,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	h.store = New(cfg)
	return h
}

func TestGetClient_ResolvesDocumentAndStampsClient(t *testing.T) {
	t.Parallel()
	srv := newDocServer(t, serveDocument(map[string]any{"scope": "openid mcp:tools admin mcp:tools"}, nil))
	h := newHarness(t, nil)

	got, err := h.store.GetClient(context.Background(), srv.id())
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.ID != srv.id() || got.Source != store.ClientSourceMetadataDocument {
		t.Fatalf("client id=%q source=%q, want %q / metadata_document", got.ID, got.Source, srv.id())
	}
	if !slices.Equal(got.Resources, []string{"https://mcp.example/"}) {
		t.Fatalf("Resources=%v, want the protected-resource list", got.Resources)
	}
	if !slices.Equal(got.Scopes, []string{"openid", "mcp:tools"}) {
		t.Fatalf("Scopes=%v, want document scopes intersected with public scopes", got.Scopes)
	}
	fetched := h.rec.named(auditevent.AuditCIMDFetched)
	if len(fetched) != 1 || fetched[0].ClientID != srv.id() {
		t.Fatalf("cimd.fetched events=%+v, want one for %q", fetched, srv.id())
	}
}

func TestGetClient_DocumentWithoutScopeGetsAllPublicScopes(t *testing.T) {
	t.Parallel()
	srv := newDocServer(t, serveDocument(nil, nil))
	h := newHarness(t, nil)

	got, err := h.store.GetClient(context.Background(), srv.id())
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if !slices.Equal(got.Scopes, testPublicScopes) {
		t.Fatalf("Scopes=%v, want every public scope %v", got.Scopes, testPublicScopes)
	}
}

func TestGetClient_ReturnsIsolatedCopy(t *testing.T) {
	t.Parallel()
	srv := newDocServer(t, serveDocument(nil, nil))
	h := newHarness(t, nil)

	first, err := h.store.GetClient(context.Background(), srv.id())
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	first.RedirectURIs[0] = "https://attacker.example/cb"
	second, err := h.store.GetClient(context.Background(), srv.id())
	if err != nil {
		t.Fatalf("second GetClient: %v", err)
	}
	if second.RedirectURIs[0] != "http://127.0.0.1:3000/callback" {
		t.Fatalf("cached record mutated through a returned copy: %v", second.RedirectURIs)
	}
}

func TestGetClient_RegisteredClientWins(t *testing.T) {
	t.Parallel()
	srv := newDocServer(t, serveDocument(nil, nil))
	h := newHarness(t, nil)
	registered := &store.Client{ID: srv.id(), Source: store.ClientSourceStatic, ClientName: "registered"}
	if err := h.inner.RegisterClient(context.Background(), registered); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	got, err := h.store.GetClient(context.Background(), srv.id())
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.Source != store.ClientSourceStatic || got.ClientName != "registered" {
		t.Fatalf("got source=%q name=%q, want the registered record", got.Source, got.ClientName)
	}
	if n := srv.hits.Load(); n != 0 {
		t.Fatalf("document fetched %d times for a registered id, want 0", n)
	}
}

type clientStoreFunc func(ctx context.Context, id string) (*store.Client, error)

func (f clientStoreFunc) GetClient(ctx context.Context, id string) (*store.Client, error) {
	return f(ctx, id)
}

func TestGetClient_InnerFaultPassesThrough(t *testing.T) {
	t.Parallel()
	srv := newDocServer(t, serveDocument(nil, nil))
	fault := errors.New("backend unreachable")
	h := newHarness(t, func(c *Config) {
		c.Inner = clientStoreFunc(func(context.Context, string) (*store.Client, error) { return nil, fault })
	})

	_, err := h.store.GetClient(context.Background(), srv.id())
	if !errors.Is(err, fault) {
		t.Fatalf("err=%v, want the inner store fault", err)
	}
	if n := srv.hits.Load(); n != 0 {
		t.Fatalf("document fetched %d times after an inner fault, want 0", n)
	}
}

func TestGetClient_NonConformingIDIsUnknownWithoutFetchOrAudit(t *testing.T) {
	t.Parallel()
	srv := newDocServer(t, serveDocument(nil, nil))
	h := newHarness(t, nil)

	for _, id := range []string{"rp-1", srv.URLWith("/"), srv.URLWith("/a?x=1"), srv.URLWith("/a/../b")} {
		_, err := h.store.GetClient(context.Background(), id)
		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("GetClient(%q) err=%v, want ErrNotFound", id, err)
		}
	}
	if n := srv.hits.Load(); n != 0 {
		t.Fatalf("document fetched %d times for non-conforming ids, want 0", n)
	}
	if n := h.rec.count(); n != 0 {
		t.Fatalf("audit events=%d for non-conforming ids, want 0", n)
	}
}

func (d *docServer) URLWith(path string) string { return d.srv.URL + path }

func TestGetClient_AllowFalseDeniesBeforeFetch(t *testing.T) {
	t.Parallel()
	srv := newDocServer(t, serveDocument(nil, nil))
	var seen atomic.Value
	h := newHarness(t, func(c *Config) {
		c.Allow = func(_ context.Context, id string) bool {
			seen.Store(id)
			return false
		}
	})

	_, err := h.store.GetClient(context.Background(), srv.id())
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err=%v, want ErrNotFound", err)
	}
	if got, _ := seen.Load().(string); got != srv.id() {
		t.Fatalf("Allow saw %q, want %q", got, srv.id())
	}
	if n := srv.hits.Load(); n != 0 {
		t.Fatalf("document fetched %d times after Allow refused, want 0", n)
	}
	denied := h.rec.named(auditevent.AuditCIMDClientDenied)
	if len(denied) != 1 || denied[0].ClientID != srv.id() {
		t.Fatalf("cimd.client_denied events=%+v, want one for %q", denied, srv.id())
	}
}

func TestGetClient_AllowConsultedOnCacheHit(t *testing.T) {
	t.Parallel()
	srv := newDocServer(t, serveDocument(nil, nil))
	var (
		allow atomic.Bool
		calls atomic.Int32
	)
	allow.Store(true)
	h := newHarness(t, func(c *Config) {
		c.Allow = func(context.Context, string) bool {
			calls.Add(1)
			return allow.Load()
		}
	})

	if _, err := h.store.GetClient(context.Background(), srv.id()); err != nil {
		t.Fatalf("first GetClient: %v", err)
	}
	allow.Store(false)
	if _, err := h.store.GetClient(context.Background(), srv.id()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetClient after narrowing Allow err=%v, want ErrNotFound", err)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("Allow calls=%d, want 2 (cache hit included)", n)
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("document fetched %d times, want 1", n)
	}
}

func TestGetClient_NegativeCacheHoldsFiveSeconds(t *testing.T) {
	t.Parallel()
	var fail atomic.Bool
	fail.Store(true)
	ok := serveDocument(nil, nil)
	srv := newDocServer(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		ok(w, r)
	})
	h := newHarness(t, nil)
	ctx := context.Background()

	for range 2 {
		if _, err := h.store.GetClient(ctx, srv.id()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("GetClient err=%v, want ErrNotFound", err)
		}
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("hits=%d inside the negative TTL, want 1", n)
	}
	if n := len(h.rec.named(auditevent.AuditCIMDFetchFailed)); n != 1 {
		t.Fatalf("cimd.fetch_failed events=%d, want 1 (cached failures are not re-audited)", n)
	}

	fail.Store(false)
	h.clock.Advance(4 * time.Second)
	if _, err := h.store.GetClient(ctx, srv.id()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetClient at 4s err=%v, want the cached failure", err)
	}
	h.clock.Advance(time.Second)
	if _, err := h.store.GetClient(ctx, srv.id()); err != nil {
		t.Fatalf("GetClient at 5s: %v, want a fresh fetch", err)
	}
	if n := srv.hits.Load(); n != 2 {
		t.Fatalf("hits=%d after the negative TTL, want 2", n)
	}
}

// TestGetClient_OverloadIsUnavailableAndNotCached saturates the process-wide
// load gate, so it must not run in parallel with any other fetching test.
//
//nolint:paralleltest // holds every slot of the process-wide load gate.
func TestGetClient_OverloadIsUnavailableAndNotCached(t *testing.T) {
	srv := newDocServer(t, serveDocument(nil, nil))
	h := newHarness(t, nil)
	ctx := context.Background()

	gate := remotecache.SharedLoadGate(remotecache.DefaultMaxInflight)
	releases := make([]func(), 0, remotecache.DefaultMaxInflight)
	for range remotecache.DefaultMaxInflight {
		release, err := gate.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire: %v", err)
		}
		releases = append(releases, release)
	}
	_, err := h.store.GetClient(ctx, srv.id())
	for _, release := range releases {
		release()
	}
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err=%v, want ErrUnavailable and not ErrNotFound", err)
	}
	if n := srv.hits.Load(); n != 0 {
		t.Fatalf("hits=%d while overloaded, want 0", n)
	}
	if n := h.rec.count(); n != 0 {
		t.Fatalf("audit events=%d for an overload refusal, want 0", n)
	}

	if _, err := h.store.GetClient(ctx, srv.id()); err != nil {
		t.Fatalf("GetClient after capacity returned: %v (overload must not be negative-cached)", err)
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("hits=%d after capacity returned, want 1", n)
	}
}

func TestGetClient_SingleflightMergesConcurrentMisses(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ok := serveDocument(nil, nil)
	srv := newDocServer(t, func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		ok(w, r)
	})
	h := newHarness(t, nil)

	const concurrent = 16
	errs := make(chan error, concurrent)
	var wg sync.WaitGroup
	for range concurrent {
		wg.Go(func() {
			_, err := h.store.GetClient(context.Background(), srv.id())
			errs <- err
		})
	}
	<-entered
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("hits=%d for %d concurrent misses, want 1", n, concurrent)
	}
	if n := len(h.rec.named(auditevent.AuditCIMDFetched)); n != 1 {
		t.Fatalf("cimd.fetched events=%d, want 1", n)
	}
}

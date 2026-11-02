package ssf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	mgmtClientA     = "rp-a" // the caller in every test
	mgmtClientB     = "rp-b"
	mgmtPollBase    = testIssuer + "/ssf/poll"
	mgmtStreamsPath = "/ssf/streams"
	mgmtStatusPath  = "/ssf/status"
	mgmtVerifyPath  = "/ssf/verify"
)

// mgmtTokenForm is how the caller's access token is presented.
type mgmtTokenForm int

const (
	mgmtJWT    mgmtTokenForm = iota // JWT under the Bearer scheme
	mgmtOpaque                      // opaque token under the Bearer scheme
	mgmtDPoP                        // DPoP-bound JWT under the DPoP scheme
)

func (f mgmtTokenForm) String() string {
	return [...]string{"jwt", "opaque", "dpop"}[f]
}

// mgmtFixture wires the endpoint handlers to an in-memory store with
// receivers rp-a and rp-b registered.
type mgmtFixture struct {
	st      *inmem.Store
	rec     *recordingAudit
	tx      *Transmitter
	sealer  *Sealer
	h       *Handlers
	mux     *http.ServeMux
	atKey   tokens.SigningKey
	setKey  SigningKey
	setPub  *ecdsa.PublicKey
	dpopKey *ecdsa.PrivateKey
	jkt     string
	seq     int
}

type mgmtOption func(*HandlerDeps)

func mgmtWithDev(d *HandlerDeps)     { d.AllowInsecureForDev = true }
func mgmtWithPrivate(d *HandlerDeps) { d.AllowPrivateNetwork = true }

func newMgmtFixture(t *testing.T, opts ...mgmtOption) *mgmtFixture {
	t.Helper()
	ctx := context.Background()
	st := newTestStores(t)
	for _, id := range []string{mgmtClientA, mgmtClientB} {
		if err := st.RegisterClient(ctx, &store.Client{ID: id}); err != nil {
			t.Fatalf("RegisterClient: %v", err)
		}
	}
	rec := &recordingAudit{}
	tx := newTestTransmitter(t, testDeps(t, st, rec))
	sealer, err := NewSealer(testSealKey(t))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	atPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	set, err := keys.NewSet([]keys.Entry{{KeyID: "at-k1", Signer: atPriv}})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	clock := fixedClock(testNow)
	verifier, err := dpop.NewVerifier(dpop.VerifierConfig{JTIs: st.ConsumedJTIs(), Clock: clock})
	if err != nil {
		t.Fatalf("dpop.NewVerifier: %v", err)
	}
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jkt, err := dpop.Thumbprint(&josev4.JSONWebKey{Key: &dpopKey.PublicKey})
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	setKey, setPub := testKey(t, "set-k1")
	f := &mgmtFixture{
		st: st, rec: rec, tx: tx, sealer: sealer,
		atKey:  tokens.SigningKey{KeyID: "at-k1", Signer: atPriv},
		setKey: setKey, setPub: setPub, dpopKey: dpopKey, jkt: jkt,
	}
	d := HandlerDeps{
		Issuer: testIssuer,
		Bearer: endpointsupport.BearerDeps{
			Keys:               set,
			Issuer:             testIssuer,
			Clock:              clock,
			Clients:            st.Clients(),
			OpaqueAccessTokens: st.OpaqueAccessTokens(),
			GrantRevocations:   st.GrantRevocations(),
			RevocationStrategy: store.RevocationStrategyGrantTombstone,
			DPoP:               verifier,
		},
		Streams:      st.SSFStreams(),
		Events:       st.SSFEvents(),
		Transmitter:  tx,
		Sealer:       sealer,
		PollEndpoint: mgmtPollBase,
		ActiveKey:    func() (SigningKey, error) { return f.setKey, nil },
		Audit:        rec,
		Clock:        clock,
	}
	for _, o := range opts {
		o(&d)
	}
	h, err := NewHandlers(d)
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	f.h = h
	f.mux = http.NewServeMux()
	f.mux.Handle(mgmtStreamsPath, h.Streams())
	f.mux.Handle(mgmtStatusPath, h.Status())
	f.mux.Handle(mgmtVerifyPath, h.Verify())
	f.mux.Handle("/ssf/poll/{"+PollPathValue+"}", h.Poll())
	return f
}

// token mints an access token for clientID with scope in the given form.
func (f *mgmtFixture) token(t *testing.T, form mgmtTokenForm, clientID string, scope []string, edit func(*tokens.AccessTokenClaims)) string {
	t.Helper()
	f.seq++
	if form == mgmtOpaque {
		rec := &store.OpaqueAccessToken{
			ID:        fmt.Sprintf("opaque-%d", f.seq),
			ClientID:  clientID,
			Subject:   clientID,
			Scope:     scope,
			Audience:  testIssuer,
			IssuedAt:  testNow.Add(-time.Minute),
			ExpiresAt: testNow.Add(time.Hour),
		}
		if err := f.st.OpaqueAccessTokens().Save(context.Background(), rec); err != nil {
			t.Fatalf("Save opaque: %v", err)
		}
		return rec.ID
	}
	c := tokens.AccessTokenClaims{
		Issuer:    testIssuer,
		Subject:   clientID,
		Audience:  []string{testIssuer},
		ClientID:  clientID,
		IssuedAt:  testNow.Add(-time.Minute).Unix(),
		ExpiresAt: testNow.Add(time.Hour).Unix(),
		JTI:       fmt.Sprintf("at-%d", f.seq),
		Scope:     scope,
	}
	if form == mgmtDPoP {
		c.Confirmation = map[string]string{tokens.CnfJKT: f.jkt}
	}
	if edit != nil {
		edit(&c)
	}
	raw, err := tokens.SignAccessToken(f.atKey, c)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	return raw
}

// authorizeRequest presents raw in form on r, adding a DPoP proof when needed.
func (f *mgmtFixture) authorizeRequest(t *testing.T, r *http.Request, form mgmtTokenForm, raw string) {
	t.Helper()
	if form != mgmtDPoP {
		r.Header.Set("Authorization", "Bearer "+raw)
		return
	}
	r.Header.Set("Authorization", "DPoP "+raw)
	f.seq++
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: f.dpopKey},
		(&josev4.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", josev4.JSONWebKey{Key: &f.dpopKey.PublicKey}),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	htu := *r.URL
	htu.RawQuery = ""
	proof, err := jwt.Signed(signer).Claims(map[string]any{
		"jti": fmt.Sprintf("proof-%d", f.seq), "htm": r.Method, "htu": htu.String(),
		"iat": testNow.Unix(), "ath": dpop.AccessTokenHash(raw),
	}).Serialize()
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	r.Header.Set("DPoP", proof)
}

// newRequest builds a request to target (path plus query) on the issuer host.
func mgmtNewRequest(method, target, body string) *http.Request {
	return httptest.NewRequestWithContext(context.Background(), method, testIssuer+target, strings.NewReader(body))
}

// do sends a request as rp-a holding a JWT with scope.
func (f *mgmtFixture) do(t *testing.T, scope []string, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.doAs(t, mgmtJWT, mgmtClientA, scope, method, target, body)
}

func (f *mgmtFixture) doAs(t *testing.T, form mgmtTokenForm, clientID string, scope []string, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := mgmtNewRequest(method, target, body)
	f.authorizeRequest(t, r, form, f.token(t, form, clientID, scope, nil))
	return f.serve(r)
}

func (f *mgmtFixture) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

var (
	mgmtScopeManage = []string{ScopeManage}
	mgmtScopeRead   = []string{ScopeRead}
	mgmtScopeNone   = []string{"openid"}
)

func mgmtDecode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return m
}

func mgmtWantStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d; body %s", w.Code, want, w.Body.String())
	}
}

// mgmtCreate creates rp-a's stream from body and returns it as stored.
func (f *mgmtFixture) mgmtCreate(t *testing.T, body string) *store.SSFStream {
	t.Helper()
	w := f.do(t, mgmtScopeManage, http.MethodPost, mgmtStreamsPath, body)
	mgmtWantStatus(t, w, http.StatusCreated)
	s, err := f.st.SSFStreams().GetByClient(context.Background(), mgmtClientA)
	if err != nil {
		t.Fatalf("GetByClient: %v", err)
	}
	return s
}

func (f *mgmtFixture) stream(t *testing.T, id string) *store.SSFStream {
	t.Helper()
	s, err := f.st.SSFStreams().Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get %q: %v", id, err)
	}
	return s
}

// mgmtPendingTypes returns the event type of every pending poll SET of
// streamID, with the stream-updated status appended after a colon.
func mgmtPendingTypes(t *testing.T, st *inmem.Store, streamID string) []string {
	t.Helper()
	evs := pendingEvents(t, st, streamID)
	out := make([]string, 0, len(evs))
	for _, ev := range evs {
		et, payload := eventMember(t, decodeClaims(t, ev.Claims))
		if et == string(EventStreamUpdated) {
			et += ":" + payload["status"].(string)
		}
		out = append(out, et)
	}
	slices.Sort(out)
	return out
}

// mgmtAuthzRow is one row of the pairwise authorization suite.
type mgmtAuthzRow struct {
	scope string // none | read | manage
	owner string // own | other | none
	op    string // create | get | patch | put | delete | status-set | verify
	form  mgmtTokenForm
}

// mgmtAuthzRows covers every pair of scope × ownership × operation ×
// token form (3 × 3 × 7 × 3 levels) in 21 rows. The (scope, ownership,
// form) triples are the 9-row orthogonal array form = (scope + owner)
// mod 3, split into three classes by (scope + 2·owner) mod 3; each class
// holds every level of each of the three factors once, so giving each
// operation one whole class covers its pairs with all three factors.
//
//	class 0: (none,own,jwt) (read,other,dpop) (manage,none,opaque)   → create, put, verify
//	class 1: (none,none,dpop) (read,own,opaque) (manage,other,jwt)   → get, delete
//	class 2: (none,other,opaque) (read,none,jwt) (manage,own,dpop)   → patch, status-set
//
// TestMgmtAuthzRowsArePairwise checks the coverage mechanically.
var mgmtAuthzRows = []mgmtAuthzRow{
	{"none", "own", "create", mgmtJWT},
	{"read", "other", "create", mgmtDPoP},
	{"manage", "none", "create", mgmtOpaque},
	{"none", "none", "get", mgmtDPoP},
	{"read", "own", "get", mgmtOpaque},
	{"manage", "other", "get", mgmtJWT},
	{"none", "other", "patch", mgmtOpaque},
	{"read", "none", "patch", mgmtJWT},
	{"manage", "own", "patch", mgmtDPoP},
	{"none", "own", "put", mgmtJWT},
	{"read", "other", "put", mgmtDPoP},
	{"manage", "none", "put", mgmtOpaque},
	{"none", "none", "delete", mgmtDPoP},
	{"read", "own", "delete", mgmtOpaque},
	{"manage", "other", "delete", mgmtJWT},
	{"none", "other", "status-set", mgmtOpaque},
	{"read", "none", "status-set", mgmtJWT},
	{"manage", "own", "status-set", mgmtDPoP},
	{"none", "own", "verify", mgmtJWT},
	{"read", "other", "verify", mgmtDPoP},
	{"manage", "none", "verify", mgmtOpaque},
}

func TestMgmtAuthzRowsArePairwise(t *testing.T) {
	t.Parallel()
	factors := []func(mgmtAuthzRow) string{
		func(r mgmtAuthzRow) string { return r.scope },
		func(r mgmtAuthzRow) string { return r.owner },
		func(r mgmtAuthzRow) string { return r.op },
		func(r mgmtAuthzRow) string { return r.form.String() },
	}
	levels := [][]string{
		{"none", "read", "manage"},
		{"own", "other", "none"},
		{"create", "get", "patch", "put", "delete", "status-set", "verify"},
		{"jwt", "opaque", "dpop"},
	}
	seen := map[string]bool{}
	for _, r := range mgmtAuthzRows {
		for i := range factors {
			for j := i + 1; j < len(factors); j++ {
				seen[fmt.Sprintf("%d=%s,%d=%s", i, factors[i](r), j, factors[j](r))] = true
			}
		}
	}
	for i := range levels {
		for j := i + 1; j < len(levels); j++ {
			for _, a := range levels[i] {
				for _, b := range levels[j] {
					if !seen[fmt.Sprintf("%d=%s,%d=%s", i, a, j, b)] {
						t.Errorf("pair (%s, %s) of factors %d and %d is not covered", a, b, i, j)
					}
				}
			}
		}
	}
}

// mgmtAuthzWant is the expected status: scope gates first (403), then
// ownership (404 for another receiver's or a missing stream; 409 for a
// second create).
func mgmtAuthzWant(r mgmtAuthzRow) int {
	need := "manage"
	if r.op == "get" {
		need = "read"
	}
	if r.scope == "none" || (need == "manage" && r.scope == "read") {
		return http.StatusForbidden
	}
	if r.op == "create" {
		if r.owner == "own" {
			return http.StatusConflict
		}
		return http.StatusCreated
	}
	if r.owner != "own" {
		return http.StatusNotFound
	}
	switch r.op {
	case "delete", "verify":
		return http.StatusNoContent
	}
	return http.StatusOK
}

func TestMgmtAuthorizationPairwise(t *testing.T) {
	t.Parallel()
	for _, row := range mgmtAuthzRows {
		name := fmt.Sprintf("%s/%s/%s/%s", row.op, row.scope, row.owner, row.form)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newMgmtFixture(t)
			target := "missing-stream"
			switch row.owner {
			case "own":
				target = seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll).ID
			case "other":
				target = seedStream(t, f.st, mgmtClientB, store.SSFStreamEnabled, store.SSFDeliveryPoll).ID
			}
			scope := map[string][]string{"none": mgmtScopeNone, "read": mgmtScopeRead, "manage": mgmtScopeManage}[row.scope]
			idQuery := "?stream_id=" + url.QueryEscape(target)
			idBody := fmt.Sprintf(`{"stream_id":%q}`, target)
			var method, path, body string
			switch row.op {
			case "create":
				method, path, body = http.MethodPost, mgmtStreamsPath, `{}`
			case "get":
				method, path = http.MethodGet, mgmtStreamsPath+idQuery
			case "patch":
				method, path, body = http.MethodPatch, mgmtStreamsPath, fmt.Sprintf(`{"stream_id":%q,"description":"x"}`, target)
			case "put":
				method, path, body = http.MethodPut, mgmtStreamsPath, idBody
			case "delete":
				method, path = http.MethodDelete, mgmtStreamsPath+idQuery
			case "status-set":
				method, path, body = http.MethodPost, mgmtStatusPath, fmt.Sprintf(`{"stream_id":%q,"status":"paused"}`, target)
			case "verify":
				method, path, body = http.MethodPost, mgmtVerifyPath, idBody
			}
			w := f.doAs(t, row.form, mgmtClientA, scope, method, path, body)
			want := mgmtAuthzWant(row)
			mgmtWantStatus(t, w, want)
			if want == http.StatusForbidden {
				got := w.Header().Get("WWW-Authenticate")
				if !strings.Contains(got, `error="insufficient_scope"`) {
					t.Errorf("WWW-Authenticate = %q, want insufficient_scope", got)
				}
			}
			if row.owner == "other" {
				// Another receiver's stream is never touched.
				s := f.stream(t, target)
				if s.Description != "" || s.Status != store.SSFStreamEnabled {
					t.Errorf("other receiver's stream changed: %+v", s)
				}
			}
		})
	}
}

func TestMgmtAuthRejections(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)

	w := f.serve(mgmtNewRequest(http.MethodGet, mgmtStreamsPath, ""))
	mgmtWantStatus(t, w, http.StatusUnauthorized)
	if got := w.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("bare challenge = %q, want Bearer", got)
	}

	for name, edit := range map[string]func(*tokens.AccessTokenClaims){
		"resource audience": func(c *tokens.AccessTokenClaims) { c.Audience = []string{"https://rs.example.com"} },
		"no audience":       func(c *tokens.AccessTokenClaims) { c.Audience = nil },
		"no client_id":      func(c *tokens.AccessTokenClaims) { c.ClientID = "" },
	} {
		r := mgmtNewRequest(http.MethodGet, mgmtStreamsPath, "")
		f.authorizeRequest(t, r, mgmtJWT, f.token(t, mgmtJWT, mgmtClientA, mgmtScopeManage, edit))
		w := f.serve(r)
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Errorf("%s: status %d, WWW-Authenticate %q", name, w.Code, w.Header().Get("WWW-Authenticate"))
		}
	}

	w = f.do(t, mgmtScopeRead, http.MethodPost, mgmtStreamsPath, `{}`)
	mgmtWantStatus(t, w, http.StatusForbidden)
	want := `Bearer error="insufficient_scope", error_description="The access token lacks the required scope", scope="ssf.manage"`
	if got := w.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}

	w = f.doAs(t, mgmtDPoP, mgmtClientA, mgmtScopeNone, http.MethodGet, mgmtStreamsPath, "")
	mgmtWantStatus(t, w, http.StatusForbidden)
	if got := w.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "DPoP ") || !strings.Contains(got, `scope="ssf.read"`) {
		t.Errorf("DPoP insufficient_scope challenge = %q", got)
	}

	w = f.do(t, mgmtScopeManage, http.MethodOptions, mgmtStreamsPath, "")
	mgmtWantStatus(t, w, http.StatusMethodNotAllowed)
}

// TestMgmtRejectsUserDelegatedTokens pins that only a token the receiver
// obtained for itself (client_credentials) reaches any SSF endpoint: a
// code-flow token carrying ssf.manage, JWT or opaque, is invalid_token.
func TestMgmtRejectsUserDelegatedTokens(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	s := f.mgmtCreate(t, `{}`)
	streamQuery := "?stream_id=" + url.QueryEscape(s.ID)
	idBody := fmt.Sprintf(`{"stream_id":%q}`, s.ID)
	requests := map[string]func() *http.Request{
		"streams get":   func() *http.Request { return mgmtNewRequest(http.MethodGet, mgmtStreamsPath, "") },
		"streams patch": func() *http.Request { return mgmtNewRequest(http.MethodPatch, mgmtStreamsPath, idBody) },
		"status set": func() *http.Request {
			return mgmtNewRequest(http.MethodPost, mgmtStatusPath, fmt.Sprintf(`{"stream_id":%q,"status":"paused"}`, s.ID))
		},
		"status get": func() *http.Request { return mgmtNewRequest(http.MethodGet, mgmtStatusPath+streamQuery, "") },
		"verify":     func() *http.Request { return mgmtNewRequest(http.MethodPost, mgmtVerifyPath, idBody) },
		"poll":       func() *http.Request { return mgmtNewRequest(http.MethodPost, "/ssf/poll/"+s.ID, `{}`) },
	}
	userCode := func(c *tokens.AccessTokenClaims) { c.Subject, c.GrantID = "alice", "grant-alice" }
	clientGrant := func(c *tokens.AccessTokenClaims) { c.GrantID = "grant-" + mgmtClientA }
	opaque := &store.OpaqueAccessToken{
		ID: "opaque-user", GrantID: "grant-alice", ClientID: mgmtClientA, Subject: "alice",
		Scope: mgmtScopeManage, Audience: testIssuer,
		IssuedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Hour),
	}
	if err := f.st.OpaqueAccessTokens().Save(context.Background(), opaque); err != nil {
		t.Fatalf("Save opaque: %v", err)
	}
	for name, newReq := range requests {
		for tokenName, raw := range map[string]string{
			"user jwt":         f.token(t, mgmtJWT, mgmtClientA, mgmtScopeManage, userCode),
			"grant-backed jwt": f.token(t, mgmtJWT, mgmtClientA, mgmtScopeManage, clientGrant),
			"user opaque":      opaque.ID,
		} {
			r := newReq()
			f.authorizeRequest(t, r, mgmtJWT, raw)
			w := f.serve(r)
			if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
				t.Errorf("%s with %s: status %d, WWW-Authenticate %q", name, tokenName, w.Code, w.Header().Get("WWW-Authenticate"))
			}
		}
	}
	if got := f.stream(t, s.ID); got.Status != store.SSFStreamEnabled {
		t.Errorf("stream status = %q after rejected requests, want enabled", got.Status)
	}
}

func TestMgmtCreateEdges(t *testing.T) {
	t.Parallel()
	session := string(EventSessionRevoked)
	cases := []struct {
		name   string
		opts   []mgmtOption
		body   string
		status int
		check  func(t *testing.T, s *store.SSFStream)
	}{
		{name: "empty body is a poll stream", body: "", status: http.StatusCreated, check: mgmtWantPoll},
		{name: "empty object is a poll stream", body: `{}`, status: http.StatusCreated, check: mgmtWantPoll},
		{name: "malformed JSON", body: `{"description":`, status: http.StatusBadRequest},
		{name: "trailing data", body: `{} {}`, status: http.StatusBadRequest},
		{name: "not an object", body: `[]`, status: http.StatusBadRequest},
		{name: "unknown member ignored", body: `{"x-vendor":1,"min_verification_interval":30}`, status: http.StatusCreated, check: mgmtWantPoll},
		{
			name: "empty events_requested", body: `{"events_requested":[]}`, status: http.StatusCreated,
			check: mgmtWantDelivered(),
		},
		{
			name: "unknown event URIs only", body: `{"events_requested":["urn:example:unknown"]}`, status: http.StatusCreated,
			check: mgmtWantDelivered(),
		},
		{
			name: "delivered is supported ∩ requested", status: http.StatusCreated,
			body:  fmt.Sprintf(`{"events_requested":["urn:example:unknown",%q,%q]}`, string(EventAccountPurged), session),
			check: mgmtWantDelivered(session, string(EventAccountPurged)),
		},
		{name: "events_requested not strings", body: `{"events_requested":[1]}`, status: http.StatusBadRequest},
		{name: "unknown delivery method", body: `{"delivery":{"method":"urn:example:carrier-pigeon"}}`, status: http.StatusBadRequest},
		{name: "delivery without method", body: `{"delivery":{}}`, status: http.StatusBadRequest},
		{name: "push without endpoint_url", body: `{"delivery":{"method":"urn:ietf:rfc:8935"}}`, status: http.StatusBadRequest},
		{name: "push over http", body: mgmtPushBody("http://rp.example.com/ssf", ""), status: http.StatusBadRequest},
		{
			name: "push over http with dev flag", opts: []mgmtOption{mgmtWithDev}, status: http.StatusCreated,
			body: mgmtPushBody("http://rp.example.com/ssf", ""),
		},
		{name: "push with fragment", body: mgmtPushBody("https://rp.example.com/ssf#x", ""), status: http.StatusBadRequest},
		{name: "push with userinfo", body: mgmtPushBody("https://u:p@rp.example.com/ssf", ""), status: http.StatusBadRequest},
		{name: "push relative URL", body: mgmtPushBody("/ssf", ""), status: http.StatusBadRequest},
		{name: "push private IP literal", body: mgmtPushBody("https://10.0.0.5/ssf", ""), status: http.StatusBadRequest},
		{name: "push loopback literal", body: mgmtPushBody("https://127.0.0.1/ssf", ""), status: http.StatusBadRequest},
		{name: "push localhost", body: mgmtPushBody("https://localhost/ssf", ""), status: http.StatusBadRequest},
		{
			name: "push loopback with dev flag", opts: []mgmtOption{mgmtWithDev}, status: http.StatusCreated,
			body: mgmtPushBody("http://127.0.0.1:8080/ssf", ""),
		},
		{
			name: "push private IP with private-network flag", opts: []mgmtOption{mgmtWithPrivate}, status: http.StatusCreated,
			body: mgmtPushBody("https://10.0.0.5/ssf", ""),
		},
		{
			name: "cloud metadata refused under every flag", opts: []mgmtOption{mgmtWithPrivate, mgmtWithDev},
			body: mgmtPushBody("http://169.254.169.254/latest", ""), status: http.StatusBadRequest,
		},
		{
			name: "authorization_header at 4 KiB", status: http.StatusCreated,
			body: mgmtPushBody("https://rp.example.com/ssf", strings.Repeat("a", mgmtMaxAuthzHeader)),
		},
		{
			name: "authorization_header over 4 KiB", status: http.StatusBadRequest,
			body: mgmtPushBody("https://rp.example.com/ssf", strings.Repeat("a", mgmtMaxAuthzHeader+1)),
		},
		{
			name: "authorization_header with CRLF", status: http.StatusBadRequest,
			body: mgmtPushBody("https://rp.example.com/ssf", "Bearer x\r\nX-Injected: 1"),
		},
		{
			name: "description over 256 characters is truncated", status: http.StatusCreated,
			body: fmt.Sprintf(`{"description":%q}`, strings.Repeat("あ", 300)),
			check: func(t *testing.T, s *store.SSFStream) {
				if s.Description != strings.Repeat("あ", 256) {
					t.Errorf("description has %d runes, want 256", len([]rune(s.Description)))
				}
			},
		},
		{
			name: "non-ASCII description kept verbatim", status: http.StatusCreated,
			body: `{"description":"受信側 ストリーム"}`,
			check: func(t *testing.T, s *store.SSFStream) {
				if s.Description != "受信側 ストリーム" {
					t.Errorf("description = %q", s.Description)
				}
			},
		},
		{name: "description not a string", body: `{"description":5}`, status: http.StatusBadRequest},
		{
			name: "body over 64 KiB", status: http.StatusRequestEntityTooLarge,
			body: fmt.Sprintf(`{"description":%q}`, strings.Repeat("a", mgmtMaxBody)),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newMgmtFixture(t, tc.opts...)
			w := f.do(t, mgmtScopeManage, http.MethodPost, mgmtStreamsPath, tc.body)
			mgmtWantStatus(t, w, tc.status)
			if tc.status != http.StatusCreated {
				if _, err := f.st.SSFStreams().GetByClient(context.Background(), mgmtClientA); err == nil {
					t.Error("a rejected create stored a stream")
				}
				return
			}
			s, err := f.st.SSFStreams().GetByClient(context.Background(), mgmtClientA)
			if err != nil {
				t.Fatalf("GetByClient: %v", err)
			}
			if tc.check != nil {
				tc.check(t, s)
			}
		})
	}
}

func mgmtPushBody(endpoint, header string) string {
	d := map[string]any{"method": DeliveryURNPush, "endpoint_url": endpoint}
	if header != "" {
		d["authorization_header"] = header
	}
	b, _ := json.Marshal(map[string]any{"delivery": d})
	return string(b)
}

func mgmtWantPoll(t *testing.T, s *store.SSFStream) {
	t.Helper()
	if s.Delivery.Method != store.SSFDeliveryPoll || s.Delivery.EndpointURL != "" {
		t.Errorf("delivery = %+v, want poll", s.Delivery)
	}
	if s.Status != store.SSFStreamEnabled {
		t.Errorf("status = %q, want enabled", s.Status)
	}
}

func mgmtWantDelivered(want ...string) func(*testing.T, *store.SSFStream) {
	return func(t *testing.T, s *store.SSFStream) {
		t.Helper()
		if !slices.Equal(s.EventsDelivered, want) && (len(want) != 0 || len(s.EventsDelivered) != 0) {
			t.Errorf("events_delivered = %v, want %v", s.EventsDelivered, want)
		}
	}
}

func TestMgmtCreateSecondStreamConflicts(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	f.mgmtCreate(t, `{}`)
	mgmtWantStatus(t, f.do(t, mgmtScopeManage, http.MethodPost, mgmtStreamsPath, `{}`), http.StatusConflict)
	// Another receiver still gets its own stream.
	w := f.doAs(t, mgmtJWT, mgmtClientB, mgmtScopeManage, http.MethodPost, mgmtStreamsPath, `{}`)
	mgmtWantStatus(t, w, http.StatusCreated)
}

func TestMgmtCreatePushSealsHeaderAndQueuesVerification(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	const header = "Bearer receiver-secret"
	w := f.do(t, mgmtScopeManage, http.MethodPost, mgmtStreamsPath,
		mgmtPushBody("https://rp.example.com/ssf", header))
	mgmtWantStatus(t, w, http.StatusCreated)
	if strings.Contains(w.Body.String(), "authorization_header") || strings.Contains(w.Body.String(), "receiver-secret") {
		t.Errorf("response exposes the authorization header: %s", w.Body.String())
	}
	got := mgmtDecode(t, w)
	s := f.stream(t, got["stream_id"].(string))
	if got["iss"] != testIssuer || got["aud"] != mgmtClientA {
		t.Errorf("iss/aud = %v/%v", got["iss"], got["aud"])
	}
	if d := got["delivery"].(map[string]any); d["method"] != DeliveryURNPush || d["endpoint_url"] != "https://rp.example.com/ssf" {
		t.Errorf("delivery = %v", d)
	}
	if len(got["events_supported"].([]any)) != len(SupportedEvents()) {
		t.Errorf("events_supported = %v", got["events_supported"])
	}
	plain, err := f.sealer.Unseal(s.ID, s.Delivery.SealedAuthorizationHeader)
	if err != nil || plain != header {
		t.Fatalf("Unseal = %q, %v; want the header", plain, err)
	}
	if strings.Contains(string(s.Delivery.SealedAuthorizationHeader), "receiver-secret") {
		t.Error("stored header is not sealed")
	}

	evs, err := f.st.SSFEvents().ClaimDue(context.Background(), testNow, 10, time.Minute)
	if err != nil || len(evs) != 1 {
		t.Fatalf("ClaimDue = %d events, %v; want the creation verification", len(evs), err)
	}
	if evs[0].Kind != store.SSFEventKindVerification || evs[0].Delivery != store.SSFDeliveryPush {
		t.Errorf("queued event = %+v", evs[0])
	}
	et, payload := eventMember(t, decodeClaims(t, evs[0].Claims))
	if et != string(EventVerification) || payload["state"] != nil {
		t.Errorf("verification = %s %v, want no state", et, payload)
	}
	if n := len(f.rec.named(string(auditevent.AuditSSFStreamCreated))); n != 1 {
		t.Errorf("stream.created events = %d, want 1", n)
	}
}

func TestMgmtCreatePollAdvertisesPollEndpoint(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	w := f.do(t, mgmtScopeManage, http.MethodPost, mgmtStreamsPath, `{"delivery":{"method":"urn:ietf:rfc:8936","endpoint_url":"https://ignored.example"}}`)
	mgmtWantStatus(t, w, http.StatusCreated)
	got := mgmtDecode(t, w)
	id := got["stream_id"].(string)
	if d := got["delivery"].(map[string]any); d["method"] != DeliveryURNPoll || d["endpoint_url"] != mgmtPollBase+"/"+id {
		t.Errorf("delivery = %v", d)
	}
	if types := mgmtPendingTypes(t, f.st, id); !slices.Equal(types, []string{string(EventVerification)}) {
		t.Errorf("pending = %v, want the creation verification", types)
	}
}

func TestMgmtRead(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	w := f.do(t, mgmtScopeRead, http.MethodGet, mgmtStreamsPath, "")
	mgmtWantStatus(t, w, http.StatusOK)
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("no stream: body %s, want []", w.Body.String())
	}
	own := f.mgmtCreate(t, `{"description":"mine"}`)
	other := seedStream(t, f.st, mgmtClientB, store.SSFStreamEnabled, store.SSFDeliveryPoll)

	w = f.do(t, mgmtScopeRead, http.MethodGet, mgmtStreamsPath, "")
	var list []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0]["stream_id"] != own.ID {
		t.Fatalf("list = %s (%v), want only the caller's stream", w.Body.String(), err)
	}
	w = f.do(t, mgmtScopeRead, http.MethodGet, mgmtStreamsPath+"?stream_id="+own.ID, "")
	mgmtWantStatus(t, w, http.StatusOK)
	if got := mgmtDecode(t, w); got["description"] != "mine" {
		t.Errorf("read = %v", got)
	}
	mgmtWantStatus(t, f.do(t, mgmtScopeRead, http.MethodGet, mgmtStreamsPath+"?stream_id="+other.ID, ""), http.StatusNotFound)
	mgmtWantStatus(t, f.do(t, mgmtScopeRead, http.MethodGet, mgmtStreamsPath+"?stream_id=nope", ""), http.StatusNotFound)
}

func TestMgmtUpdateEdges(t *testing.T) {
	t.Parallel()
	session, purged := string(EventSessionRevoked), string(EventAccountPurged)
	const header = "Bearer receiver-secret"
	push := fmt.Sprintf(`{"description":"d","events_requested":[%q],"delivery":{"method":%q,"endpoint_url":"https://rp.example.com/a","authorization_header":%q}}`,
		session, DeliveryURNPush, header)
	cases := []struct {
		name   string
		method string
		body   string // %s is the stream_id
		status int
		check  func(t *testing.T, f *mgmtFixture, s *store.SSFStream)
	}{
		{
			// The sealed header was supplied for /a and never follows the stream to /b.
			name: "PATCH endpoint_url without authorization_header refused", method: http.MethodPatch, status: http.StatusBadRequest,
			body: `{"stream_id":%q,"delivery":{"endpoint_url":"https://rp.example.com/b"}}`,
		},
		{
			name: "PATCH endpoint_url with a new authorization_header", method: http.MethodPatch, status: http.StatusOK,
			body: `{"stream_id":%q,"delivery":{"endpoint_url":"https://rp.example.com/b","authorization_header":"Bearer other"}}`,
			check: func(t *testing.T, f *mgmtFixture, s *store.SSFStream) {
				if s.Delivery.EndpointURL != "https://rp.example.com/b" || s.Delivery.Method != store.SSFDeliveryPush {
					t.Errorf("delivery = %+v", s.Delivery)
				}
				if plain, err := f.sealer.Unseal(s.ID, s.Delivery.SealedAuthorizationHeader); err != nil || plain != "Bearer other" {
					t.Errorf("header = %q, %v; want the new one", plain, err)
				}
				if s.Description != "d" || !slices.Equal(s.EventsRequested, []string{session}) {
					t.Errorf("omitted members changed: %+v", s)
				}
			},
		},
		{
			name: "PATCH unchanged endpoint_url keeps the header", method: http.MethodPatch, status: http.StatusOK,
			body: `{"stream_id":%q,"delivery":{"endpoint_url":"https://rp.example.com/a"}}`,
			check: func(t *testing.T, f *mgmtFixture, s *store.SSFStream) {
				if plain, err := f.sealer.Unseal(s.ID, s.Delivery.SealedAuthorizationHeader); err != nil || plain != header {
					t.Errorf("header = %q, %v; want kept", plain, err)
				}
			},
		},
		{
			name: "PUT without authorization_header drops it", method: http.MethodPut, status: http.StatusOK,
			body: `{"stream_id":%q,"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://rp.example.com/a"}}`,
			check: func(t *testing.T, _ *mgmtFixture, s *store.SSFStream) {
				if s.Delivery.SealedAuthorizationHeader != nil {
					t.Error("PUT kept the sealed header")
				}
				if s.Description != "" || len(s.EventsRequested) != 0 || len(s.EventsDelivered) != 0 {
					t.Errorf("PUT kept omitted members: %+v", s)
				}
			},
		},
		{
			name: "PUT without delivery makes a poll stream", method: http.MethodPut, status: http.StatusOK,
			body: `{"stream_id":%q}`,
			check: func(t *testing.T, _ *mgmtFixture, s *store.SSFStream) {
				if !mgmtIsBarePoll(s.Delivery) {
					t.Errorf("delivery = %+v", s.Delivery)
				}
			},
		},
		{
			name: "PATCH events_requested recomputes delivered", method: http.MethodPatch, status: http.StatusOK,
			body: `{"stream_id":%q,"events_requested":["` + purged + `","urn:example:x"]}`,
			check: func(t *testing.T, _ *mgmtFixture, s *store.SSFStream) {
				if !slices.Equal(s.EventsDelivered, []string{purged}) {
					t.Errorf("events_delivered = %v", s.EventsDelivered)
				}
			},
		},
		{
			name: "PUT events_requested recomputes delivered", method: http.MethodPut, status: http.StatusOK,
			body: `{"stream_id":%q,"events_requested":["` + purged + `","` + session + `"]}`,
			check: func(t *testing.T, _ *mgmtFixture, s *store.SSFStream) {
				if !slices.Equal(s.EventsDelivered, []string{session, purged}) {
					t.Errorf("events_delivered = %v", s.EventsDelivered)
				}
			},
		},
		{
			name: "PATCH description only", method: http.MethodPatch, status: http.StatusOK,
			body: `{"stream_id":%q,"description":"new"}`,
			check: func(t *testing.T, _ *mgmtFixture, s *store.SSFStream) {
				if s.Description != "new" || s.Delivery.EndpointURL != "https://rp.example.com/a" {
					t.Errorf("stream = %+v", s)
				}
			},
		},
		{
			name: "events_delivered equal to the current value", method: http.MethodPatch, status: http.StatusOK,
			body: `{"stream_id":%q,"events_delivered":["` + session + `"]}`,
		},
		{name: "events_delivered differs (PATCH)", method: http.MethodPatch, status: http.StatusBadRequest, body: `{"stream_id":%q,"events_delivered":[]}`},
		{name: "events_delivered differs (PUT)", method: http.MethodPut, status: http.StatusBadRequest, body: `{"stream_id":%q,"events_delivered":["` + purged + `"]}`},
		{name: "iss changed", method: http.MethodPatch, status: http.StatusBadRequest, body: `{"stream_id":%q,"iss":"https://evil.example"}`},
		{name: "aud changed", method: http.MethodPatch, status: http.StatusBadRequest, body: `{"stream_id":%q,"aud":"rp-b"}`},
		{name: "aud as array of another", method: http.MethodPut, status: http.StatusBadRequest, body: `{"stream_id":%q,"aud":["rp-a","rp-b"]}`},
		{name: "aud unchanged", method: http.MethodPatch, status: http.StatusOK, body: `{"stream_id":%q,"aud":"rp-a","iss":"` + testIssuer + `"}`},
		{name: "stream_id missing", method: http.MethodPatch, status: http.StatusBadRequest, body: `{"description":"x"%.0s}`},
		{name: "unknown stream_id", method: http.MethodPatch, status: http.StatusNotFound, body: `{"stream_id":"x%.0s"}`},
		{name: "malformed JSON", method: http.MethodPut, status: http.StatusBadRequest, body: `{"stream_id":%q`},
		{name: "unknown delivery method", method: http.MethodPatch, status: http.StatusBadRequest, body: `{"stream_id":%q,"delivery":{"method":"urn:x"}}`},
		{
			name: "PATCH push to poll is accepted", method: http.MethodPatch, status: http.StatusOK,
			body: `{"stream_id":%q,"delivery":{"method":"urn:ietf:rfc:8936"}}`,
			check: func(t *testing.T, f *mgmtFixture, s *store.SSFStream) {
				if !mgmtIsBarePoll(s.Delivery) {
					t.Errorf("delivery = %+v", s.Delivery)
				}
				// The update moved the queued creation verification to poll.
				if types := mgmtPendingTypes(t, f.st, s.ID); !slices.Equal(types, []string{string(EventVerification)}) {
					t.Errorf("pending after retag = %v", types)
				}
			},
		},
		{
			name: "PATCH http endpoint refused", method: http.MethodPatch, status: http.StatusBadRequest,
			body: `{"stream_id":%q,"delivery":{"endpoint_url":"http://rp.example.com/a"}}`,
		},
		{
			name: "PATCH empty authorization_header drops it", method: http.MethodPatch, status: http.StatusOK,
			body: `{"stream_id":%q,"delivery":{"authorization_header":""}}`,
			check: func(t *testing.T, _ *mgmtFixture, s *store.SSFStream) {
				if s.Delivery.SealedAuthorizationHeader != nil {
					t.Error("header kept")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newMgmtFixture(t)
			s := f.mgmtCreate(t, push)
			w := f.do(t, mgmtScopeManage, tc.method, mgmtStreamsPath, fmt.Sprintf(tc.body, s.ID))
			mgmtWantStatus(t, w, tc.status)
			after := f.stream(t, s.ID)
			if tc.status != http.StatusOK {
				if after.Description != s.Description || after.Delivery.EndpointURL != s.Delivery.EndpointURL ||
					!slices.Equal(after.Delivery.SealedAuthorizationHeader, s.Delivery.SealedAuthorizationHeader) {
					t.Errorf("rejected update changed the stream: %+v", after)
				}
				return
			}
			if strings.Contains(w.Body.String(), "receiver-secret") {
				t.Errorf("response exposes the header: %s", w.Body.String())
			}
			if tc.check != nil {
				tc.check(t, f, after)
			}
			if n := len(f.rec.named(string(auditevent.AuditSSFStreamUpdated))); n != 1 {
				t.Errorf("stream.updated events = %d, want 1", n)
			}
		})
	}
}

func TestMgmtPatchMethodChangeRetagsHeldEvents(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	seedReceiver(t, f.st, mgmtClientA, "alice")
	s := seedStream(t, f.st, mgmtClientA, store.SSFStreamPaused, store.SSFDeliveryPush, EventSessionRevoked)
	if _, err := f.tx.Publish(context.Background(), EventSessionRevoked, "alice", Fields{}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	w := f.do(t, mgmtScopeManage, http.MethodPatch, mgmtStreamsPath,
		fmt.Sprintf(`{"stream_id":%q,"delivery":{"method":%q}}`, s.ID, DeliveryURNPoll))
	mgmtWantStatus(t, w, http.StatusOK)
	// The event moved to poll and stays held while the stream is paused.
	if types := mgmtPendingTypes(t, f.st, s.ID); len(types) != 0 {
		t.Errorf("pending while paused = %v, want none", types)
	}
	mgmtWantStatus(t, f.do(t, mgmtScopeManage, http.MethodPost, mgmtStatusPath,
		fmt.Sprintf(`{"stream_id":%q,"status":"enabled"}`, s.ID)), http.StatusOK)
	want := []string{string(EventSessionRevoked), string(EventStreamUpdated) + ":enabled"}
	slices.Sort(want)
	if types := mgmtPendingTypes(t, f.st, s.ID); !slices.Equal(types, want) {
		t.Errorf("pending after enable = %v, want %v", types, want)
	}
}

func TestMgmtDelete(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	s := f.mgmtCreate(t, `{}`)
	mgmtWantStatus(t, f.do(t, mgmtScopeManage, http.MethodDelete, mgmtStreamsPath, ""), http.StatusBadRequest)
	w := f.do(t, mgmtScopeManage, http.MethodDelete, mgmtStreamsPath+"?stream_id="+s.ID, "")
	mgmtWantStatus(t, w, http.StatusNoContent)
	if w.Body.Len() != 0 {
		t.Errorf("204 body = %q", w.Body.String())
	}
	if _, err := f.st.SSFStreams().Get(context.Background(), s.ID); err == nil {
		t.Error("stream survives delete")
	}
	if evs := pendingEvents(t, f.st, s.ID); len(evs) != 0 {
		t.Errorf("queue survives delete: %d events", len(evs))
	}
	if n := len(f.rec.named(string(auditevent.AuditSSFStreamDeleted))); n != 1 {
		t.Errorf("stream.deleted events = %d, want 1", n)
	}
	mgmtWantStatus(t, f.do(t, mgmtScopeManage, http.MethodDelete, mgmtStreamsPath+"?stream_id="+s.ID, ""), http.StatusNotFound)
	// The receiver may create a new stream afterwards.
	f.mgmtCreate(t, `{}`)
}

func TestMgmtStatusTransitions(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	ctx := context.Background()
	seedReceiver(t, f.st, mgmtClientA, "alice")
	s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked)
	publish := func() {
		t.Helper()
		if _, err := f.tx.Publish(ctx, EventSessionRevoked, "alice", Fields{}); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	setStatus := func(status, reason string) map[string]any {
		t.Helper()
		w := f.do(t, mgmtScopeManage, http.MethodPost, mgmtStatusPath,
			fmt.Sprintf(`{"stream_id":%q,"status":%q,"reason":%q}`, s.ID, status, reason))
		mgmtWantStatus(t, w, http.StatusOK)
		return mgmtDecode(t, w)
	}
	pending := func(want ...string) {
		t.Helper()
		slices.Sort(want)
		if got := mgmtPendingTypes(t, f.st, s.ID); !slices.Equal(got, want) {
			t.Errorf("pending = %v, want %v", got, want)
		}
	}
	revoked := string(EventSessionRevoked)
	updated := func(status string) string { return string(EventStreamUpdated) + ":" + status }

	publish()
	pending(revoked)

	got := setStatus("paused", "maintenance")
	if got["status"] != "paused" || got["reason"] != "maintenance" || got["stream_id"] != s.ID {
		t.Errorf("status response = %v", got)
	}
	publish()
	// Ordinary events are held; the stream-updated is not.
	pending(updated("paused"))
	if st := f.stream(t, s.ID); st.Status != store.SSFStreamPaused || st.StatusReason != "maintenance" {
		t.Errorf("stored status = %q/%q", st.Status, st.StatusReason)
	}

	setStatus("enabled", "")
	// A stream holds one stream-updated: the newest replaces the pending one.
	pending(revoked, revoked, updated("enabled"))

	setStatus("disabled", "")
	publish()
	// Ordinary events are dropped; the control events survive.
	pending(updated("disabled"))

	// Verification is still accepted and delivered while disabled.
	mgmtWantStatus(t, f.do(t, mgmtScopeManage, http.MethodPost, mgmtVerifyPath,
		fmt.Sprintf(`{"stream_id":%q,"state":"ping"}`, s.ID)), http.StatusNoContent)
	pending(updated("disabled"), string(EventVerification))

	// Setting the current status again queues no stream-updated.
	setStatus("disabled", "still off")
	pending(updated("disabled"), string(EventVerification))

	// Toggling the status never grows the queue past one stream-updated.
	for range 10 {
		setStatus("paused", "")
		setStatus("enabled", "")
	}
	pending(updated("enabled"), string(EventVerification))

	w := f.do(t, mgmtScopeRead, http.MethodGet, mgmtStatusPath+"?stream_id="+s.ID, "")
	mgmtWantStatus(t, w, http.StatusOK)
	if got := mgmtDecode(t, w); got["status"] != "enabled" {
		t.Errorf("GET status = %v", got)
	}
	if n := len(f.rec.named(string(auditevent.AuditSSFStreamUpdated))); n != 24 {
		t.Errorf("stream.updated events = %d, want 24", n)
	}
}

func TestMgmtStatusEdges(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	s := f.mgmtCreate(t, `{}`)
	for name, tc := range map[string]struct {
		method, target, body string
		status               int
	}{
		"GET without stream_id":  {http.MethodGet, mgmtStatusPath, "", http.StatusBadRequest},
		"GET unknown stream":     {http.MethodGet, mgmtStatusPath + "?stream_id=x", "", http.StatusNotFound},
		"unknown status":         {http.MethodPost, mgmtStatusPath, fmt.Sprintf(`{"stream_id":%q,"status":"asleep"}`, s.ID), http.StatusBadRequest},
		"missing status":         {http.MethodPost, mgmtStatusPath, fmt.Sprintf(`{"stream_id":%q}`, s.ID), http.StatusBadRequest},
		"reason not a string":    {http.MethodPost, mgmtStatusPath, fmt.Sprintf(`{"stream_id":%q,"status":"paused","reason":1}`, s.ID), http.StatusBadRequest},
		"POST without stream_id": {http.MethodPost, mgmtStatusPath, `{"status":"paused"}`, http.StatusBadRequest},
		"PUT not allowed":        {http.MethodPut, mgmtStatusPath, `{}`, http.StatusMethodNotAllowed},
	} {
		w := f.do(t, mgmtScopeManage, tc.method, tc.target, tc.body)
		if w.Code != tc.status {
			t.Errorf("%s: status %d, want %d (%s)", name, w.Code, tc.status, w.Body.String())
		}
	}
	if st := f.stream(t, s.ID); st.Status != store.SSFStreamEnabled {
		t.Errorf("status changed to %q", st.Status)
	}
}

func TestMgmtVerifyReplacesPending(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	s := f.mgmtCreate(t, `{}`)
	for _, state := range []string{"s1", "s2"} {
		w := f.do(t, mgmtScopeManage, http.MethodPost, mgmtVerifyPath, fmt.Sprintf(`{"stream_id":%q,"state":%q}`, s.ID, state))
		mgmtWantStatus(t, w, http.StatusNoContent)
	}
	evs := pendingEvents(t, f.st, s.ID)
	if len(evs) != 1 {
		t.Fatalf("pending = %d events, want the one latest verification", len(evs))
	}
	if _, payload := eventMember(t, decodeClaims(t, evs[0].Claims)); payload["state"] != "s2" {
		t.Errorf("state = %v, want s2", payload["state"])
	}
	mgmtWantStatus(t, f.do(t, mgmtScopeManage, http.MethodPost, mgmtVerifyPath, `{}`), http.StatusBadRequest)
	mgmtWantStatus(t, f.do(t, mgmtScopeManage, http.MethodPost, mgmtVerifyPath,
		fmt.Sprintf(`{"stream_id":%q,"state":7}`, s.ID)), http.StatusBadRequest)
	mgmtWantStatus(t, f.do(t, mgmtScopeManage, http.MethodGet, mgmtVerifyPath, ""), http.StatusMethodNotAllowed)
}

func TestNewHandlersRequiresDeps(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	base := HandlerDeps{
		Issuer:       testIssuer,
		Bearer:       endpointsupport.BearerDeps{Issuer: testIssuer},
		Streams:      f.st.SSFStreams(),
		Events:       f.st.SSFEvents(),
		Transmitter:  f.tx,
		Sealer:       f.sealer,
		PollEndpoint: mgmtPollBase,
		ActiveKey:    func() (SigningKey, error) { return f.setKey, nil },
	}
	if _, err := NewHandlers(base); err != nil {
		t.Fatalf("complete deps: %v", err)
	}
	for name, edit := range map[string]func(*HandlerDeps){
		"issuer":        func(d *HandlerDeps) { d.Issuer = "" },
		"bearer issuer": func(d *HandlerDeps) { d.Bearer.Issuer = "https://other.example" },
		"streams":       func(d *HandlerDeps) { d.Streams = nil },
		"events":        func(d *HandlerDeps) { d.Events = nil },
		"transmitter":   func(d *HandlerDeps) { d.Transmitter = nil },
		"sealer":        func(d *HandlerDeps) { d.Sealer = nil },
		"poll endpoint": func(d *HandlerDeps) { d.PollEndpoint = "" },
		"active key":    func(d *HandlerDeps) { d.ActiveKey = nil },
	} {
		d := base
		edit(&d)
		if _, err := NewHandlers(d); err == nil {
			t.Errorf("missing %s: NewHandlers succeeded", name)
		}
	}
}

// mgmtIsBarePoll reports a poll delivery with no push endpoint or header.
func mgmtIsBarePoll(d store.SSFDelivery) bool {
	return d.Method == store.SSFDeliveryPoll && d.EndpointURL == "" && d.SealedAuthorizationHeader == nil
}

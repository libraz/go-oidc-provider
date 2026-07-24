package backchannel_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func mustKey(tb testing.TB) (*ecdsa.PrivateKey, backchannel.SigningKey) {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	return priv, backchannel.SigningKey{KeyID: "sig-1", Signer: priv}
}

func fixedClock(t time.Time) timex.Clock {
	return timex.ClockFunc(func() time.Time { return t })
}

// TestSignLogoutToken_EmitsRequiredClaims pins the OpenID Connect
// Back-Channel Logout 1.0 §2.4 logout-token shape end-to-end. Every
// invariant the spec enumerates is asserted here so a regression that
// (a) drops one of the mandatory claims, (b) introduces a forbidden
// claim, or (c) silently swaps the JWT typ header surfaces locally
// rather than at certification time.
//
// Tracks (RFC + CVE class):
//   - OpenID Connect Back-Channel Logout 1.0 §2.4 — logout_token MUST
//     carry iss/aud/iat/exp/jti/events; sub OR sid (or both); typ
//     header MUST be "logout+jwt"; "nonce" MUST NOT be present.
//   - The "missing events claim" failure mode appeared in several
//     OPs that retrofitted back-channel logout — RPs that strictly
//     follow §2.4 (rightly) reject any token that lacks the events
//     map keyed by [backchannel.EventID]. There is no single CVE
//     because the failure is silent (RP just refuses to log the
//     user out) rather than a security bypass.
//   - The "nonce on logout_token" failure mode is the dangerous one:
//     a logout_token carrying a nonce can be misclassified as an
//     id_token by a permissive RP (RFC 8725 §3.11 "use a typ header
//     to discriminate JWT shapes"); pinning nonce-absence here is
//     part of the structural defence.
//   - The "typ=logout+jwt" header lets RPs key off the JWT type
//     before signature verification; conflating it with id_token
//     would make CVE-2024-10318-style nonce-binding bypasses
//     reachable from the back channel as well.
func TestSignLogoutToken_EmitsRequiredClaims(t *testing.T) {
	t.Parallel()
	priv, sk := mustKey(t)
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	tok, err := backchannel.SignLogoutToken(sk, backchannel.LogoutClaims{
		Issuer:    "https://op.example.com",
		Audience:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(2 * time.Minute).Unix(),
		Subject:   "user-123",
		SessionID: "sid-abc",
	})
	if err != nil {
		t.Fatalf("SignLogoutToken: %v", err)
	}
	parsed, err := jwt.ParseSigned(tok, allowedAlgs())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	claims := map[string]any{}
	if err := parsed.Claims(&priv.PublicKey, &claims); err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, key := range []string{"iss", "aud", "iat", "exp", "jti", "sub", "sid", "events"} {
		if _, ok := claims[key]; !ok {
			t.Fatalf("claim %q missing: %+v", key, claims)
		}
	}
	if _, forbidden := claims["nonce"]; forbidden {
		t.Fatalf("logout token must not carry nonce: %+v", claims)
	}
	events, ok := claims["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim is %T, want map", claims["events"])
	}
	if _, ok := events[backchannel.EventID]; !ok {
		t.Fatalf("events missing %q: %+v", backchannel.EventID, events)
	}
	header := parsed.Headers[0]
	if header.ExtraHeaders["typ"] != backchannel.TokenType {
		t.Fatalf("typ header = %v, want %q", header.ExtraHeaders["typ"], backchannel.TokenType)
	}
}

func TestSignLogoutToken_RejectsMissingSubAndSid(t *testing.T) {
	t.Parallel()
	_, sk := mustKey(t)
	const now int64 = 1_700_000_000
	_, err := backchannel.SignLogoutToken(sk, backchannel.LogoutClaims{
		Issuer:    "https://op.example.com",
		Audience:  "client-1",
		IssuedAt:  now,
		ExpiresAt: now + 60,
	})
	if err == nil {
		t.Fatal("expected error when neither Subject nor SessionID supplied")
	}
}

func TestSignLogoutToken_RejectsExpBeforeIat(t *testing.T) {
	t.Parallel()
	_, sk := mustKey(t)
	const now int64 = 1_700_000_000
	_, err := backchannel.SignLogoutToken(sk, backchannel.LogoutClaims{
		Issuer:    "https://op.example.com",
		Audience:  "client-1",
		IssuedAt:  now,
		ExpiresAt: now,
		Subject:   "u",
	})
	if err == nil {
		t.Fatal("expected error when exp <= iat")
	}
}

func TestHTTPDeliverer_PostsFormBody(t *testing.T) {
	t.Parallel()
	var (
		gotBody string
		gotCT   string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotBody = r.PostForm.Get("logout_token")
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	deliverer := backchannel.NewHTTPDeliverer(2 * time.Second)
	deliverer.AllowPrivateNetwork = true // httptest binds to 127.0.0.1
	err := deliverer.Deliver(context.Background(),
		backchannel.Target{ClientID: "c", URL: srv.URL},
		"signed.token.value")
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if gotBody != "signed.token.value" {
		t.Fatalf("body = %q, want %q", gotBody, "signed.token.value")
	}
	if !strings.HasPrefix(gotCT, "application/x-www-form-urlencoded") {
		t.Fatalf("content-type = %q", gotCT)
	}
}

func TestHTTPDeliverer_FailsOnNon2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	d := backchannel.NewHTTPDeliverer(time.Second)
	d.AllowPrivateNetwork = true // httptest binds to 127.0.0.1
	if err := d.Deliver(context.Background(),
		backchannel.Target{URL: srv.URL}, "tok"); err == nil {
		t.Fatal("expected non-nil error on 500")
	}
}

func TestHTTPDeliverer_RefusesRedirect(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://evil.example/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	d := backchannel.NewHTTPDeliverer(time.Second)
	d.AllowPrivateNetwork = true // httptest binds to 127.0.0.1
	if err := d.Deliver(context.Background(),
		backchannel.Target{URL: srv.URL}, "tok"); err == nil {
		t.Fatal("expected error when RP returns 3xx")
	}
}

// TestHTTPDeliverer_CustomClientCannotReenableRedirects verifies the public
// custom-client seam preserves its Transport but not its weaker redirect
// policy. Before this regression fix, a default http.Client followed the 307
// and posted the signed logout token to the second target.
func TestHTTPDeliverer_CustomClientCannotReenableRedirects(t *testing.T) {
	t.Parallel()

	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, nil, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	d := backchannel.NewHTTPDeliverer(time.Second)
	d.AllowPrivateNetwork = true
	d.Client = &http.Client{Transport: origin.Client().Transport}
	if err := d.Deliver(context.Background(), backchannel.Target{URL: origin.URL}, "tok"); err == nil {
		t.Fatal("Deliver succeeded after redirect; want redirect refusal")
	}
	if got := redirected.Load(); got != 0 {
		t.Fatalf("redirect destination received %d requests; want 0", got)
	}
}

// TestHTTPDeliverer_CustomClientCannotDisableTimeout verifies a supplied
// client with Timeout=0 cannot turn the per-RP delivery budget into an
// unbounded wait.
func TestHTTPDeliverer_CustomClientCannotDisableTimeout(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(250 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := backchannel.NewHTTPDeliverer(20 * time.Millisecond)
	d.AllowPrivateNetwork = true
	d.Client = &http.Client{Transport: srv.Client().Transport, Timeout: 0}
	started := time.Now()
	if err := d.Deliver(context.Background(), backchannel.Target{URL: srv.URL}, "tok"); err == nil {
		t.Fatal("Deliver succeeded after configured timeout; want error")
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("Deliver waited %s; custom client bypassed configured timeout", elapsed)
	}
}

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

func newCoordinatorFixture(t *testing.T, deliver backchannel.DelivererFunc) (*backchannel.Coordinator, *inmem.Store, *recordingEmitter) {
	t.Helper()
	_, sk := mustKey(t)
	st := inmem.New()
	rec := &recordingEmitter{}
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:    "https://op.example.com",
		Signing:   sk,
		Clients:   st.Clients(),
		Grants:    st.Grants(),
		Deliverer: deliver,
		Emitter:   rec,
		Clock:     fixedClock(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	return coord, st, rec
}

func saveClient(t *testing.T, st *inmem.Store, c *store.Client) {
	t.Helper()
	if err := st.RegisterClient(context.Background(), c); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
}

func saveGrant(t *testing.T, st *inmem.Store, g *store.Grant) {
	t.Helper()
	if err := st.Grants().Save(context.Background(), g); err != nil {
		t.Fatalf("Grants().Save: %v", err)
	}
}

type faultClientStore struct {
	store.ClientStore
	faultID string
	err     error
	calls   atomic.Int32
}

func (s *faultClientStore) GetClient(ctx context.Context, id string) (*store.Client, error) {
	s.calls.Add(1)
	if id == s.faultID {
		return nil, s.err
	}
	return s.ClientStore.GetClient(ctx, id)
}

type countingGrantStore struct {
	store.GrantStore
	pageCalls atomic.Int32
	listCalls atomic.Int32
	lastLimit atomic.Int64
}

func (s *countingGrantStore) ListBySubject(
	ctx context.Context,
	subject string,
) ([]*store.Grant, error) {
	s.listCalls.Add(1)
	return s.GrantStore.ListBySubject(ctx, subject)
}

func (s *countingGrantStore) ListClientIDsBySubject(
	ctx context.Context,
	subject, cursor string,
	limit int,
) (store.GrantClientPage, error) {
	s.pageCalls.Add(1)
	s.lastLimit.Store(int64(limit))
	return s.GrantStore.ListClientIDsBySubject(ctx, subject, cursor, limit)
}

func TestCoordinator_FansOutToRegisteredClients(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	deliver := backchannel.DelivererFunc(func(_ context.Context, target backchannel.Target, _ string) error {
		calls.Add(1)
		if target.URL == "" {
			t.Errorf("empty URL passed to deliverer for client %s", target.ClientID)
		}
		return nil
	})
	coord, st, rec := newCoordinatorFixture(t, deliver)

	now := time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)
	saveClient(t, st, &store.Client{ID: "rp-a", BackchannelLogoutURI: "https://rp-a.example/logout"})
	saveClient(t, st, &store.Client{ID: "rp-b", BackchannelLogoutURI: "https://rp-b.example/logout"})
	saveClient(t, st, &store.Client{ID: "rp-c"}) // no backchannel URL → skipped
	saveGrant(t, st, &store.Grant{ID: "g-a", Subject: "user", ClientID: "rp-a", CreatedAt: now, UpdatedAt: now})
	saveGrant(t, st, &store.Grant{ID: "g-b", Subject: "user", ClientID: "rp-b", CreatedAt: now, UpdatedAt: now})
	saveGrant(t, st, &store.Grant{ID: "g-c", Subject: "user", ClientID: "rp-c", CreatedAt: now, UpdatedAt: now})

	n, err := coord.Notify(context.Background(), backchannel.Notice{
		Subject:   "user",
		SessionID: "sid-1",
		RequestID: "req-1",
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if n != 2 {
		t.Fatalf("Notify dispatched %d, want 2", n)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("deliverer called %d times, want 2", got)
	}
	for _, ev := range rec.snapshot() {
		if ev.Name != "logout.back_channel.delivered" {
			t.Errorf("audit event = %q, want delivered", ev.Name)
		}
	}
}

// TestCoordinator_TwoRPsReceiveSubOnlyTokens exercises the production HTTP
// deliverer against two real RP endpoints. A browser-session SID supplied
// for audit correlation must not be disclosed to either RP because the
// grant records do not establish client-specific SID lineage.
func TestCoordinator_TwoRPsReceiveSubOnlyTokens(t *testing.T) {
	t.Parallel()

	priv, signing := mustKey(t)
	rpATokens := make(chan string, 1)
	rpBTokens := make(chan string, 1)
	rpA := newLogoutReceiver(t, rpATokens)
	rpB := newLogoutReceiver(t, rpBTokens)

	st := inmem.New()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	saveClient(t, st, &store.Client{ID: "rp-a", BackchannelLogoutURI: rpA.URL})
	saveClient(t, st, &store.Client{ID: "rp-b", BackchannelLogoutURI: rpB.URL})
	saveGrant(t, st, &store.Grant{ID: "g-a", Subject: "user", ClientID: "rp-a", CreatedAt: now, UpdatedAt: now})
	saveGrant(t, st, &store.Grant{ID: "g-b", Subject: "user", ClientID: "rp-b", CreatedAt: now, UpdatedAt: now})

	deliverer := backchannel.NewHTTPDeliverer(time.Second)
	deliverer.AllowPrivateNetwork = true
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:    "https://op.example.com",
		Signing:   signing,
		Clients:   st.Clients(),
		Grants:    st.Grants(),
		Deliverer: deliverer,
		Clock:     fixedClock(now),
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}

	n, err := coord.Notify(context.Background(), backchannel.Notice{
		Subject:   "user",
		SessionID: "browser-session-from-rp-a",
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if n != 2 {
		t.Fatalf("Notify deliveries=%d want 2", n)
	}
	assertSubOnlyLogoutToken(t, <-rpATokens, &priv.PublicKey, "rp-a", "user")
	assertSubOnlyLogoutToken(t, <-rpBTokens, &priv.PublicKey, "rp-b", "user")
}

func newLogoutReceiver(tb testing.TB, tokens chan<- string) *httptest.Server {
	tb.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "malformed form", http.StatusBadRequest)
			return
		}
		token := r.Form.Get("logout_token")
		if token == "" {
			http.Error(w, "missing logout_token", http.StatusBadRequest)
			return
		}
		tokens <- token
		w.WriteHeader(http.StatusNoContent)
	}))
	tb.Cleanup(server.Close)
	return server
}

func assertSubOnlyLogoutToken(
	tb testing.TB,
	token string,
	publicKey *ecdsa.PublicKey,
	wantAudience, wantSubject string,
) {
	tb.Helper()
	parsed, err := jwt.ParseSigned(token, allowedAlgs())
	if err != nil {
		tb.Fatalf("parse logout token: %v", err)
	}
	claims := map[string]any{}
	if err := parsed.Claims(publicKey, &claims); err != nil {
		tb.Fatalf("verify logout token: %v", err)
	}
	if got := claims["aud"]; got != wantAudience {
		tb.Errorf("aud=%v want %q", got, wantAudience)
	}
	if got := claims["sub"]; got != wantSubject {
		tb.Errorf("sub=%v want %q", got, wantSubject)
	}
	if sid, ok := claims["sid"]; ok {
		tb.Errorf("unexpected sid=%v in sub-only logout token", sid)
	}
}

// TestCoordinator_BoundsFanout proves a subject with many grants cannot cause
// one logout request to create unbounded goroutines or outbound deliveries.
func TestCoordinator_BoundsFanout(t *testing.T) {
	t.Parallel()
	_, signing := mustKey(t)
	st := inmem.New()
	rec := &recordingEmitter{}
	var active, peak, calls atomic.Int32
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	deliver := backchannel.DelivererFunc(func(context.Context, backchannel.Target, string) error {
		current := active.Add(1)
		for {
			old := peak.Load()
			if current <= old || peak.CompareAndSwap(old, current) {
				break
			}
		}
		if calls.Add(1) <= 2 {
			started <- struct{}{}
		}
		<-release
		active.Add(-1)
		return nil
	})
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer: "https://op.example.com", Signing: signing, Clients: st.Clients(), Grants: st.Grants(),
		Deliverer: deliver, Emitter: rec, Clock: fixedClock(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)),
		MaxConcurrentDeliveries: 2, MaxTargets: 3,
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	now := time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)
	for i := range 5 {
		id := fmt.Sprintf("rp-%d", i)
		saveClient(t, st, &store.Client{ID: id, BackchannelLogoutURI: "https://" + id + ".example/logout"})
		saveGrant(t, st, &store.Grant{ID: "grant-" + id, Subject: "user", ClientID: id, CreatedAt: now, UpdatedAt: now})
	}
	done := make(chan struct{})
	var notified int
	go func() {
		notified, err = coord.Notify(context.Background(), backchannel.Notice{Subject: "user", SessionID: "sid"})
		close(done)
	}()
	<-started
	<-started
	if got := peak.Load(); got != 2 {
		t.Fatalf("concurrent deliveries=%d, want 2", got)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Notify did not finish")
	}
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if notified != 3 || calls.Load() != 3 {
		t.Fatalf("notified=%d calls=%d, want 3 each", notified, calls.Load())
	}
	foundOverflow := false
	for _, event := range rec.snapshot() {
		if event.Name == "logout.back_channel.overflow" {
			foundOverflow = event.Extras["more_targets"] == true &&
				event.Extras["next_cursor"] == "rp-2"
		}
	}
	if !foundOverflow {
		t.Fatal("missing overflow audit event with continuation cursor")
	}
}

func TestCoordinator_ProjectsSubjectPerTargetClient(t *testing.T) {
	t.Parallel()
	priv, sk := mustKey(t)
	st := inmem.New()
	delivered := make(chan string, 1)
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:  "https://op.example.com",
		Signing: sk,
		Clients: st.Clients(),
		Grants:  st.Grants(),
		SubjectProjector: func(_ context.Context, raw string, client *store.Client) (string, error) {
			if raw != "internal-user" {
				t.Fatalf("raw subject=%q want internal-user", raw)
			}
			if client == nil || client.ID != "pairwise-rp" {
				t.Fatalf("projector client=%v want pairwise-rp", client)
			}
			return "pairwise-sub-for-rp", nil
		},
		Deliverer: backchannel.DelivererFunc(func(_ context.Context, _ backchannel.Target, token string) error {
			delivered <- token
			return nil
		}),
		Clock: fixedClock(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	now := time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)
	saveClient(t, st, &store.Client{
		ID: "pairwise-rp", BackchannelLogoutURI: "https://rp.example/logout", SubjectType: "pairwise",
	})
	saveGrant(t, st, &store.Grant{
		ID: "g-pairwise", Subject: "internal-user", ClientID: "pairwise-rp", CreatedAt: now, UpdatedAt: now,
	})

	n, err := coord.Notify(context.Background(), backchannel.Notice{Subject: "internal-user", SessionID: "sid-1"})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if n != 1 {
		t.Fatalf("Notify dispatched %d, want 1", n)
	}
	token := <-delivered
	parsed, err := jwt.ParseSigned(token, allowedAlgs())
	if err != nil {
		t.Fatalf("parse logout token: %v", err)
	}
	claims := map[string]any{}
	if err := parsed.Claims(&priv.PublicKey, &claims); err != nil {
		t.Fatalf("verify logout token: %v", err)
	}
	if got := claims["sub"]; got != "pairwise-sub-for-rp" {
		t.Fatalf("logout token sub=%v want pairwise-sub-for-rp", got)
	}
}

func TestCoordinator_SkipsLegacySessionRequiredClient(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	deliver := backchannel.DelivererFunc(func(_ context.Context, _ backchannel.Target, _ string) error {
		calls.Add(1)
		return nil
	})
	coord, st, _ := newCoordinatorFixture(t, deliver)
	now := time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)
	saveClient(t, st, &store.Client{
		ID: "strict", BackchannelLogoutURI: "https://strict.example/logout",
		BackchannelLogoutSessionRequired: true,
	})
	saveClient(t, st, &store.Client{
		ID: "lax", BackchannelLogoutURI: "https://lax.example/logout",
	})
	saveGrant(t, st, &store.Grant{ID: "g-strict", Subject: "u", ClientID: "strict", CreatedAt: now, UpdatedAt: now})
	saveGrant(t, st, &store.Grant{ID: "g-lax", Subject: "u", ClientID: "lax", CreatedAt: now, UpdatedAt: now})

	n, err := coord.Notify(context.Background(), backchannel.Notice{Subject: "u", SessionID: "browser-sid"})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if n != 1 || calls.Load() != 1 {
		t.Fatalf("Notify dispatched n=%d calls=%d, want 1/1", n, calls.Load())
	}
}

func TestCoordinator_RecordsFailureWhenDelivererErrors(t *testing.T) {
	t.Parallel()
	deliver := backchannel.DelivererFunc(func(context.Context, backchannel.Target, string) error {
		return errors.New("rp unavailable")
	})
	coord, st, rec := newCoordinatorFixture(t, deliver)
	now := time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)
	saveClient(t, st, &store.Client{ID: "rp", BackchannelLogoutURI: "https://rp.example/logout"})
	saveGrant(t, st, &store.Grant{ID: "g", Subject: "u", ClientID: "rp", CreatedAt: now, UpdatedAt: now})

	if _, err := coord.Notify(context.Background(), backchannel.Notice{Subject: "u"}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	events := rec.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].Name != "logout.back_channel.failed" {
		t.Fatalf("event = %q, want failed", events[0].Name)
	}
	if events[0].ClientID != "rp" {
		t.Fatalf("client_id = %q, want rp", events[0].ClientID)
	}
	if msg, _ := events[0].Extras["error"].(string); !strings.Contains(msg, "rp unavailable") {
		t.Fatalf("extras.error = %q, want to contain underlying cause", msg)
	}
}

func TestCoordinator_ClientStoreFaultIsAuditedAndAggregated(t *testing.T) {
	t.Parallel()
	_, signing := mustKey(t)
	st := inmem.New()
	rec := &recordingEmitter{}
	backendErr := errors.New("registry connection refused")
	clients := &faultClientStore{
		ClientStore: st.Clients(),
		faultID:     "rp-fault",
		err:         backendErr,
	}
	var delivered atomic.Int32
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:  "https://op.example.com",
		Signing: signing,
		Clients: clients,
		Grants:  st.Grants(),
		Deliverer: backchannel.DelivererFunc(func(
			context.Context,
			backchannel.Target,
			string,
		) error {
			delivered.Add(1)
			return nil
		}),
		Emitter: rec,
		Clock:   fixedClock(time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	now := time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)
	saveClient(t, st, &store.Client{ID: "rp-good", BackchannelLogoutURI: "https://good.example/logout"})
	saveClient(t, st, &store.Client{ID: "rp-fault", BackchannelLogoutURI: "https://fault.example/logout"})
	for _, clientID := range []string{"rp-good", "rp-fault", "rp-stale"} {
		saveGrant(t, st, &store.Grant{
			ID: "grant-" + clientID, Subject: "user", ClientID: clientID,
			CreatedAt: now, UpdatedAt: now,
		})
	}

	n, notifyErr := coord.Notify(context.Background(), backchannel.Notice{
		Subject: "user", SessionID: "sid-1", RequestID: "req-1",
	})
	if n != 1 || delivered.Load() != 1 {
		t.Fatalf("Notify delivered n=%d calls=%d, want 1/1", n, delivered.Load())
	}
	if !errors.Is(notifyErr, backendErr) {
		t.Fatalf("Notify error = %v, want wrapped backend fault", notifyErr)
	}
	if clients.calls.Load() != 3 {
		t.Fatalf("ClientStore lookups = %d, want 3", clients.calls.Load())
	}

	var resolutionFailures []audit.Event
	for _, event := range rec.snapshot() {
		if event.Name == "logout.back_channel.failed" &&
			event.Extras["failure_stage"] == "client_lookup" {
			resolutionFailures = append(resolutionFailures, event)
		}
	}
	if len(resolutionFailures) != 1 {
		t.Fatalf("client lookup failure events = %d, want 1", len(resolutionFailures))
	}
	event := resolutionFailures[0]
	if event.ClientID != "rp-fault" || event.Extras["retryable"] != true {
		t.Fatalf("failure evidence = %+v", event)
	}
	if event.Extras["error"] == "" {
		t.Fatal("failure evidence omitted backend reason")
	}
}

func TestCoordinator_GrantAudienceAndClientLookupsAreBounded(t *testing.T) {
	t.Parallel()

	_, signing := mustKey(t)
	st := inmem.New()
	const (
		grantCount = 100_000
		maxTargets = 8
	)
	now := time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)
	for i := range maxTargets {
		clientID := fmt.Sprintf("client-%06d", i)
		saveClient(t, st, &store.Client{
			ID: clientID, BackchannelLogoutURI: "https://" + clientID + ".example/logout",
		})
	}
	for i := range grantCount {
		clientID := fmt.Sprintf("client-%06d", i)
		saveGrant(t, st, &store.Grant{
			ID: fmt.Sprintf("grant-%06d", i), Subject: "large-user", ClientID: clientID,
			CreatedAt: now, UpdatedAt: now,
		})
	}
	grants := &countingGrantStore{GrantStore: st.Grants()}
	clients := &faultClientStore{ClientStore: st.Clients()}
	rec := &recordingEmitter{}
	var delivered atomic.Int32
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer: "https://op.example.com", Signing: signing,
		Clients: clients, Grants: grants, Emitter: rec, MaxTargets: maxTargets,
		Deliverer: backchannel.DelivererFunc(func(
			context.Context,
			backchannel.Target,
			string,
		) error {
			delivered.Add(1)
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}

	n, err := coord.Notify(context.Background(), backchannel.Notice{Subject: "large-user"})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if n != maxTargets || delivered.Load() != maxTargets {
		t.Fatalf("delivered n=%d calls=%d, want %d", n, delivered.Load(), maxTargets)
	}
	if grants.pageCalls.Load() != 1 || grants.listCalls.Load() != 0 {
		t.Fatalf("grant queries page=%d unbounded=%d, want 1/0", grants.pageCalls.Load(), grants.listCalls.Load())
	}
	if grants.lastLimit.Load() != maxTargets {
		t.Fatalf("grant page limit=%d, want %d", grants.lastLimit.Load(), maxTargets)
	}
	if clients.calls.Load() != maxTargets {
		t.Fatalf("client lookups=%d, want %d", clients.calls.Load(), maxTargets)
	}
	var overflow *audit.Event
	for _, event := range rec.snapshot() {
		if event.Name == "logout.back_channel.overflow" {
			ev := event
			overflow = &ev
		}
	}
	if overflow == nil || overflow.Extras["next_cursor"] != "client-000007" {
		t.Fatalf("overflow evidence = %+v", overflow)
	}
}

func TestCoordinator_NoTargetsReturnsZero(t *testing.T) {
	t.Parallel()
	coord, _, rec := newCoordinatorFixture(t, backchannel.DelivererFunc(
		func(context.Context, backchannel.Target, string) error { return nil }))
	n, err := coord.Notify(context.Background(), backchannel.Notice{Subject: "absent"})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if n != 0 {
		t.Fatalf("Notify on empty grants returned %d, want 0", n)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("expected no audit events, got %d", len(got))
	}
}

// TestCoordinator_EmitsNoSessionsForSubjectWhenSidProvided pins the
// gated audit signal: when the caller's notice carries a SessionID
// (i.e. /end_session arrived with id_token_hint, or
// Provider.Logout was called against a session-naming subject) and
// the coordinator's session walk returns zero RPs, the
// `bcl.no_sessions_for_subject` event fires once. The event extras
// must carry the durability posture so SOC dashboards can filter
// expected gaps under volatile placement from unexpected gaps under
// durable placement.
func TestCoordinator_EmitsNoSessionsForSubjectWhenSidProvided(t *testing.T) {
	t.Parallel()
	_, sk := mustKey(t)
	st := inmem.New()
	rec := &recordingEmitter{}
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:                   "https://op.example.com",
		Signing:                  sk,
		Clients:                  st.Clients(),
		Grants:                   st.Grants(),
		Deliverer:                backchannel.DelivererFunc(func(context.Context, backchannel.Target, string) error { return nil }),
		Emitter:                  rec,
		Clock:                    fixedClock(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)),
		SessionDurabilityPosture: backchannel.PostureVolatile,
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	n, err := coord.Notify(context.Background(), backchannel.Notice{
		Subject:   "evicted-user",
		SessionID: "sid-evicted",
		RequestID: "req-1",
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if n != 0 {
		t.Fatalf("Notify dispatched %d, want 0", n)
	}
	events := rec.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Name != "bcl.no_sessions_for_subject" {
		t.Errorf("event name = %q, want bcl.no_sessions_for_subject", ev.Name)
	}
	if ev.ActorID != "evicted-user" {
		t.Errorf("actor_id = %q, want evicted-user", ev.ActorID)
	}
	if ev.SessionID != "sid-evicted" {
		t.Errorf("session_id = %q, want sid-evicted", ev.SessionID)
	}
	if got, _ := ev.Extras["session_durability_posture"].(string); got != "volatile" {
		t.Errorf("extras.session_durability_posture = %q, want volatile", got)
	}
}

// TestCoordinator_OmitsNoSessionsEventWhenSidEmpty is the negative
// companion: a Provider.Logout call against a subject the OP never
// saw (no id_token_hint, no SessionID) is not surprising and stays
// silent. The audit event is single-purpose — flag the volatility
// gap, not the every-call no-op.
func TestCoordinator_OmitsNoSessionsEventWhenSidEmpty(t *testing.T) {
	t.Parallel()
	coord, _, rec := newCoordinatorFixture(t, backchannel.DelivererFunc(
		func(context.Context, backchannel.Target, string) error { return nil }))
	if _, err := coord.Notify(context.Background(), backchannel.Notice{Subject: "absent"}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("expected no audit events on sid-less Notify, got %d", len(got))
	}
}

// TestCoordinator_NoSessionsEventCarriesDurablePosture pins the
// posture-projection rule. An embedder that flipped
// op.WithSessionDurabilityPosture(SessionDurabilityDurable) sees
// the same `bcl.no_sessions_for_subject` event but with the extras
// flagged so SOC dashboards know the gap is unexpected.
func TestCoordinator_NoSessionsEventCarriesDurablePosture(t *testing.T) {
	t.Parallel()
	_, sk := mustKey(t)
	st := inmem.New()
	rec := &recordingEmitter{}
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:                   "https://op.example.com",
		Signing:                  sk,
		Clients:                  st.Clients(),
		Grants:                   st.Grants(),
		Deliverer:                backchannel.DelivererFunc(func(context.Context, backchannel.Target, string) error { return nil }),
		Emitter:                  rec,
		Clock:                    fixedClock(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)),
		SessionDurabilityPosture: backchannel.PostureDurable,
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	if _, err := coord.Notify(context.Background(), backchannel.Notice{
		Subject:   "u",
		SessionID: "sid-1",
	}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	events := rec.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if got, _ := events[0].Extras["session_durability_posture"].(string); got != "durable" {
		t.Errorf("extras.session_durability_posture = %q, want durable", got)
	}
}

func TestCoordinator_RejectsEmptySubject(t *testing.T) {
	t.Parallel()
	coord, _, _ := newCoordinatorFixture(t, backchannel.DelivererFunc(
		func(context.Context, backchannel.Target, string) error { return nil }))
	if _, err := coord.Notify(context.Background(), backchannel.Notice{}); err == nil {
		t.Fatal("expected error on empty Subject")
	}
}

func TestNewCoordinator_RejectsMissingDeps(t *testing.T) {
	t.Parallel()
	_, sk := mustKey(t)
	st := inmem.New()
	cases := map[string]backchannel.Config{
		"empty issuer":    {Signing: sk, Clients: st.Clients(), Grants: st.Grants()},
		"nil signer":      {Issuer: "x", Clients: st.Clients(), Grants: st.Grants()},
		"nil clients":     {Issuer: "x", Signing: sk, Grants: st.Grants()},
		"nil grant store": {Issuer: "x", Signing: sk, Clients: st.Clients()},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := backchannel.NewCoordinator(cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// allowedAlgs returns the JWS alg allow-list parseSigned needs.
// Logout tokens are ES256-only in v1.0.
func allowedAlgs() []josev4.SignatureAlgorithm {
	return []josev4.SignatureAlgorithm{josev4.ES256}
}

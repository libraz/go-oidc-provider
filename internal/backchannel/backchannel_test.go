package backchannel_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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
	now := time.Now().Unix()
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
	now := time.Now().Unix()
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
	if err := d.Deliver(context.Background(),
		backchannel.Target{URL: srv.URL}, "tok"); err == nil {
		t.Fatal("expected error when RP returns 3xx")
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

	now := time.Now()
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

func TestCoordinator_SkipsSessionRequiredWhenSidEmpty(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	deliver := backchannel.DelivererFunc(func(_ context.Context, _ backchannel.Target, _ string) error {
		calls.Add(1)
		return nil
	})
	coord, st, _ := newCoordinatorFixture(t, deliver)
	now := time.Now()
	saveClient(t, st, &store.Client{
		ID: "strict", BackchannelLogoutURI: "https://strict.example/logout",
		BackchannelLogoutSessionRequired: true,
	})
	saveClient(t, st, &store.Client{
		ID: "lax", BackchannelLogoutURI: "https://lax.example/logout",
	})
	saveGrant(t, st, &store.Grant{ID: "g-strict", Subject: "u", ClientID: "strict", CreatedAt: now, UpdatedAt: now})
	saveGrant(t, st, &store.Grant{ID: "g-lax", Subject: "u", ClientID: "lax", CreatedAt: now, UpdatedAt: now})

	n, err := coord.Notify(context.Background(), backchannel.Notice{Subject: "u"})
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
	now := time.Now()
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

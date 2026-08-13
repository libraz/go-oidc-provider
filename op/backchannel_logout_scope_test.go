// Test file drives the unexported back-channel coordinator handle
// op.New records so the delivery gate is exercised through the real
// wiring rather than a hand-built deliverer.
//
//nolint:testpackage // exercises unexported config fields
package op

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// scopeFixtureIssuer is the issuer the delivery-scope Provider is built
// with. Nothing verifies the Logout Tokens it signs; the assertions sit
// on whether the POST left the process at all.
const scopeFixtureIssuer = "https://op.backchannel-scope.test"

// denyListReason is the substring the deliverer's SSRF sentinel carries.
// Matching on it separates "the gate refused this destination" from
// "the OP dialled the destination and the connection failed" — the two
// outcomes a delivery to an unreachable private address would otherwise
// be indistinguishable by.
const denyListReason = "deny-listed network"

// deliveryRecord is one audit record captured off the Provider's audit
// stream. Delivery outcome is reported there and nowhere else — the
// coordinator swallows per-RP errors by design — so the audit stream is
// the only honest observation point for what the OP did with a target.
type deliveryRecord struct {
	event   string
	message string
	err     string
}

// auditSink is the [slog.Handler] the delivery-scope Provider logs its
// audit stream into.
type auditSink struct {
	mu      sync.Mutex
	records []deliveryRecord
}

func (s *auditSink) Enabled(context.Context, slog.Level) bool { return true }

func (s *auditSink) WithAttrs([]slog.Attr) slog.Handler { return s }

func (s *auditSink) WithGroup(string) slog.Handler { return s }

func (s *auditSink) Handle(_ context.Context, rec slog.Record) error {
	captured := deliveryRecord{message: rec.Message}
	rec.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "event":
			captured.event = a.Value.String()
		case "extras":
			// The per-delivery detail rides under a group; the
			// deliverer's rejection reason is the value under "error".
			for _, inner := range a.Value.Group() {
				if inner.Key == "error" {
					captured.err = inner.Value.String()
				}
			}
		}
		return true
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, captured)
	return nil
}

// last returns the most recent captured record.
func (s *auditSink) last(t *testing.T) deliveryRecord {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) == 0 {
		t.Fatal("no audit record captured; the fan-out never reached the deliverer")
	}
	return s.records[len(s.records)-1]
}

// newDeliveryScopeProvider builds the leanest Provider that still
// records a back-channel coordinator, with the supplied opt-ins
// applied. The token-only shape is deliberate: it keeps the fixture
// free of an authenticator and a login chain, neither of which the
// delivery gate consults.
func newDeliveryScopeProvider(t *testing.T, sink *auditSink, opts ...Option) *Provider {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	base := []Option{
		WithIssuer(scopeFixtureIssuer),
		WithStore(inmem.New()),
		WithKeyset(Keyset{SigningKey{KeyID: "sig-1", Signer: priv}}),
		WithGrants(grant.ClientCredentials),
		WithDynamicRegistration(RegistrationOption{}),
		WithBackchannelLogoutTimeout(2 * time.Second),
		WithAuditLogger(slog.New(sink)),
	}
	provider, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	if provider.cfg.backchannelCoordinator == nil {
		t.Fatal("op.New did not record a back-channel coordinator")
	}
	return provider
}

// deliverTo drives one fan-out at the supplied backchannel_logout_uri
// through the coordinator op.New built, and returns the audit record
// the delivery produced.
func deliverTo(t *testing.T, provider *Provider, sink *auditSink, uri string) deliveryRecord {
	t.Helper()
	sent, err := provider.cfg.backchannelCoordinator.NotifyClientDeleted(
		context.Background(),
		backchannel.ClientDeletionSnapshot{
			Client: &store.Client{
				ID:                   "rp-scope",
				BackchannelLogoutURI: uri,
			},
			Subjects: []string{"user-1"},
		},
	)
	if err != nil {
		t.Fatalf("NotifyClientDeleted: %v", err)
	}
	if sent != 1 {
		t.Fatalf("dispatched deliveries = %d, want 1", sent)
	}
	return sink.last(t)
}

// loopbackRP starts a stub relying party bound on 127.0.0.1 that
// accepts the logout POST, and reports whether it was hit.
func loopbackRP(t *testing.T) (uri string, hit func() bool) {
	t.Helper()
	var mu sync.Mutex
	got := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		got = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/backchannel-logout", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return got
	}
}

// TestBackchannelDevOptIn_RefusesNonLoopbackPrivateTargets is the
// acceptance test for the width of the dev opt-in. With
// [WithAllowInsecureBackchannelLogoutForDev] as the only opt-in, a
// client whose backchannel_logout_uri names an RFC 1918 (or any other
// non-loopback private) address must have its delivery refused by the
// SSRF gate — the option's godoc promises loopback and nothing else,
// and a signed logout token POSTed into private space is an SSRF
// primitive handed to whoever can register a client.
//
// The assertion is on the refusal *reason*, not merely on failure: an
// unreachable private address fails either way, and only the sentinel
// distinguishes "the gate stopped this" from "the OP dialled it".
func TestBackchannelDevOptIn_RefusesNonLoopbackPrivateTargets(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		uri  string
	}{
		{"rfc1918-10", "https://10.0.5.12/backchannel-logout"},
		{"rfc1918-172", "https://172.16.4.9/backchannel-logout"},
		{"rfc1918-192", "https://192.168.1.1/backchannel-logout"},
		{"ipv6-ula", "https://[fd00::1]/backchannel-logout"},
		{"link-local-v4", "https://169.254.10.1/backchannel-logout"},
		{"link-local-v6", "https://[fe80::1]/backchannel-logout"},
		{"cloud-metadata", "https://169.254.169.254/backchannel-logout"},
		{"unspecified", "https://0.0.0.0/backchannel-logout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sink := &auditSink{}
			provider := newDeliveryScopeProvider(t, sink, WithAllowInsecureBackchannelLogoutForDev())

			rec := deliverTo(t, provider, sink, tc.uri)
			if !strings.Contains(rec.err, denyListReason) {
				t.Fatalf("delivery to %s was not refused by the SSRF gate:\n  event=%q\n  message=%q\n  error=%q",
					tc.uri, rec.event, rec.message, rec.err)
			}
		})
	}
}

// TestBackchannelDevOptIn_DeliversToLoopback is the other half of the
// acceptance: narrowing the opt-in must not cost it the destination it
// exists for. The stub RP records the hit, so the assertion is that the
// POST actually arrived rather than that no error was logged.
func TestBackchannelDevOptIn_DeliversToLoopback(t *testing.T) {
	t.Parallel()

	sink := &auditSink{}
	provider := newDeliveryScopeProvider(t, sink, WithAllowInsecureBackchannelLogoutForDev())
	uri, hit := loopbackRP(t)

	rec := deliverTo(t, provider, sink, uri)
	if rec.err != "" {
		t.Fatalf("loopback delivery reported an error: %q", rec.err)
	}
	if !hit() {
		t.Fatal("the loopback stub RP never received the logout token")
	}
}

// TestBackchannelPrivateOptIn_DeliversToLoopback pins that the wider,
// separately-named opt-in keeps working: an embedder that declared the
// service-mesh posture still reaches loopback, and reaching private
// space remains available through that option alone.
func TestBackchannelPrivateOptIn_DeliversToLoopback(t *testing.T) {
	t.Parallel()

	sink := &auditSink{}
	provider := newDeliveryScopeProvider(t, sink, WithBackchannelAllowPrivateNetwork(true))
	uri, hit := loopbackRP(t)

	rec := deliverTo(t, provider, sink, uri)
	if rec.err != "" {
		t.Fatalf("loopback delivery under the private-network opt-in reported an error: %q", rec.err)
	}
	if !hit() {
		t.Fatal("the loopback stub RP never received the logout token")
	}
}

// TestBackchannelNoOptIn_RefusesLoopback keeps the default posture
// pinned: with neither opt-in, loopback is refused as well, so the
// narrowed dev flag is doing real work rather than restating the
// default.
func TestBackchannelNoOptIn_RefusesLoopback(t *testing.T) {
	t.Parallel()

	sink := &auditSink{}
	provider := newDeliveryScopeProvider(t, sink)
	uri, hit := loopbackRP(t)

	rec := deliverTo(t, provider, sink, uri)
	if !strings.Contains(rec.err, denyListReason) {
		t.Fatalf("default posture did not refuse loopback:\n  event=%q\n  message=%q\n  error=%q",
			rec.event, rec.message, rec.err)
	}
	if hit() {
		t.Fatal("the OP POSTed a logout token to loopback with no opt-in configured")
	}
}

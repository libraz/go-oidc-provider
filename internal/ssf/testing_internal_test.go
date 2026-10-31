package ssf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"sync"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// Shared fixtures for every test in this package.

const testIssuer = "https://op.example.com"

// testNow is the instant fixedClock returns unless a test picks another.
var testNow = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func fixedClock(at time.Time) timex.Clock {
	return timex.ClockFunc(func() time.Time { return at })
}

// testKey returns a fresh ES256 signing key and its public half.
func testKey(t testing.TB, kid string) (SigningKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return SigningKey{KeyID: kid, Signer: priv, Alg: "ES256"}, &priv.PublicKey
}

// testSealKey returns a fresh 32-byte seal key.
func testSealKey(t testing.TB) []byte {
	t.Helper()
	k := make([]byte, sealKeyLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("read seal key: %v", err)
	}
	return k
}

// newTestStores returns the in-memory reference store, which implements
// store.SharedSignalsStore and store.GrantClientLister.
func newTestStores(t testing.TB) *inmem.Store {
	t.Helper()
	return inmem.New()
}

func testGrants(t testing.TB, st *inmem.Store) store.GrantClientLister {
	t.Helper()
	g, ok := st.Grants().(store.GrantClientLister)
	if !ok {
		t.Fatal("inmem grant store does not implement GrantClientLister")
	}
	return g
}

// testDeps returns transmitter dependencies wired to st, with a fixed
// clock and the given audit recorder.
func testDeps(t testing.TB, st *inmem.Store, rec *recordingAudit) Deps {
	t.Helper()
	return Deps{
		Issuer:  testIssuer,
		Streams: st.SSFStreams(),
		Events:  st.SSFEvents(),
		Grants:  testGrants(t, st),
		Clients: st.Clients(),
		Audit:   rec,
		Clock:   fixedClock(testNow),
	}
}

func newTestTransmitter(t testing.TB, d Deps) *Transmitter {
	t.Helper()
	tr, err := New(d)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tr
}

// seedReceiver registers clientID and gives subject a grant for it.
func seedReceiver(t testing.TB, st *inmem.Store, clientID, subject string) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.Clients().GetClient(ctx, clientID); err != nil {
		if err := st.RegisterClient(ctx, &store.Client{ID: clientID}); err != nil {
			t.Fatalf("RegisterClient %q: %v", clientID, err)
		}
	}
	seedGrant(t, st, clientID, subject)
}

func seedGrant(t testing.TB, st *inmem.Store, clientID, subject string) {
	t.Helper()
	g := &store.Grant{ID: "grant-" + clientID + "-" + subject, Subject: subject, ClientID: clientID}
	if err := st.Grants().Save(context.Background(), g); err != nil {
		t.Fatalf("Grants().Save: %v", err)
	}
}

// seedStream creates a stream for clientID with the given status and
// delivery method, delivering events.
func seedStream(
	t testing.TB,
	st *inmem.Store,
	clientID string,
	status store.SSFStreamStatus,
	method store.SSFDeliveryMethod,
	events ...EventType,
) *store.SSFStream {
	t.Helper()
	delivered := make([]string, len(events))
	for i, e := range events {
		delivered[i] = string(e)
	}
	s := &store.SSFStream{
		ID:              "stream-" + clientID,
		ClientID:        clientID,
		Delivery:        store.SSFDelivery{Method: method},
		EventsRequested: delivered,
		EventsDelivered: delivered,
		Status:          status,
		CreatedAt:       testNow,
		UpdatedAt:       testNow,
	}
	if method == store.SSFDeliveryPush {
		s.Delivery.EndpointURL = "https://rp.example.com/ssf/" + clientID
	}
	if err := st.SSFStreams().Create(context.Background(), s); err != nil {
		t.Fatalf("SSFStreams().Create: %v", err)
	}
	return s
}

// pendingEvents returns every unheld poll event queued for streamID.
func pendingEvents(t testing.TB, st *inmem.Store, streamID string) []*store.SSFEvent {
	t.Helper()
	evs, _, err := st.SSFEvents().Pending(context.Background(), streamID, 1000)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	return evs
}

// decodeClaims parses SET claims JSON into a generic map.
func decodeClaims(t testing.TB, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	return m
}

// eventMember returns the single events member of claims and its key.
func eventMember(t testing.TB, claims map[string]any) (string, map[string]any) {
	t.Helper()
	events, ok := claims["events"].(map[string]any)
	if !ok || len(events) != 1 {
		t.Fatalf("events = %#v, want exactly one member", claims["events"])
	}
	for k, v := range events {
		payload, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("events[%q] = %#v, want object", k, v)
		}
		return k, payload
	}
	return "", nil
}

// verifySET checks a compact SET against pub and returns its protected
// header and payload bytes.
func verifySET(t testing.TB, compact string, pub *ecdsa.PublicKey) (josev4.Header, []byte) {
	t.Helper()
	jws, err := josev4.ParseSignedCompact(compact, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	payload, err := jws.Verify(pub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return jws.Signatures[0].Protected, payload
}

// recordingAudit captures audit events.
type recordingAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingAudit) Emit(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

// named returns the captured events with the given name.
func (r *recordingAudit) named(name string) []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Event
	for _, ev := range r.events {
		if ev.Name == name {
			out = append(out, ev)
		}
	}
	return out
}

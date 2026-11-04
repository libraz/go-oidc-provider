package ssf

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/netsec"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// workerEnv is a worker over the in-memory store whose push client
// admits httptest receivers on loopback.
type workerEnv struct {
	st     *inmem.Store
	rec    *recordingAudit
	sealer *Sealer
	pub    *ecdsa.PublicKey
	w      *Worker
}

func newWorkerEnv(t *testing.T) *workerEnv {
	t.Helper()
	st := newTestStores(t)
	sealer, err := NewSealer(testSealKey(t))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	key, pub := testKey(t, "kid-1")
	rec := &recordingAudit{}
	w, err := NewWorker(WorkerDeps{
		Events:              st.SSFEvents(),
		Streams:             st.SSFStreams(),
		Sealer:              sealer,
		SigningKey:          func() (SigningKey, error) { return key, nil },
		AllowInsecureForDev: true,
		Audit:               rec,
		Clock:               fixedClock(testNow),
	})
	if err != nil {
		t.Fatalf("NewWorker: %v", err)
	}
	return &workerEnv{st: st, rec: rec, sealer: sealer, pub: pub, w: w}
}

// pushStream creates an enabled push stream for clientID at url. A
// non-empty header is sealed with the env's sealer.
func (e *workerEnv) pushStream(t *testing.T, clientID, url, header string) *store.SSFStream {
	t.Helper()
	id := "stream-" + clientID
	var sealed []byte
	if header != "" {
		sealed = e.sealer.Seal(id, header)
	}
	return e.pushStreamSealed(t, clientID, url, sealed)
}

func (e *workerEnv) pushStreamSealed(t *testing.T, clientID, url string, sealed []byte) *store.SSFStream {
	t.Helper()
	s := &store.SSFStream{
		ID:       "stream-" + clientID,
		ClientID: clientID,
		Delivery: store.SSFDelivery{
			Method:                    store.SSFDeliveryPush,
			EndpointURL:               url,
			SealedAuthorizationHeader: sealed,
		},
		EventsRequested: []string{string(EventSessionRevoked)},
		EventsDelivered: []string{string(EventSessionRevoked)},
		Status:          store.SSFStreamEnabled,
		CreatedAt:       testNow,
		UpdatedAt:       testNow,
	}
	if err := e.st.SSFStreams().Create(context.Background(), s); err != nil {
		t.Fatalf("SSFStreams().Create: %v", err)
	}
	return s
}

// enqueue queues a session-revoked SET for streamID/clientID, due at
// next, with the given failed-attempt count.
func (e *workerEnv) enqueue(t *testing.T, streamID, clientID, jti string, attempts int, next time.Time) []byte {
	t.Helper()
	claims, err := BuildClaims(Claims{
		Issuer:    testIssuer,
		Audience:  clientID,
		IssuedAt:  testNow,
		JTI:       jti,
		SubjectID: IssSubSubject(testIssuer, "alice"),
		Event:     EventSessionRevoked,
	})
	if err != nil {
		t.Fatalf("BuildClaims: %v", err)
	}
	ev := &store.SSFEvent{
		JTI:           jti,
		StreamID:      streamID,
		Kind:          store.SSFEventKindEvent,
		Delivery:      store.SSFDeliveryPush,
		Claims:        claims,
		Attempts:      attempts,
		NextAttemptAt: next,
		ExpiresAt:     testNow.Add(eventTTL),
	}
	if err := e.st.SSFEvents().Enqueue(context.Background(), ev); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	return claims
}

// runOnce runs one batch at now and fails on error.
func (e *workerEnv) runOnce(t *testing.T, now time.Time) int {
	t.Helper()
	n, _, err := e.w.RunOnce(context.Background(), now)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return n
}

// claimAt leases whatever is due at now; it is how a test observes the
// queue, so call it only once the worker is done with the event.
func (e *workerEnv) claimAt(t *testing.T, now time.Time) []*store.SSFEvent {
	t.Helper()
	evs, err := e.st.SSFEvents().ClaimDue(context.Background(), now, 1000, 1000, workerLease)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	return evs
}

// assertRescheduled checks that jti is due no earlier than
// now+d-10% and no later than now+d+10%, with attempts recorded.
func (e *workerEnv) assertRescheduled(t *testing.T, now time.Time, d time.Duration, attempts int) {
	t.Helper()
	lo := now.Add(d - d/10)
	hi := now.Add(d + d/10)
	if evs := e.claimAt(t, lo.Add(-time.Nanosecond)); len(evs) != 0 {
		t.Fatalf("event due before %v (backoff %v - 10%%)", lo, d)
	}
	evs := e.claimAt(t, hi)
	if len(evs) != 1 {
		t.Fatalf("event not due by %v (backoff %v + 10%%): %d due", hi, d, len(evs))
	}
	if evs[0].Attempts != attempts {
		t.Fatalf("Attempts = %d, want %d", evs[0].Attempts, attempts)
	}
}

// workerPush is one request a receiver saw.
type workerPush struct {
	authz, contentType string
	body               []byte
}

// workerReceiver records pushes and answers with status.
type workerReceiver struct {
	mu     sync.Mutex
	pushes []workerPush
	status int
	body   string
}

func newWorkerReceiver(t *testing.T, status int, body string) (*workerReceiver, *httptest.Server) {
	t.Helper()
	r := &workerReceiver{status: status, body: body}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.pushes = append(r.pushes, workerPush{authz: req.Header.Get("Authorization"), contentType: req.Header.Get("Content-Type"), body: b})
		r.mu.Unlock()
		if r.status == http.StatusFound {
			w.Header().Set("Location", "http://127.0.0.1:1/elsewhere")
		}
		w.WriteHeader(r.status)
		_, _ = io.WriteString(w, r.body)
	}))
	t.Cleanup(srv.Close)
	return r, srv
}

// newWorkerHungReceiver answers nothing until the client hangs up or the
// test ends; arrived, if non-nil, is closed on the first request. The body
// is drained first: only then does the server watch the connection, so
// r.Context() ends when the client gives up.
func newWorkerHungReceiver(t *testing.T, arrived chan struct{}) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if arrived != nil {
			once.Do(func() { close(arrived) })
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	// Cleanups run last-in first-out: release the handler, then Close.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv
}

func (r *workerReceiver) got() []workerPush {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]workerPush(nil), r.pushes...)
}

func TestWorker_BatchFitsInsideLease(t *testing.T) {
	t.Parallel()
	rounds := (workerBatchSize+workerConcurrency-1)/workerConcurrency + workerStreamShare
	if batch := time.Duration(rounds) * workerPushTimeout; batch >= workerLease {
		t.Fatalf("worst-case batch %v >= lease %v: another replica could re-claim a SET mid-push", batch, workerLease)
	}
}

func TestWorker_StatusClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		body   string
		want   string // audit event
		err    string // err extra on rejection
	}{
		{name: "202 delivered", status: http.StatusAccepted, want: workerEventDelivered},
		{name: "400 rejected", status: http.StatusBadRequest, body: `{"err":"invalid_audience","description":"x"}`, want: workerEventRejected, err: "invalid_audience"},
		{name: "200 retried", status: http.StatusOK, want: workerEventRetried},
		{name: "204 retried", status: http.StatusNoContent, want: workerEventRetried},
		{name: "302 not followed", status: http.StatusFound, want: workerEventRetried},
		{name: "401 retried", status: http.StatusUnauthorized, want: workerEventRetried},
		{name: "429 retried", status: http.StatusTooManyRequests, want: workerEventRetried},
		{name: "500 retried", status: http.StatusInternalServerError, want: workerEventRetried},
		{name: "503 retried", status: http.StatusServiceUnavailable, want: workerEventRetried},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newWorkerEnv(t)
			recv, srv := newWorkerReceiver(t, tc.status, tc.body)
			s := e.pushStream(t, "rp-1", srv.URL+"/events", "Bearer receiver-secret")
			claims := e.enqueue(t, s.ID, s.ClientID, "jti-1", 0, testNow)

			if n := e.runOnce(t, testNow); n != 1 {
				t.Fatalf("RunOnce claimed %d, want 1", n)
			}

			pushes := recv.got()
			if len(pushes) != 1 {
				t.Fatalf("receiver saw %d pushes, want 1", len(pushes))
			}
			p := pushes[0]
			if p.contentType != "application/secevent+jwt" {
				t.Errorf("Content-Type = %q", p.contentType)
			}
			if p.authz != "Bearer receiver-secret" {
				t.Errorf("Authorization = %q, want the unsealed header", p.authz)
			}
			if _, payload := verifySET(t, string(p.body), e.pub); string(payload) != string(claims) {
				t.Errorf("signed payload = %s, want stored claims %s", payload, claims)
			}

			got := e.rec.named(tc.want)
			if len(got) != 1 {
				t.Fatalf("%s events = %d, want 1 (all: %+v)", tc.want, len(got), e.rec.events)
			}
			ex := got[0].Extras
			if got[0].ClientID != "rp-1" || ex["stream_id"] != s.ID || ex["jti"] != "jti-1" || ex["event_type"] != string(EventSessionRevoked) {
				t.Errorf("audit = %+v", got[0])
			}
			if ex["status"] != tc.status {
				t.Errorf("status extra = %v, want %d", ex["status"], tc.status)
			}
			if tc.err != "" && ex["err"] != tc.err {
				t.Errorf("err extra = %v, want %q", ex["err"], tc.err)
			}

			if tc.want == workerEventRetried {
				e.assertRescheduled(t, testNow, workerBackoff[0], 1)
				return
			}
			if evs := e.claimAt(t, testNow.Add(1000*time.Hour)); len(evs) != 0 {
				t.Fatalf("%d events still queued after %s", len(evs), tc.want)
			}
		})
	}
}

func TestWorker_TransportFailureRetried(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	s := e.pushStream(t, "rp-1", url, "")
	e.enqueue(t, s.ID, s.ClientID, "jti-1", 0, testNow)

	e.runOnce(t, testNow)

	got := e.rec.named(workerEventRetried)
	if len(got) != 1 {
		t.Fatalf("push_retried = %d, want 1", len(got))
	}
	if _, ok := got[0].Extras["status"]; ok {
		t.Errorf("status extra on a transport failure: %v", got[0].Extras)
	}
	if got[0].Extras["error"] == nil {
		t.Errorf("error extra missing: %v", got[0].Extras)
	}
	e.assertRescheduled(t, testNow, workerBackoff[0], 1)
}

func TestWorker_BackoffSchedule(t *testing.T) {
	t.Parallel()
	for attempts, d := range workerBackoff {
		t.Run(d.String(), func(t *testing.T) {
			t.Parallel()
			e := newWorkerEnv(t)
			_, srv := newWorkerReceiver(t, http.StatusInternalServerError, "")
			s := e.pushStream(t, "rp-1", srv.URL, "")
			e.enqueue(t, s.ID, s.ClientID, "jti-1", attempts, testNow)

			e.runOnce(t, testNow)

			e.assertRescheduled(t, testNow, d, attempts+1)
			if got := e.rec.named(workerEventRetried); len(got) != 1 || got[0].Extras["attempts"] != attempts+1 {
				t.Fatalf("push_retried = %+v, want one with attempts %d", got, attempts+1)
			}
		})
	}
}

func TestWorker_JitterBounds(t *testing.T) {
	t.Parallel()
	for _, d := range workerBackoff {
		lo, hi := d-d/10, d+d/10
		seen := map[time.Duration]bool{}
		for range 2000 {
			j := workerJitter(d)
			if j < lo || j > hi {
				t.Fatalf("workerJitter(%v) = %v, outside [%v, %v]", d, j, lo, hi)
			}
			seen[j] = true
		}
		if len(seen) < 100 {
			t.Fatalf("workerJitter(%v) produced %d distinct values in 2000 draws", d, len(seen))
		}
	}
}

func TestWorker_AbandonsAfterFourRetries(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	recv, srv := newWorkerReceiver(t, http.StatusServiceUnavailable, "")
	s := e.pushStream(t, "rp-1", srv.URL, "")
	e.enqueue(t, s.ID, s.ClientID, "jti-1", 0, testNow)

	now := testNow
	for range workerMaxRetries + 1 {
		if n := e.runOnce(t, now); n != 1 {
			t.Fatalf("RunOnce at %v claimed %d, want 1", now, n)
		}
		now = now.Add(3 * time.Hour)
	}

	if got := len(recv.got()); got != workerMaxRetries+1 {
		t.Fatalf("pushes = %d, want %d (first try + %d retries)", got, workerMaxRetries+1, workerMaxRetries)
	}
	if got := len(e.rec.named(workerEventRetried)); got != workerMaxRetries {
		t.Fatalf("push_retried = %d, want %d", got, workerMaxRetries)
	}
	ab := e.rec.named(workerEventAbandoned)
	if len(ab) != 1 || ab[0].Extras["reason"] != workerReasonAttempts {
		t.Fatalf("push_abandoned = %+v, want one with reason %q", ab, workerReasonAttempts)
	}
	if n := e.runOnce(t, now.Add(1000*time.Hour)); n != 0 {
		t.Fatalf("abandoned SET still queued: claimed %d", n)
	}
}

// TestWorker_HungReceiverDoesNotBlockBatch wedges one receiver for the
// whole batch: the other receivers' SETs must all be delivered while the
// wedged push is still open, and the wedged stream never has a second
// push in flight.
func TestWorker_HungReceiverDoesNotBlockBatch(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	release := make(chan struct{})
	var inFlight, maxInFlight, hungPushes atomic.Int32
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hungPushes.Add(1)
		cur := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			prev := maxInFlight.Load()
			if cur <= prev || maxInFlight.CompareAndSwap(prev, cur) {
				break
			}
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer hung.Close()
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()

	others := workerBatchSize - workerStreamShare
	var served atomic.Int32
	allServed := make(chan struct{})
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		if int(served.Add(1)) == others {
			close(allServed)
		}
	}))
	defer fast.Close()

	a := e.pushStream(t, "rp-hung", hung.URL, "")
	// Earliest due, so the wedged stream is claimed and started first.
	for i := range workerStreamShare {
		e.enqueue(t, a.ID, a.ClientID, fmt.Sprintf("a-%d", i), 0, testNow.Add(-time.Hour))
	}
	for g := range others / workerStreamShare {
		s := e.pushStream(t, fmt.Sprintf("rp-fast-%d", g), fast.URL, "")
		for i := range workerStreamShare {
			e.enqueue(t, s.ID, s.ClientID, fmt.Sprintf("b-%d-%d", g, i), 0, testNow)
		}
	}

	done := make(chan int, 1)
	go func() {
		n, _, _ := e.w.RunOnce(context.Background(), testNow)
		done <- n
	}()

	select {
	case <-allServed:
	case <-time.After(10 * time.Second):
		t.Fatalf("fast receivers got %d of %d SETs while one receiver hung", served.Load(), others)
	}
	select {
	case <-done:
		t.Fatal("RunOnce returned while the hung push was still open")
	default:
	}
	if got := hungPushes.Load(); got != 1 {
		t.Fatalf("hung receiver saw %d pushes while the first was open, want 1", got)
	}
	releaseAll()
	if n := <-done; n != workerBatchSize {
		t.Fatalf("RunOnce claimed %d, want %d", n, workerBatchSize)
	}
	if got := len(e.rec.named(workerEventDelivered)); got != workerBatchSize {
		t.Fatalf("push_delivered = %d, want %d", got, workerBatchSize)
	}
	if got := maxInFlight.Load(); got != 1 {
		t.Fatalf("concurrent pushes to one stream = %d, want 1", got)
	}
}

// TestWorker_StreamShareBoundsClaim queues a large backlog for one
// receiver ahead of two others: one round takes only that stream's share,
// delivers the other receivers' SETs, and asks for another round.
func TestWorker_StreamShareBoundsClaim(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	busy, busySrv := newWorkerReceiver(t, http.StatusAccepted, "")
	other, otherSrv := newWorkerReceiver(t, http.StatusAccepted, "")
	a := e.pushStream(t, "rp-busy", busySrv.URL, "")
	for i := range 3 * workerBatchSize {
		e.enqueue(t, a.ID, a.ClientID, fmt.Sprintf("a-%03d", i), 0, testNow.Add(-time.Hour))
	}
	for _, client := range []string{"rp-b", "rp-c"} {
		s := e.pushStream(t, client, otherSrv.URL, "")
		e.enqueue(t, s.ID, s.ClientID, client+"-0", 0, testNow)
	}

	n, more, err := e.w.RunOnce(context.Background(), testNow)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != workerStreamShare+2 || !more {
		t.Fatalf("RunOnce = %d more=%v, want %d more=true", n, more, workerStreamShare+2)
	}
	if got := len(busy.got()); got != workerStreamShare {
		t.Fatalf("busy receiver got %d pushes in one round, want its share %d", got, workerStreamShare)
	}
	if got := len(other.got()); got != 2 {
		t.Fatalf("other receivers got %d pushes, want 2 in the same round", got)
	}
}

// TestWorker_FailedPushStopsStreamShare fails a stream's first push: the
// rest of its share is not pushed in that round, keeps its lease and its
// retry budget, and no further round is requested.
func TestWorker_FailedPushStopsStreamShare(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	recv, srv := newWorkerReceiver(t, http.StatusServiceUnavailable, "")
	s := e.pushStream(t, "rp-1", srv.URL, "")
	for i := range workerStreamShare {
		e.enqueue(t, s.ID, s.ClientID, fmt.Sprintf("jti-%d", i), 0, testNow.Add(time.Duration(i)*time.Second-time.Minute))
	}

	n, more, err := e.w.RunOnce(context.Background(), testNow)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != workerStreamShare || more {
		t.Fatalf("RunOnce = %d more=%v, want %d more=false", n, more, workerStreamShare)
	}
	if got := len(recv.got()); got != 1 {
		t.Fatalf("receiver saw %d pushes, want 1: a failed push ends the stream's round", got)
	}
	untouched := 0
	for _, ev := range e.claimAt(t, testNow.Add(workerLease)) {
		if ev.JTI != "jti-0" && ev.Attempts == 0 {
			untouched++
		}
	}
	if untouched != workerStreamShare-1 {
		t.Fatalf("unpushed SETs due after the lease = %d, want %d with no spent attempt", untouched, workerStreamShare-1)
	}
}

// TestWorker_RoundsDrainBacklog pins that one tick claims round after
// round until a receiver's backlog is delivered, rather than one share per
// interval.
func TestWorker_RoundsDrainBacklog(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	recv, srv := newWorkerReceiver(t, http.StatusAccepted, "")
	s := e.pushStream(t, "rp-1", srv.URL, "")
	backlog := 3*workerStreamShare + 1
	for i := range backlog {
		e.enqueue(t, s.ID, s.ClientID, fmt.Sprintf("jti-%02d", i), 0, testNow)
	}

	e.w.runRounds(context.Background())

	if got := len(recv.got()); got != backlog {
		t.Fatalf("receiver got %d pushes in one tick, want the whole backlog %d", got, backlog)
	}
	if evs := e.claimAt(t, testNow.Add(1000*time.Hour)); len(evs) != 0 {
		t.Fatalf("%d SETs still queued", len(evs))
	}
}

func TestWorker_ReceiverTimeoutIsRetried(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	e.w.fetch = workerFetchClient(false, "", true, 100*time.Millisecond)
	hung := newWorkerHungReceiver(t, nil)
	_, fast := newWorkerReceiver(t, http.StatusAccepted, "")

	a := e.pushStream(t, "rp-hung", hung.URL, "")
	b := e.pushStream(t, "rp-fast", fast.URL, "")
	e.enqueue(t, a.ID, a.ClientID, "a-0", 0, testNow)
	e.enqueue(t, b.ID, b.ClientID, "b-0", 0, testNow)

	e.runOnce(t, testNow)

	if got := e.rec.named(workerEventDelivered); len(got) != 1 || got[0].ClientID != "rp-fast" {
		t.Fatalf("push_delivered = %+v, want rp-fast only", got)
	}
	if got := e.rec.named(workerEventRetried); len(got) != 1 || got[0].ClientID != "rp-hung" {
		t.Fatalf("push_retried = %+v, want rp-hung only", got)
	}
}

func TestWorker_SealFailureAbandons(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	recv, srv := newWorkerReceiver(t, http.StatusAccepted, "")
	foreign, err := NewSealer(testSealKey(t))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	s := e.pushStreamSealed(t, "rp-1", srv.URL, foreign.Seal("stream-rp-1", "Bearer x"))
	e.enqueue(t, s.ID, s.ClientID, "jti-1", 0, testNow)

	e.runOnce(t, testNow)

	if got := len(recv.got()); got != 0 {
		t.Fatalf("receiver saw %d pushes, want 0", got)
	}
	ab := e.rec.named(workerEventAbandoned)
	if len(ab) != 1 || ab[0].Extras["reason"] != workerReasonSeal {
		t.Fatalf("push_abandoned = %+v, want one with reason %q", ab, workerReasonSeal)
	}
	if evs := e.claimAt(t, testNow.Add(1000*time.Hour)); len(evs) != 0 {
		t.Fatalf("%d events still queued", len(evs))
	}
}

func TestWorker_UnsealsWithPreviousKey(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	recv, srv := newWorkerReceiver(t, http.StatusAccepted, "")
	oldKey := testSealKey(t)
	old, err := NewSealer(oldKey)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if e.w.sealer, err = NewSealer(testSealKey(t), oldKey); err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	s := e.pushStreamSealed(t, "rp-1", srv.URL, old.Seal("stream-rp-1", "Bearer rotated"))
	e.enqueue(t, s.ID, s.ClientID, "jti-1", 0, testNow)

	e.runOnce(t, testNow)

	pushes := recv.got()
	if len(pushes) != 1 || pushes[0].authz != "Bearer rotated" {
		t.Fatalf("pushes = %+v, want one carrying the header sealed under the previous key", pushes)
	}
}

func TestWorker_MissingStreamAcks(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	e.enqueue(t, "stream-gone", "rp-gone", "jti-1", 0, testNow)

	if n := e.runOnce(t, testNow); n != 1 {
		t.Fatalf("RunOnce claimed %d, want 1", n)
	}
	if len(e.rec.events) != 0 {
		t.Fatalf("audit events = %+v, want none", e.rec.events)
	}
	if evs := e.claimAt(t, testNow.Add(1000*time.Hour)); len(evs) != 0 {
		t.Fatalf("SET of a deleted stream still queued")
	}
}

// TestWorker_SignsWithKeyActiveAtDispatch rotates the signing key between
// a failed push and its retry: each push verifies under the key active
// when it was sent, and the retry keeps the jti.
func TestWorker_SignsWithKeyActiveAtDispatch(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	k1, pub1 := testKey(t, "kid-1")
	k2, pub2 := testKey(t, "kid-2")
	var active atomic.Pointer[SigningKey]
	active.Store(&k1)
	e.w.signingKey = func() (SigningKey, error) { return *active.Load(), nil }

	recv, srv := newWorkerReceiver(t, http.StatusInternalServerError, "")
	s := e.pushStream(t, "rp-1", srv.URL, "")
	e.enqueue(t, s.ID, s.ClientID, "jti-1", 0, testNow)

	e.runOnce(t, testNow)
	active.Store(&k2)
	recv.mu.Lock()
	recv.status = http.StatusAccepted
	recv.mu.Unlock()
	e.runOnce(t, testNow.Add(2*time.Minute))

	pushes := recv.got()
	if len(pushes) != 2 {
		t.Fatalf("pushes = %d, want 2", len(pushes))
	}
	for i, want := range []struct {
		kid string
		pub *ecdsa.PublicKey
	}{{"kid-1", pub1}, {"kid-2", pub2}} {
		hdr, payload := verifySET(t, string(pushes[i].body), want.pub)
		if hdr.KeyID != want.kid {
			t.Errorf("push %d kid = %q, want %q", i, hdr.KeyID, want.kid)
		}
		if typ := hdr.ExtraHeaders["typ"]; typ != TokenType {
			t.Errorf("push %d typ = %v", i, typ)
		}
		if jti := decodeClaims(t, payload)["jti"]; jti != "jti-1" {
			t.Errorf("push %d jti = %v, want jti-1", i, jti)
		}
	}
}

// TestWorker_StartStopLeavesNoGoroutine stops the loop while a push is
// wedged: Drain returns only once the loop goroutine has exited, and the
// cut-short push is neither rescheduled nor acked.
func TestWorker_StartStopLeavesNoGoroutine(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	if err := e.w.Drain(context.Background()); err != nil {
		t.Fatalf("Drain before Start = %v, want nil", err)
	}
	e.w.interval = 10 * time.Millisecond

	arrived := make(chan struct{})
	hung := newWorkerHungReceiver(t, arrived)
	s := e.pushStream(t, "rp-1", hung.URL, "")
	e.enqueue(t, s.ID, s.ClientID, "jti-1", 0, testNow)

	e.w.Start(context.Background())
	e.w.Start(context.Background())
	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("loop never pushed the due SET")
	}
	e.w.Stop()
	e.w.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.w.Drain(ctx); err != nil {
		t.Fatalf("Drain = %v, want nil: the loop goroutine did not exit", err)
	}
	if got := e.rec.named(workerEventRetried); len(got) != 0 {
		t.Fatalf("push_retried after Stop = %+v, want none", got)
	}
	evs := e.claimAt(t, testNow.Add(workerLease))
	if len(evs) != 1 || evs[0].Attempts != 0 {
		t.Fatalf("queued after Stop = %+v, want jti-1 with its lease and no spent attempt", evs)
	}
}

func TestWorker_DrainHonoursDeadline(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	e.w.Start(context.Background())
	defer func() {
		e.w.Stop()
		_ = e.w.Drain(context.Background())
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.w.Drain(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Drain on a running loop with a done ctx = %v, want context.Canceled", err)
	}
}

func TestWorker_LoopDeletesExpired(t *testing.T) {
	t.Parallel()
	e := newWorkerEnv(t)
	e.w.interval = 10 * time.Millisecond
	poll := seedStream(t, e.st, "rp-poll", store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked)
	expired := &store.SSFEvent{
		JTI:       "expired-1",
		StreamID:  poll.ID,
		Kind:      store.SSFEventKindVerification,
		Delivery:  store.SSFDeliveryPoll,
		Claims:    []byte(`{}`),
		ExpiresAt: testNow.Add(-time.Minute),
	}
	if err := e.st.SSFEvents().Enqueue(context.Background(), expired); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	e.w.Start(context.Background())
	defer func() {
		e.w.Stop()
		_ = e.w.Drain(context.Background())
	}()
	deadline := time.After(10 * time.Second)
	for len(pendingEvents(t, e.st, poll.ID)) != 0 {
		select {
		case <-deadline:
			t.Fatal("expired SET still queued")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestNewWorker_RequiresDeps(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	sealer, err := NewSealer(testSealKey(t))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	keyFn := func() (SigningKey, error) { return SigningKey{}, nil }
	full := WorkerDeps{Events: st.SSFEvents(), Streams: st.SSFStreams(), Sealer: sealer, SigningKey: keyFn}
	for name, mutate := range map[string]func(*WorkerDeps){
		"events":     func(d *WorkerDeps) { d.Events = nil },
		"streams":    func(d *WorkerDeps) { d.Streams = nil },
		"sealer":     func(d *WorkerDeps) { d.Sealer = nil },
		"signingKey": func(d *WorkerDeps) { d.SigningKey = nil },
	} {
		d := full
		mutate(&d)
		if _, err := NewWorker(d); err == nil {
			t.Errorf("NewWorker without %s succeeded", name)
		}
	}
	if _, err := NewWorker(full); err != nil {
		t.Fatalf("NewWorker(full) = %v", err)
	}
}

func TestWorkerFetchClient_PrivateRefusalNamesOptIn(t *testing.T) {
	t.Parallel()
	const optIn = "op.WithAllowPrivateNetworkSharedSignals()"
	c := workerFetchClient(false, optIn, false, time.Second)
	err := c.AssertSafeURL(context.Background(), "https://10.0.0.1/push")
	if !errors.Is(err, netsec.ErrPrivateNetworkBlocked) || !strings.Contains(err.Error(), optIn) {
		t.Fatalf("err=%v want ErrPrivateNetworkBlocked naming %s", err, optIn)
	}
}

package ssf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/op/store"
)

// pollTarget is the poll URL of streamID.
func pollTarget(streamID string) string { return "/ssf/poll/" + streamID }

// pollEnqueue queues n ordinary poll events for s directly and returns
// their jtis.
func pollEnqueue(t *testing.T, f *mgmtFixture, s *store.SSFStream, n int) []string {
	t.Helper()
	jtis := make([]string, n)
	for i := range n {
		jti := fmt.Sprintf("%s-jti-%03d", s.ID, i)
		claims, err := BuildClaims(Claims{
			Issuer: testIssuer, Audience: s.ClientID, IssuedAt: testNow, JTI: jti,
			SubjectID: IssSubSubject(testIssuer, "alice"), Event: EventSessionRevoked,
		})
		if err != nil {
			t.Fatalf("BuildClaims: %v", err)
		}
		ev := &store.SSFEvent{
			JTI: jti, StreamID: s.ID, Kind: store.SSFEventKindEvent, Delivery: s.Delivery.Method,
			Claims: claims, NextAttemptAt: testNow, ExpiresAt: testNow.Add(eventTTL),
		}
		if err := f.st.SSFEvents().Enqueue(context.Background(), ev); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		jtis[i] = jti
	}
	return jtis
}

type pollResult struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable"`
}

func (f *mgmtFixture) poll(t *testing.T, streamID, body string) pollResult {
	t.Helper()
	w := f.do(t, mgmtScopeRead, http.MethodPost, pollTarget(streamID), body)
	mgmtWantStatus(t, w, http.StatusOK)
	var res pollResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	if res.Sets == nil {
		t.Fatalf("response %s has no sets object", w.Body.String())
	}
	return res
}

func pollKeys(res pollResult) []string {
	out := make([]string, 0, len(res.Sets))
	for k := range res.Sets {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func TestPollReturnsSignedSETsAndAcks(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll)
	jtis := pollEnqueue(t, f, s, 2)

	res := f.poll(t, s.ID, `{"returnImmediately":true}`)
	if got := pollKeys(res); !slices.Equal(got, jtis) {
		t.Fatalf("sets = %v, want %v", got, jtis)
	}
	for jti, set := range res.Sets {
		hdr, payload := verifySET(t, set, f.setPub)
		if hdr.KeyID != "set-k1" || hdr.ExtraHeaders["typ"] != TokenType {
			t.Errorf("header = kid %q typ %v", hdr.KeyID, hdr.ExtraHeaders["typ"])
		}
		if decodeClaims(t, payload)["jti"] != jti {
			t.Errorf("SET under %q carries another jti", jti)
		}
	}

	// Unacknowledged SETs are returned again.
	if got := pollKeys(f.poll(t, s.ID, `{"returnImmediately":true}`)); !slices.Equal(got, jtis) {
		t.Errorf("re-poll = %v, want %v", got, jtis)
	}
	res = f.poll(t, s.ID, fmt.Sprintf(`{"ack":[%q],"returnImmediately":true}`, jtis[0]))
	if got := pollKeys(res); !slices.Equal(got, jtis[1:]) {
		t.Errorf("after ack = %v, want %v", got, jtis[1:])
	}
	res = f.poll(t, s.ID, fmt.Sprintf(`{"ack":[%q],"returnImmediately":true}`, jtis[1]))
	if len(res.Sets) != 0 || res.MoreAvailable {
		t.Errorf("after acking all = %+v", res)
	}
}

func TestPollSignsWithTheKeyActiveAtResponseTime(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll)
	jti := pollEnqueue(t, f, s, 1)[0]
	first := f.poll(t, s.ID, `{"returnImmediately":true}`)
	rotated, rotatedPub := testKey(t, "set-k2")
	f.setKey = rotated
	second := f.poll(t, s.ID, `{"returnImmediately":true}`)
	if hdr, _ := verifySET(t, second.Sets[jti], rotatedPub); hdr.KeyID != "set-k2" {
		t.Errorf("kid after rotation = %q", hdr.KeyID)
	}
	if hdr, _ := verifySET(t, first.Sets[jti], f.setPub); hdr.KeyID != "set-k1" {
		t.Errorf("kid before rotation = %q", hdr.KeyID)
	}
}

func TestPollEdges(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		body   string
		status int
	}{
		{"negative maxEvents", `{"maxEvents":-1}`, http.StatusBadRequest},
		{"fractional maxEvents", `{"maxEvents":1.5}`, http.StatusBadRequest},
		{"exponent maxEvents", `{"maxEvents":1e2}`, http.StatusBadRequest},
		{"string maxEvents", `{"maxEvents":"3"}`, http.StatusBadRequest},
		{"boolean maxEvents", `{"maxEvents":true}`, http.StatusBadRequest},
		{"string returnImmediately", `{"returnImmediately":"yes"}`, http.StatusBadRequest},
		{"non-string ack element", `{"ack":["a",1]}`, http.StatusBadRequest},
		{"ack not an array", `{"ack":"a"}`, http.StatusBadRequest},
		{"setErrs value not an object", `{"setErrs":{"a":"bad"}}`, http.StatusBadRequest},
		{"setErrs not an object", `{"setErrs":["a"]}`, http.StatusBadRequest},
		{"malformed JSON", `{"maxEvents":`, http.StatusBadRequest},
		{"trailing data", `{}x`, http.StatusBadRequest},
		{"body over 64 KiB", fmt.Sprintf(`{"ack":[%q]}`, strings.Repeat("a", mgmtMaxBody)), http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newMgmtFixture(t)
			s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll)
			jtis := pollEnqueue(t, f, s, 1)
			w := f.do(t, mgmtScopeRead, http.MethodPost, pollTarget(s.ID), tc.body)
			mgmtWantStatus(t, w, tc.status)
			if got := len(pendingEvents(t, f.st, s.ID)); got != len(jtis) {
				t.Errorf("a rejected poll changed the queue: %d pending", got)
			}
		})
	}
}

func TestPollMaxEventsZeroOnlyAcknowledges(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll)
	jtis := pollEnqueue(t, f, s, 2)
	w := f.do(t, mgmtScopeRead, http.MethodPost, pollTarget(s.ID), fmt.Sprintf(`{"maxEvents":0,"ack":[%q]}`, jtis[0]))
	mgmtWantStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != `{"sets":{}}` {
		t.Errorf("body = %s, want {\"sets\":{}}", got)
	}
	if got := pendingEvents(t, f.st, s.ID); len(got) != 1 || got[0].JTI != jtis[1] {
		t.Errorf("pending = %v, want only the unacknowledged one", got)
	}
}

func TestPollMaxEventsDefaultAndCap(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll)
	pollEnqueue(t, f, s, pollCapMax+4)

	res := f.poll(t, s.ID, `{"returnImmediately":true}`)
	if len(res.Sets) != pollDefaultMax || !res.MoreAvailable {
		t.Errorf("default: %d sets, more %v; want %d and more", len(res.Sets), res.MoreAvailable, pollDefaultMax)
	}
	for _, n := range []string{"257", "99999999999999999999"} {
		res = f.poll(t, s.ID, `{"returnImmediately":true,"maxEvents":`+n+`}`)
		if len(res.Sets) != pollCapMax || !res.MoreAvailable {
			t.Errorf("maxEvents %s: %d sets, more %v; want %d and more", n, len(res.Sets), res.MoreAvailable, pollCapMax)
		}
	}
	res = f.poll(t, s.ID, `{"returnImmediately":true,"maxEvents":3}`)
	if len(res.Sets) != 3 {
		t.Errorf("maxEvents 3: %d sets", len(res.Sets))
	}
}

func TestPollSetErrsAcknowledgeAndAudit(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll)
	other := seedStream(t, f.st, mgmtClientB, store.SSFStreamEnabled, store.SSFDeliveryPoll)
	jtis := pollEnqueue(t, f, s, 2)
	otherJTI := pollEnqueue(t, f, other, 1)[0]

	body := fmt.Sprintf(`{"returnImmediately":true,"ack":["unknown",%q],"setErrs":{%q:{"err":"invalid_key","description":"kid unknown"}}}`,
		otherJTI, jtis[0])
	res := f.poll(t, s.ID, body)
	if got := pollKeys(res); !slices.Equal(got, jtis[1:]) {
		t.Errorf("sets = %v, want %v", got, jtis[1:])
	}
	// Unknown jtis and another stream's jtis are ignored.
	if got := pendingEvents(t, f.st, other.ID); len(got) != 1 {
		t.Errorf("another stream's event was acknowledged")
	}
	evs := f.rec.named(string(auditevent.AuditSSFPollSETError))
	if len(evs) != 1 {
		t.Fatalf("poll_set_error events = %d, want 1", len(evs))
	}
	if x := evs[0].Extras; x["jti"] != jtis[0] || x["err"] != "invalid_key" || x["stream_id"] != s.ID || evs[0].ClientID != mgmtClientA {
		t.Errorf("audit = %+v", evs[0])
	}
}

func TestPollStreamChecks(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	push := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPush)
	other := seedStream(t, f.st, mgmtClientB, store.SSFStreamEnabled, store.SSFDeliveryPoll)

	mgmtWantStatus(t, f.do(t, mgmtScopeRead, http.MethodPost, pollTarget(push.ID), `{}`), http.StatusBadRequest)
	mgmtWantStatus(t, f.do(t, mgmtScopeRead, http.MethodPost, pollTarget(other.ID), `{}`), http.StatusNotFound)
	mgmtWantStatus(t, f.do(t, mgmtScopeRead, http.MethodPost, pollTarget("missing"), `{}`), http.StatusNotFound)
	mgmtWantStatus(t, f.do(t, mgmtScopeNone, http.MethodPost, pollTarget(other.ID), `{}`), http.StatusForbidden)
	mgmtWantStatus(t, f.do(t, mgmtScopeRead, http.MethodGet, pollTarget(other.ID), ""), http.StatusMethodNotAllowed)

	// ssf.manage implies ssf.read.
	b := newMgmtFixture(t)
	s := seedStream(t, b.st, mgmtClientA, store.SSFStreamDisabled, store.SSFDeliveryPoll)
	mgmtWantStatus(t, b.do(t, mgmtScopeManage, http.MethodPost, pollTarget(s.ID), `{"returnImmediately":true}`), http.StatusOK)
}

func TestPollDisabledStreamStillDeliversControlEvents(t *testing.T) {
	t.Parallel()
	f := newMgmtFixture(t)
	s := f.mgmtCreate(t, `{}`)
	mgmtWantStatus(t, f.do(t, mgmtScopeManage, http.MethodPost, mgmtStatusPath,
		fmt.Sprintf(`{"stream_id":%q,"status":"disabled"}`, s.ID)), http.StatusOK)
	res := f.poll(t, s.ID, `{"returnImmediately":true}`)
	types := make([]string, 0, len(res.Sets))
	for _, set := range res.Sets {
		_, payload := verifySET(t, set, f.setPub)
		et, _ := eventMember(t, decodeClaims(t, payload))
		types = append(types, et)
	}
	slices.Sort(types)
	want := []string{string(EventStreamUpdated), string(EventVerification)}
	slices.Sort(want)
	if !slices.Equal(types, want) {
		t.Errorf("disabled stream delivered %v, want %v", types, want)
	}
}

// pollCountingEvents closes reread on the second Pending call: the first
// re-read of a long poll.
type pollCountingEvents struct {
	store.SSFEventStore
	mu     sync.Mutex
	calls  int
	reread chan struct{}
}

func (e *pollCountingEvents) Pending(ctx context.Context, streamID string, n int) ([]*store.SSFEvent, bool, error) {
	e.mu.Lock()
	e.calls++
	if e.calls == 2 {
		close(e.reread)
	}
	e.mu.Unlock()
	return e.SSFEventStore.Pending(ctx, streamID, n)
}

func TestPollLongPollWaits(t *testing.T) {
	t.Parallel()

	t.Run("nothing arrives", func(t *testing.T) {
		t.Parallel()
		f := newMgmtFixture(t)
		f.h.pollInterval, f.h.pollWait = 5*time.Millisecond, 60*time.Millisecond
		s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll)
		for _, body := range []string{`{}`, `{"returnImmediately":false}`} {
			start := time.Now()
			res := f.poll(t, s.ID, body)
			if elapsed := time.Since(start); elapsed < f.h.pollWait {
				t.Errorf("%s returned after %v, want the %v wait", body, elapsed, f.h.pollWait)
			}
			if len(res.Sets) != 0 {
				t.Errorf("%s: sets = %v", body, res.Sets)
			}
		}
	})

	t.Run("returnImmediately does not wait", func(t *testing.T) {
		t.Parallel()
		f := newMgmtFixture(t)
		f.h.pollInterval, f.h.pollWait = time.Hour, time.Hour
		s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll)
		f.poll(t, s.ID, `{"returnImmediately":true}`)
	})

	t.Run("an event arriving during the wait is returned", func(t *testing.T) {
		t.Parallel()
		f := newMgmtFixture(t)
		f.h.pollInterval, f.h.pollWait = 5*time.Millisecond, time.Hour
		s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll)
		// Tokens and the request are built before the wait so the
		// fixture is not shared with the enqueuing goroutine.
		r := mgmtNewRequest(http.MethodPost, pollTarget(s.ID), `{}`)
		f.authorizeRequest(t, r, mgmtJWT, f.token(t, mgmtJWT, mgmtClientA, mgmtScopeRead, nil))
		counted := &pollCountingEvents{SSFEventStore: f.st.SSFEvents(), reread: make(chan struct{})}
		f.h.events = counted
		done := make(chan pollResult, 1)
		go func() {
			w := f.serve(r)
			var res pollResult
			_ = json.Unmarshal(w.Body.Bytes(), &res)
			done <- res
		}()
		// Enqueue only once the handler has found nothing and re-read.
		<-counted.reread
		jti := pollEnqueue(t, f, s, 1)[0]
		select {
		case res := <-done:
			if _, ok := res.Sets[jti]; !ok {
				t.Errorf("sets = %v, want %q", res.Sets, jti)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("long poll did not return the arriving event")
		}
	})

	t.Run("cancelled request returns", func(t *testing.T) {
		t.Parallel()
		f := newMgmtFixture(t)
		f.h.pollInterval, f.h.pollWait = 5*time.Millisecond, time.Hour
		s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		r := mgmtNewRequest(http.MethodPost, pollTarget(s.ID), `{}`).WithContext(ctx)
		f.authorizeRequest(t, r, mgmtJWT, f.token(t, mgmtJWT, mgmtClientA, mgmtScopeRead, nil))
		done := make(chan int, 1)
		go func() { done <- f.serve(r).Code }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("long poll ignored the request context")
		}
	})
}

// Test file exercises the dispatcher in isolation. The op-side
// adapter is exercised end-to-end in the token endpoint tests; the
// scope of these tests is the policy gates: form filtering, panic
// recovery, TTL cap, scope / audience subset, audit emission.
//
//nolint:testpackage // exercises unexported helpers
package customgrant

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
	"github.com/libraz/go-oidc-provider/op/store"
)

// recordingEmitter captures every audit event so tests can assert on
// the names and reasons the dispatcher emitted. The type is intentionally
// inlined: an in-tree audit recorder would be over-engineering for the
// single caller.
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

// stubHandler is the table-test-friendly Handler implementation. The
// handle field is the per-test override; nil treats the request as a
// trivial pass-through that returns the supplied response.
type stubHandler struct {
	name   string
	policy ParamPolicy
	handle func(ctx context.Context, req Request) (Response, error)
}

func (s stubHandler) Name() string             { return s.name }
func (s stubHandler) ParamPolicy() ParamPolicy { return s.policy }
func (s stubHandler) Handle(ctx context.Context, req Request) (Response, error) {
	if s.handle != nil {
		return s.handle(ctx, req)
	}
	return Response{AccessToken: "at-1", AccessTokenTTL: time.Minute}, nil
}

// newClient builds a store.Client wired for one custom grant. The
// scope and resource lists drive the subset checks; tests override
// them locally as needed.
func newClient(grant string) *store.Client {
	return &store.Client{
		ID:         "c-1",
		GrantTypes: []string{grant},
		Scopes:     []string{"read", "write"},
		Resources:  []string{"https://api.example.com"},
	}
}

// newDispatcher builds a dispatcher pre-wired with a recording audit
// emitter the test asserts against.
func newDispatcher(t *testing.T, h Handler, opts ...Option) (*Dispatcher, *recordingEmitter) {
	t.Helper()
	em := &recordingEmitter{}
	disp := New([]Handler{h}, append(opts, WithAudit(em))...)
	return disp, em
}

func TestDispatch_HappyPath(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:happy"
	disp, em := newDispatcher(t, stubHandler{
		name:   grant,
		policy: ParamPolicy{Allowed: []string{"resource"}},
	})
	resp, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
		Form:      url.Values{"resource": []string{"https://api.example.com"}},
	})
	if err != nil {
		t.Fatalf("Dispatch returned %v, want nil", err)
	}
	if resp.AccessToken != "at-1" {
		t.Fatalf("AccessToken = %q, want at-1", resp.AccessToken)
	}
	events := em.snapshot()
	if len(events) != 1 || events[0].Name != AuditEventRequested {
		t.Fatalf("audit events = %+v, want one %s", events, AuditEventRequested)
	}
}

func TestDispatch_UnknownGrant(t *testing.T) {
	t.Parallel()

	disp, _ := newDispatcher(t, stubHandler{name: "urn:example:grant-type:registered"})
	_, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: "urn:example:grant-type:nope",
		Client:    newClient("urn:example:grant-type:nope"),
	})
	if !errors.Is(err, ErrUnknownGrant) {
		t.Fatalf("err = %v, want ErrUnknownGrant", err)
	}
}

func TestDispatch_ClientGrantNotPermitted(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:permitted"
	disp, em := newDispatcher(t, stubHandler{name: grant})
	client := newClient(grant)
	client.GrantTypes = []string{"authorization_code"} // grant not registered for client
	_, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    client,
	})
	if !errors.Is(err, ErrClientGrantNotPermitted) {
		t.Fatalf("err = %v, want ErrClientGrantNotPermitted", err)
	}
	assertRequestedThenFailed(t, em.snapshot(), "client_grant_not_permitted")
}

func TestDispatch_FormPolicy(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:form"
	cases := []struct {
		name    string
		policy  ParamPolicy
		form    url.Values
		wantErr error
	}{
		{
			name:   "implicit parameters tolerated",
			policy: ParamPolicy{Allowed: []string{"resource"}},
			form: url.Values{
				"grant_type":    []string{grant},
				"client_id":     []string{"c-1"},
				"client_secret": []string{"s"},
				"scope":         []string{"read"},
				"resource":      []string{"https://api.example.com"},
			},
		},
		{
			name:    "unknown parameter",
			policy:  ParamPolicy{Allowed: []string{"resource"}},
			form:    url.Values{"unexpected": []string{"value"}},
			wantErr: ErrUnknownParameter,
		},
		{
			name:    "duplicate not permitted",
			policy:  ParamPolicy{Allowed: []string{"resource"}},
			form:    url.Values{"resource": []string{"a", "b"}},
			wantErr: ErrDuplicateParameter,
		},
		{
			name: "duplicates within cap",
			policy: ParamPolicy{
				Allowed:      []string{"resource"},
				DupesAllowed: []string{"resource"},
			},
			form: url.Values{"resource": []string{"a", "b", "c"}},
		},
		{
			name: "duplicate cap exceeded",
			policy: ParamPolicy{
				Allowed:      []string{"resource"},
				DupesAllowed: []string{"resource"},
			},
			form: url.Values{
				"resource": func() []string {
					out := make([]string, DupCap+1)
					for i := range out {
						out[i] = "v"
					}
					return out
				}(),
			},
			wantErr: ErrDuplicateCapExceeded,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			disp, _ := newDispatcher(t, stubHandler{name: grant, policy: tc.policy})
			_, err := disp.Dispatch(context.Background(), DispatchInput{
				GrantType: grant,
				Client:    newClient(grant),
				Form:      tc.form,
			})
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDispatch_PanicRecovered(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:panic"
	disp, em := newDispatcher(t, stubHandler{
		name: grant,
		handle: func(_ context.Context, _ Request) (Response, error) {
			panic("boom")
		},
	})
	_, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if !errors.Is(err, ErrPanic) {
		t.Fatalf("err = %v, want ErrPanic", err)
	}
	// Exactly one failure record. A recover block that emitted its own
	// record on top of the one Dispatch raises for the returned error
	// doubles the panic-class failure rate, so an alert calibrated on
	// oidc_custom_grant_events_total{event="failed"} fires at half the
	// real rate — and the two records disagreed on level and reason.
	failed := assertRequestedThenFailed(t, em.snapshot(), "panic")
	if failed.Level != audit.LevelError {
		t.Errorf("panic failure level=%v want %v", failed.Level, audit.LevelError)
	}
	if got, _ := failed.Extras["panic_value"].(string); got != "boom" {
		t.Errorf("extras.panic_value=%v want boom", failed.Extras["panic_value"])
	}
	if got, _ := failed.Extras["stack"].(string); got == "" {
		t.Error("extras.stack is empty; the panic record must carry the trace")
	}
}

// assertRequestedThenFailed pins the audit shape of a rejected
// dispatch: the attempt is recorded at entry, exactly one failure
// follows it, and the failure names the gate that fired. Returning the
// failure lets a caller assert the gate-specific extras.
func assertRequestedThenFailed(tb testing.TB, events []audit.Event, wantReason string) audit.Event {
	tb.Helper()
	if len(events) != 2 {
		tb.Fatalf("audit events = %+v, want exactly %s then %s", events, AuditEventRequested, AuditEventFailed)
	}
	if events[0].Name != AuditEventRequested {
		tb.Fatalf("first event = %q, want %s (the attempt is counted at entry)", events[0].Name, AuditEventRequested)
	}
	if events[1].Name != AuditEventFailed {
		tb.Fatalf("second event = %q, want %s", events[1].Name, AuditEventFailed)
	}
	if got := events[1].Extras["reason"]; got != wantReason {
		tb.Errorf("failure reason = %v, want %q", got, wantReason)
	}
	return events[1]
}

func TestDispatch_TTLCapTruncates(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:ttl"
	disp, _ := newDispatcher(t,
		stubHandler{
			name: grant,
			handle: func(_ context.Context, _ Request) (Response, error) {
				return Response{AccessToken: "at", AccessTokenTTL: 24 * time.Hour}, nil
			},
		},
		WithMaxAccessTTL(time.Hour),
	)
	resp, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if err != nil {
		t.Fatalf("Dispatch err = %v", err)
	}
	if resp.AccessTokenTTL != time.Hour {
		t.Fatalf("AccessTokenTTL = %v, want capped to 1h", resp.AccessTokenTTL)
	}
}

func TestDispatch_TTLCapDisabledWhenZero(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:ttl0"
	disp, _ := newDispatcher(t, stubHandler{
		name: grant,
		handle: func(_ context.Context, _ Request) (Response, error) {
			return Response{AccessToken: "at", AccessTokenTTL: 24 * time.Hour}, nil
		},
	})
	resp, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if err != nil {
		t.Fatalf("Dispatch err = %v", err)
	}
	if resp.AccessTokenTTL != 24*time.Hour {
		t.Fatalf("AccessTokenTTL = %v, want unchanged 24h", resp.AccessTokenTTL)
	}
}

func TestDispatch_NegativeTTLRejected(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:negttl"
	disp, _ := newDispatcher(t, stubHandler{
		name: grant,
		handle: func(_ context.Context, _ Request) (Response, error) {
			return Response{AccessToken: "at", AccessTokenTTL: -time.Second}, nil
		},
	})
	_, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if !errors.Is(err, ErrNegativeTTL) {
		t.Fatalf("err = %v, want ErrNegativeTTL", err)
	}
}

func TestDispatch_EmptyAccessTokenRejected(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:empty"
	disp, _ := newDispatcher(t, stubHandler{
		name: grant,
		handle: func(_ context.Context, _ Request) (Response, error) {
			return Response{AccessToken: ""}, nil
		},
	})
	_, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if !errors.Is(err, ErrEmptyAccessToken) {
		t.Fatalf("err = %v, want ErrEmptyAccessToken", err)
	}
}

func TestDispatch_ScopeInflationRejected(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:scope"
	disp, _ := newDispatcher(t, stubHandler{
		name: grant,
		handle: func(_ context.Context, _ Request) (Response, error) {
			return Response{
				AccessToken: "at",
				Scope:       []string{"read", "admin"}, // admin not allowed
			}, nil
		},
	})
	_, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("err = %v, want ErrScopeNotAllowed", err)
	}
}

func TestDispatch_AudienceInflationRejected(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:aud"
	disp, _ := newDispatcher(t, stubHandler{
		name: grant,
		handle: func(_ context.Context, _ Request) (Response, error) {
			return Response{
				AccessToken: "at",
				Audience:    []string{"https://elsewhere.example"},
			}, nil
		},
	})
	_, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if !errors.Is(err, ErrAudienceNotAllowed) {
		t.Fatalf("err = %v, want ErrAudienceNotAllowed", err)
	}
}

// TestAudienceSubsetFollowsTheSharedResourcePolicy pins the dispatcher
// onto the OP-wide resource-indicator equality policy. The dispatcher
// compares a handler-returned audience against the client's registered
// Resources, which is the same question client_credentials and token
// exchange answer, and a private normalisation helper here would let a
// value be accepted for one grant and rejected for another.
//
// [resourceindicator.EqualLabel] is the policy itself, so the assertion
// is that the dispatcher agrees with it — including on the fragment and
// userinfo forms, which are FORBIDDEN on a resource indicator and must
// therefore match nothing.
func TestAudienceSubsetFollowsTheSharedResourcePolicy(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		registered string
		returned   string
	}{
		{name: "default https port stripped", registered: "https://api.example.com:443/v1/", returned: "https://api.example.com/v1"},
		{name: "non-default port preserved", registered: "https://api.example.com:8443", returned: "https://api.example.com"},
		{name: "trailing slash ignored", registered: "https://api.example.com/v1/", returned: "https://api.example.com/v1"},
		{name: "scheme and host case folded", registered: "HTTPS://API.EXAMPLE.COM/v1", returned: "https://api.example.com/v1"},
		{name: "path case preserved", registered: "https://api.example.com/V1", returned: "https://api.example.com/v1"},
		{name: "returned fragment matches nothing", registered: "https://api.example.com/v1", returned: "https://api.example.com/v1#frag"},
		{name: "returned userinfo matches nothing", registered: "https://api.example.com/v1", returned: "https://trusted@api.example.com/v1"},
		{name: "opaque audience label compares verbatim", registered: "urn:example:api", returned: "urn:example:api"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := resourceindicator.EqualLabel(tc.registered, tc.returned)
			if got := audienceSubset([]string{tc.returned}, []string{tc.registered}); got != want {
				t.Fatalf("audienceSubset=%v want %v (shared policy)", got, want)
			}
		})
	}
}

func TestDispatch_HandlerErrorPropagated(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:err"
	custom := errors.New("handler-supplied error")
	disp, em := newDispatcher(t, stubHandler{
		name: grant,
		handle: func(_ context.Context, _ Request) (Response, error) {
			return Response{}, custom
		},
	})
	_, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if !errors.Is(err, custom) {
		t.Fatalf("err = %v, want %v", err, custom)
	}
	assertRequestedThenFailed(t, em.snapshot(), "handler_error")
}

func TestDispatch_HasHandlerAndNames(t *testing.T) {
	t.Parallel()

	disp := New([]Handler{
		stubHandler{name: "urn:example:a"},
		stubHandler{name: "urn:example:b"},
	})
	if !disp.HasHandler("urn:example:a") {
		t.Errorf("HasHandler(a) = false")
	}
	if disp.HasHandler("urn:example:c") {
		t.Errorf("HasHandler(c) = true, want false")
	}
	names := disp.Names()
	if len(names) != 2 || names[0] != "urn:example:a" || names[1] != "urn:example:b" {
		t.Errorf("Names = %v, want [a b]", names)
	}
}

func TestDispatch_NilDispatcherReturnsUnknownGrant(t *testing.T) {
	t.Parallel()

	var disp *Dispatcher
	_, err := disp.Dispatch(context.Background(), DispatchInput{GrantType: "x"})
	if !errors.Is(err, ErrUnknownGrant) {
		t.Fatalf("err = %v, want ErrUnknownGrant", err)
	}
}

// TestDispatch_BoundAccessTokenPassesThrough verifies that a handler
// returning only BoundAccessToken (no AccessToken) clears the
// dispatcher's invariants — the wire layer is the one that mints, so
// the dispatcher must NOT reject the empty AccessToken in this shape.
func TestDispatch_BoundAccessTokenPassesThrough(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:bound"
	disp, _ := newDispatcher(t, stubHandler{
		name: grant,
		handle: func(_ context.Context, _ Request) (Response, error) {
			return Response{
				BoundAccessToken: &BoundAccessToken{
					Subject: "user-1",
					TTL:     time.Minute,
				},
				Scope: []string{"read"},
			}, nil
		},
	})
	resp, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if err != nil {
		t.Fatalf("Dispatch err = %v, want nil", err)
	}
	if resp.AccessToken != "" {
		t.Errorf("AccessToken = %q, want empty (BoundAccessToken path)", resp.AccessToken)
	}
	if resp.BoundAccessToken == nil {
		t.Fatalf("BoundAccessToken = nil, want non-nil")
	}
	if resp.BoundAccessToken.Subject != "user-1" {
		t.Errorf("BoundAccessToken.Subject = %q, want user-1", resp.BoundAccessToken.Subject)
	}
}

// TestDispatch_BoundAndAccessTokenConflict verifies that a handler
// returning BOTH AccessToken and BoundAccessToken is rejected with
// ErrConflictingAccessTokenForms. The two fields are mutually
// exclusive; the dispatcher must surface the misuse rather than
// silently preferring one.
func TestDispatch_BoundAndAccessTokenConflict(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:conflict"
	disp, _ := newDispatcher(t, stubHandler{
		name: grant,
		handle: func(_ context.Context, _ Request) (Response, error) {
			return Response{
				AccessToken:      "handler-signed-at",
				BoundAccessToken: &BoundAccessToken{Subject: "user-1"},
			}, nil
		},
	})
	_, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if !errors.Is(err, ErrConflictingAccessTokenForms) {
		t.Fatalf("err = %v, want ErrConflictingAccessTokenForms", err)
	}
}

// TestDispatch_BoundAccessTokenTTLCapped truncates a BoundAccessToken
// TTL above the dispatcher's global cap. The truncation mirrors the
// existing AccessTokenTTL policy so a misbehaving handler cannot mint
// a long-lived bound token by accident.
func TestDispatch_BoundAccessTokenTTLCapped(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:bound-ttl"
	disp, _ := newDispatcher(t,
		stubHandler{
			name: grant,
			handle: func(_ context.Context, _ Request) (Response, error) {
				return Response{
					BoundAccessToken: &BoundAccessToken{
						Subject: "user-1",
						TTL:     24 * time.Hour,
					},
				}, nil
			},
		},
		WithMaxAccessTTL(time.Hour),
	)
	resp, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if err != nil {
		t.Fatalf("Dispatch err = %v", err)
	}
	if resp.BoundAccessToken == nil {
		t.Fatalf("BoundAccessToken = nil")
	}
	if resp.BoundAccessToken.TTL != time.Hour {
		t.Errorf("BoundAccessToken.TTL = %v, want capped to 1h", resp.BoundAccessToken.TTL)
	}
}

// TestDispatch_BoundAccessTokenAudienceInflationRejected verifies the
// dispatcher's audience subset gate also covers BoundAccessToken.Audience.
// A handler that names an audience the client did not register fails
// the same way an AccessToken-path response does.
func TestDispatch_BoundAccessTokenAudienceInflationRejected(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:bound-aud"
	disp, _ := newDispatcher(t, stubHandler{
		name: grant,
		handle: func(_ context.Context, _ Request) (Response, error) {
			return Response{
				BoundAccessToken: &BoundAccessToken{
					Subject:  "user-1",
					Audience: []string{"https://elsewhere.example"},
				},
			}, nil
		},
	})
	_, err := disp.Dispatch(context.Background(), DispatchInput{
		GrantType: grant,
		Client:    newClient(grant),
	})
	if !errors.Is(err, ErrAudienceNotAllowed) {
		t.Fatalf("err = %v, want ErrAudienceNotAllowed", err)
	}
}

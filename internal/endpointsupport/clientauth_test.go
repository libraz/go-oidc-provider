package endpointsupport_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/op/store"
)

// stubClientStore is a minimal [store.ClientStore] that returns
// pre-seeded clients by id; an unknown id surfaces as
// [store.ErrNotFound] so [endpointsupport.LookupClient] applies the
// canonical "invalid client" mapping.
type stubClientStore struct {
	clients map[string]*store.Client
	err     error
}

func (s *stubClientStore) GetClient(_ context.Context, id string) (*store.Client, error) {
	if s.err != nil {
		return nil, s.err
	}
	c, ok := s.clients[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return c, nil
}

// TestLookupClient_NotFoundCollapses pins the canonical posture: every
// "client not resolvable" path returns ErrCredentialsInvalid so the
// caller cannot distinguish "unknown id" from "wrong secret".
func TestLookupClient_NotFoundCollapses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		id    string
		store store.ClientStore
	}{
		{name: "empty id", id: "", store: &stubClientStore{}},
		{name: "nil store", id: "alpha", store: nil},
		{name: "store not-found", id: "alpha", store: &stubClientStore{clients: map[string]*store.Client{}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := endpointsupport.LookupClient(t.Context(), tc.store, tc.id)
			if !errors.Is(err, clientauth.ErrCredentialsInvalid) {
				t.Fatalf("LookupClient: got %v, want ErrCredentialsInvalid", err)
			}
		})
	}
}

// TestLookupClient_PassesThroughOtherErrors confirms that unrelated
// store errors surface unchanged so the caller can collapse them onto
// 500.
func TestLookupClient_PassesThroughOtherErrors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")
	_, err := endpointsupport.LookupClient(t.Context(), &stubClientStore{err: sentinel}, "alpha")
	if !errors.Is(err, sentinel) {
		t.Fatalf("LookupClient: got %v, want sentinel", err)
	}
}

// TestReasonForAuthnError pins the audit-reason mapping so a
// regression that swaps two clientauth sentinels is caught here rather
// than buried in an endpoint integration test.
func TestReasonForAuthnError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{clientauth.ErrNoCredentials, "no_credentials"},
		{clientauth.ErrAmbiguousCredentials, "ambiguous_credentials"},
		{clientauth.ErrUnsupportedMethod, "unsupported_method"},
		{clientauth.ErrClientMismatch, "client_mismatch"},
		{clientauth.ErrCredentialsInvalid, "invalid_client_credentials"},
		{clientauth.ErrAssertionMalformed, "assertion_malformed"},
		{clientauth.ErrAssertionReplayed, "assertion_replayed"},
		{errors.New("unknown"), "server_error"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			got := endpointsupport.ReasonForAuthnError(tc.err)
			if got != tc.want {
				t.Fatalf("ReasonForAuthnError(%v): got %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestWriteAuthnError pins the wire mapping for every clientauth
// sentinel so endpoint regressions show up here.
func TestWriteAuthnError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		err            error
		basic          bool
		wantStatus     int
		wantCode       string
		wantWWWAuth    string // empty means header MUST NOT be set
		wantWWWAuthSet bool
	}{
		{
			name:        "no_credentials_basic",
			err:         clientauth.ErrNoCredentials,
			basic:       true,
			wantStatus:  http.StatusUnauthorized,
			wantCode:    "invalid_client",
			wantWWWAuth: `Basic realm="oidc"`, wantWWWAuthSet: true,
		},
		{
			name: "no_credentials_no_basic", err: clientauth.ErrNoCredentials,
			basic: false, wantStatus: http.StatusUnauthorized, wantCode: "invalid_client",
		},
		{
			name: "ambiguous", err: clientauth.ErrAmbiguousCredentials,
			wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "unsupported_method", err: clientauth.ErrUnsupportedMethod,
			wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "credentials_invalid_basic", err: clientauth.ErrCredentialsInvalid, basic: true,
			wantStatus: http.StatusUnauthorized, wantCode: "invalid_client",
			wantWWWAuth: `Basic realm="oidc"`, wantWWWAuthSet: true,
		},
		{
			name: "assertion_malformed", err: clientauth.ErrAssertionMalformed,
			wantStatus: http.StatusUnauthorized, wantCode: "invalid_client",
		},
		{
			name: "unknown_error", err: errors.New("unexpected"),
			wantStatus: http.StatusInternalServerError, wantCode: "server_error",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			endpointsupport.WriteAuthnError(rec, tc.err, tc.basic)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d", rec.Code, tc.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), `"error":"`+tc.wantCode+`"`) {
				t.Fatalf("body: %q does not carry %q", rec.Body.String(), tc.wantCode)
			}
			got := rec.Header().Get("WWW-Authenticate")
			if tc.wantWWWAuthSet && got != tc.wantWWWAuth {
				t.Fatalf("WWW-Authenticate: got %q, want %q", got, tc.wantWWWAuth)
			}
			if !tc.wantWWWAuthSet && got != "" {
				t.Fatalf("WWW-Authenticate: got %q, want empty", got)
			}
			// every error path stamps no-store / no-cache.
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control: got %q, want %q", rec.Header().Get("Cache-Control"), "no-store")
			}
			if rec.Header().Get("Pragma") != "no-cache" {
				t.Fatalf("Pragma: got %q, want %q", rec.Header().Get("Pragma"), "no-cache")
			}
		})
	}
}

// recordingEmitter captures the events EmitAuthnFailure produces so the
// test can assert on the canonical fields.
type recordingEmitter struct{ events []audit.Event }

func (r *recordingEmitter) Emit(_ context.Context, ev audit.Event) {
	r.events = append(r.events, ev)
}

// TestEmitAuthnFailure_NilSinkSafe confirms the helper can be called
// with a nil emitter — endpoints invoke it unconditionally.
func TestEmitAuthnFailure_NilSinkSafe(t *testing.T) {
	t.Parallel()
	endpointsupport.EmitAuthnFailure(t.Context(), nil, "introspection.error", "msg", "alpha", clientauth.ErrCredentialsInvalid)
}

// TestEmitAuthnFailure_PinsShape pins the audit fields so a regression
// that drops the reason extra is caught here.
func TestEmitAuthnFailure_PinsShape(t *testing.T) {
	t.Parallel()
	rec := &recordingEmitter{}
	endpointsupport.EmitAuthnFailure(t.Context(), rec, "introspection.error", "boom", "alpha", clientauth.ErrCredentialsInvalid)
	if len(rec.events) != 1 {
		t.Fatalf("events: got %d, want 1", len(rec.events))
	}
	ev := rec.events[0]
	if ev.Name != "introspection.error" || ev.ClientID != "alpha" {
		t.Fatalf("event: got %+v", ev)
	}
	if ev.Level != audit.LevelWarn {
		t.Fatalf("level: got %v, want warn", ev.Level)
	}
	if ev.Extras["reason"] != "invalid_client_credentials" {
		t.Fatalf("reason: got %v", ev.Extras["reason"])
	}
}

// TestAuthenticateClient_PrivateKeyJWTDisabled confirms that a request
// presenting a private_key_jwt assertion at an endpoint without an
// AssertionVerifier is rejected as invalid_client and surfaces the
// distinguishable "private_key_jwt_disabled" reason via the failure
// hook.
func TestAuthenticateClient_PrivateKeyJWTDisabled(t *testing.T) {
	t.Parallel()
	// The assertion body must decode as JSON with at least an "iss"
	// claim because clientauth.Parse runs unverifiedAssertionClientID
	// on assertions whose request omits a top-level client_id; an
	// empty body would surface as ErrAssertionMalformed before the
	// AssertionVerifier-disabled gate fires. The signature segment is
	// a placeholder — the helper short-circuits before signature
	// verification when no AssertionVerifier is wired.
	const assertion = "eyJhbGciOiJIUzI1NiJ9." + // base64({"alg":"HS256"})
		"eyJpc3MiOiJjbGllbnQtYWxwaGEifQ." + // base64({"iss":"client-alpha"})
		"sig"
	form := url.Values{}
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	var hookErr error
	_, _, ok := endpointsupport.AuthenticateClient(t.Context(), rec, r,
		endpointsupport.AuthenticateOpts{
			Clients:           &stubClientStore{clients: map[string]*store.Client{}},
			AssertionVerifier: nil,
		},
		func(_ *clientauth.Credentials, err error) { hookErr = err },
	)
	if ok {
		t.Fatalf("AuthenticateClient: unexpectedly succeeded")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if !endpointsupport.IsPrivateKeyJWTDisabled(hookErr) {
		t.Fatalf("hook err: got %v, want IsPrivateKeyJWTDisabled", hookErr)
	}
	if endpointsupport.ReasonForAuthnError(hookErr) != "private_key_jwt_disabled" {
		t.Fatalf("reason: got %q", endpointsupport.ReasonForAuthnError(hookErr))
	}
}

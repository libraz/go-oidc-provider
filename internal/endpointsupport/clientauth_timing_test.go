package endpointsupport_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/op/store"
)

// postBasic drives AuthenticateClient with client_secret_basic
// credentials against clients, returning the recorder and the error the
// failure hook saw.
func postBasic(t *testing.T, clients store.ClientStore, id, secret string) (*httptest.ResponseRecorder, error) {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(id, secret)
	rec := httptest.NewRecorder()

	var hookErr error
	_, _, ok := endpointsupport.AuthenticateClient(t.Context(), rec, r,
		endpointsupport.AuthenticateOpts{Clients: clients},
		func(_ *clientauth.Credentials, err error) { hookErr = err },
	)
	if ok {
		t.Fatalf("AuthenticateClient: unexpectedly succeeded")
	}
	return rec, hookErr
}

// TestAuthenticateClient_UnknownClientPaysTheVerifyCost pins the
// constant-time posture at the layer that actually decides it. An
// unregistered client_id must burn the same work factor a registered
// one with a wrong secret burns, or the endpoint answers "no such
// client" fast enough to be read with a stopwatch — a client-existence
// oracle available to anyone who can reach /token, and the enumeration
// step before any credential attack.
//
// The lookup used to return before VerifyClient ran, which left the
// nil-client branch of the verifier unreachable from production and the
// shim it guards running nowhere. Nothing in a response distinguishes
// the two, which is why this asserts on the shim counter rather than on
// status or body: every wire-level assertion passed throughout.
//
// The test is deliberately sequential. The counter is process-global,
// so a parallel sibling burning its own shim could satisfy the delta
// while this path skipped it.
//
//nolint:paralleltest // reads a process-global counter; see above.
func TestAuthenticateClient_UnknownClientPaysTheVerifyCost(t *testing.T) {
	before := clientauth.DummyVerifyRuns()
	rec, hookErr := postBasic(t, &stubClientStore{clients: map[string]*store.Client{}}, "no-such-client", "whatever")

	if got := clientauth.DummyVerifyRuns() - before; got != 1 {
		t.Fatalf("dummy verify runs: got %d, want 1", got)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if !errors.Is(hookErr, clientauth.ErrCredentialsInvalid) {
		t.Fatalf("hook err: got %v, want ErrCredentialsInvalid", hookErr)
	}
	if got := endpointsupport.ReasonForAuthnError(hookErr); got != "invalid_client_credentials" {
		t.Fatalf("reason: got %q, want invalid_client_credentials", got)
	}
}

// TestAuthenticateClient_StoreFailureSkipsTheVerifyCost pins the other
// half. A backend that cannot answer is not a client-existence signal:
// it fails every lookup identically, so there is nothing to hide, and
// padding it would let a broken store amplify into a memory-cost
// multiplier on every request that arrives during the outage.
//
//nolint:paralleltest // reads a process-global counter; see above.
func TestAuthenticateClient_StoreFailureSkipsTheVerifyCost(t *testing.T) {
	before := clientauth.DummyVerifyRuns()
	_, hookErr := postBasic(t, &stubClientStore{err: errors.New("backend unavailable")}, "alpha", "whatever")

	if got := clientauth.DummyVerifyRuns() - before; got != 0 {
		t.Fatalf("dummy verify runs: got %d, want 0", got)
	}
	if errors.Is(hookErr, clientauth.ErrCredentialsInvalid) {
		t.Fatalf("hook err: got %v, want the store error to survive", hookErr)
	}
}

package grantmgmtendpoint_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/grantmgmtendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// fixedClock is the deterministic wall-clock the handler reads through
// its Clock dependency. The 2026-04-26 anchor matches the sibling suites.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

const gmSecret = "grant-mgmt-secret" //nolint:gosec // G101: test fixture credential.

type recordingAudit struct {
	events []audit.Event
}

func (r *recordingAudit) Emit(_ context.Context, ev audit.Event) {
	r.events = append(r.events, ev)
}

// fixture bundles an inmem store, a confidential client, and an httptest
// server mounting the handler at the {grant_id} pattern the endpoint
// expects. Tests drive the server over the wire — no handler is invoked
// directly.
type fixture struct {
	store    *inmem.Store
	client   *store.Client
	audit    *recordingAudit
	server   *httptest.Server
	clock    fixedClock
	endpoint string
}

// newFixture builds a fixture whose Deps are produced by deps so each test
// can toggle QueryEnabled / RevokeEnabled or swap the grant store. The
// supplied grants store backs the handler; pass nil to use the fixture's
// own inmem grant store.
func newFixture(tb testing.TB, configure func(*grantmgmtendpoint.Deps)) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	st := inmem.New(inmem.WithClock(clock))

	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(gmSecret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := &store.Client{
		ID:                      "client-gm",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		Scopes:                  []string{"openid"},
	}
	if err := st.RegisterClient(context.Background(), client); err != nil {
		tb.Fatalf("RegisterClient: %v", err)
	}

	auditRecorder := &recordingAudit{}
	deps := grantmgmtendpoint.Deps{
		Clients:                  st.Clients(),
		Grants:                   st.Grants(),
		RefreshTokens:            st.RefreshTokens(),
		Audit:                    auditRecorder,
		AllowedClientAuthMethods: []clientauth.Method{clientauth.MethodSecretBasic},
		Clock:                    clock,
	}
	if configure != nil {
		configure(&deps)
	}

	mux := http.NewServeMux()
	mux.Handle("/grant_management/{grant_id}", grantmgmtendpoint.Handler(deps))
	server := httptest.NewServer(mux)
	tb.Cleanup(server.Close)

	return &fixture{
		store:    st,
		client:   client,
		audit:    auditRecorder,
		server:   server,
		clock:    clock,
		endpoint: server.URL + "/grant_management",
	}
}

// seedGrant persists a grant owned by the fixture's confidential client so
// the revoke / 500 tests have an owned target to operate on.
func (f *fixture) seedGrant(tb testing.TB, id string) {
	tb.Helper()
	if err := f.store.Grants().Save(context.Background(), &store.Grant{
		ID:        id,
		Subject:   "user-gm",
		ClientID:  f.client.ID,
		Scope:     []string{"openid"},
		CreatedAt: f.clock.now,
		UpdatedAt: f.clock.now,
	}); err != nil {
		tb.Fatalf("Grants.Save: %v", err)
	}
}

// do issues a request with Basic auth as the fixture's confidential client.
func (f *fixture) do(tb testing.TB, method, grantID string) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, f.endpoint+"/"+grantID, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth(f.client.ID, gmSecret)
	resp, err := f.server.Client().Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}

// decodeError parses an RFC 6749 §5.2 JSON error envelope.
func decodeError(tb testing.TB, resp *http.Response) map[string]string {
	tb.Helper()
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		tb.Fatalf("decode error envelope: %v", err)
	}
	return out
}

// TestHandler_RevokeDisabled_Returns405 pins the action-set gate: with
// RevokeEnabled:false a DELETE is rejected with 405 and the Allow header
// omits DELETE so the endpoint never honours an action the OP did not
// advertise in grant_management_actions_supported. The method-gating runs
// before any grant lookup, so no owned grant is required.
func TestHandler_RevokeDisabled_Returns405(t *testing.T) {
	t.Parallel()

	f := newFixture(t, func(d *grantmgmtendpoint.Deps) {
		d.QueryEnabled = true
		d.RevokeEnabled = false
	})
	resp := f.do(t, http.MethodDelete, "any-grant")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", resp.StatusCode)
	}
	allow := resp.Header.Get("Allow")
	if strings.Contains(allow, http.MethodDelete) {
		t.Errorf("Allow=%q must not advertise DELETE when revoke is disabled", allow)
	}
	if !strings.Contains(allow, http.MethodGet) {
		t.Errorf("Allow=%q should advertise GET (query enabled)", allow)
	}
}

// TestHandler_QueryDisabled_Returns405 is the symmetric gate for the GET
// (query) operation.
func TestHandler_QueryDisabled_Returns405(t *testing.T) {
	t.Parallel()

	f := newFixture(t, func(d *grantmgmtendpoint.Deps) {
		d.QueryEnabled = false
		d.RevokeEnabled = true
	})
	resp := f.do(t, http.MethodGet, "any-grant")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); strings.Contains(allow, http.MethodGet) {
		t.Errorf("Allow=%q must not advertise GET when query is disabled", allow)
	}
}

// TestHandler_RevokeEnabled_DeletesOwnedGrant pins the happy path: with
// RevokeEnabled a DELETE on an owned grant succeeds (204) and the grant is
// gone afterwards.
func TestHandler_RevokeEnabled_DeletesOwnedGrant(t *testing.T) {
	t.Parallel()

	f := newFixture(t, func(d *grantmgmtendpoint.Deps) {
		d.RevokeEnabled = true
	})
	f.seedGrant(t, "grant-owned")

	resp := f.do(t, http.MethodDelete, "grant-owned")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d want 204", resp.StatusCode)
	}
	if _, err := f.store.Grants().Find(context.Background(), "grant-owned"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("grant still present after revoke: err=%v want ErrNotFound", err)
	}
	if got := len(f.audit.events); got != 1 {
		t.Fatalf("audit events=%d want 1", got)
	}
	ev := f.audit.events[0]
	if ev.Name != "grant_management.revoked" {
		t.Errorf("audit name=%q want grant_management.revoked", ev.Name)
	}
	if ev.ClientID != f.client.ID {
		t.Errorf("audit client_id=%q want %q", ev.ClientID, f.client.ID)
	}
	if ev.ActorID != "user-gm" {
		t.Errorf("audit actor_id=%q want user-gm", ev.ActorID)
	}
	if ev.Extras["grant_id"] != "grant-owned" {
		t.Errorf("audit grant_id=%v want grant-owned", ev.Extras["grant_id"])
	}
}

func TestHandler_RevokeEnabled_DeletesDuplicateSubjectClientGrants(t *testing.T) {
	t.Parallel()

	f := newFixture(t, func(d *grantmgmtendpoint.Deps) {
		d.RevokeEnabled = true
	})
	f.seedGrant(t, "grant-visible")
	f.seedGrant(t, "grant-orphan")
	if err := f.store.Grants().Save(context.Background(), &store.Grant{
		ID:        "grant-other-subject",
		Subject:   "other-user",
		ClientID:  f.client.ID,
		Scope:     []string{"openid"},
		CreatedAt: f.clock.now,
		UpdatedAt: f.clock.now,
	}); err != nil {
		t.Fatalf("Grants.Save other subject: %v", err)
	}

	resp := f.do(t, http.MethodDelete, "grant-visible")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d want 204", resp.StatusCode)
	}
	for _, id := range []string{"grant-visible", "grant-orphan"} {
		if _, err := f.store.Grants().Find(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s still present after revoke: err=%v want ErrNotFound", id, err)
		}
	}
	if _, err := f.store.Grants().Find(context.Background(), "grant-other-subject"); err != nil {
		t.Errorf("other subject grant should remain: %v", err)
	}
	if got := len(f.audit.events); got != 1 {
		t.Fatalf("audit events=%d want 1", got)
	}
	ids, ok := f.audit.events[0].Extras["revoked_grant_ids"].([]string)
	if !ok {
		t.Fatalf("revoked_grant_ids has type %T", f.audit.events[0].Extras["revoked_grant_ids"])
	}
	if !slices.Equal(ids, []string{"grant-orphan", "grant-visible"}) {
		t.Fatalf("revoked_grant_ids=%v", ids)
	}
}

// deleteFailsGrantStore wraps a real GrantStore but forces Delete to fail,
// so the test can exercise the serveRevoke server_error path without a mock
// of the wider storage contract.
type deleteFailsGrantStore struct {
	store.GrantStore
}

func (s deleteFailsGrantStore) Delete(context.Context, string) error {
	return errors.New("simulated backend delete failure")
}

type revokeFailsRefreshStore struct {
	store.RefreshTokenStore
}

func (s revokeFailsRefreshStore) RevokeByGrant(context.Context, string) error {
	return errors.New("simulated refresh revoke failure")
}

type revokeFailsOpaqueAccessTokenStore struct {
	store.OpaqueAccessTokenStore
}

func (s revokeFailsOpaqueAccessTokenStore) RevokeByGrant(context.Context, string) (int, error) {
	return 0, errors.New("simulated opaque access-token revoke failure")
}

type revokeFailsAccessTokenRegistry struct {
	store.AccessTokenRegistry
}

func (s revokeFailsAccessTokenRegistry) RevokeByGrant(context.Context, string) (int, error) {
	return 0, errors.New("simulated JWT access-token revoke failure")
}

// TestHandler_RevokeDeleteFailure_Returns500 pins that a failure to delete
// the grant record surfaces as 500 server_error (not a false 204): the
// grant is still live and queryable, so reporting success would be a lie.
func TestHandler_RevokeDeleteFailure_Returns500(t *testing.T) {
	t.Parallel()

	var grants store.GrantStore
	f := newFixture(t, func(d *grantmgmtendpoint.Deps) {
		d.RevokeEnabled = true
		grants = deleteFailsGrantStore{GrantStore: d.Grants}
		d.Grants = grants
	})
	f.seedGrant(t, "grant-stuck")

	resp := f.do(t, http.MethodDelete, "grant-stuck")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", resp.StatusCode)
	}
	body := decodeError(t, resp)
	if body["error"] != "server_error" {
		t.Errorf("error=%v want server_error", body["error"])
	}
	// The grant must remain findable: the revoke did not complete.
	if _, err := f.store.Grants().Find(context.Background(), "grant-stuck"); err != nil {
		t.Errorf("grant should still be findable after a failed revoke: %v", err)
	}
}

// TestHandler_RevokeSecurityCascadeFailure_Returns500 pins the fail-closed
// ordering: no security-revocation failure may be hidden behind a successful
// grant delete and 204 response. Keeping the grant makes the DELETE retryable.
func TestHandler_RevokeSecurityCascadeFailure_Returns500(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*grantmgmtendpoint.Deps)
	}{
		{
			name: "refresh tokens",
			configure: func(d *grantmgmtendpoint.Deps) {
				d.RefreshTokens = revokeFailsRefreshStore{}
			},
		},
		{
			name: "opaque access tokens",
			configure: func(d *grantmgmtendpoint.Deps) {
				d.OpaqueAccessTokens = revokeFailsOpaqueAccessTokenStore{}
			},
		},
		{
			name: "JWT access tokens",
			configure: func(d *grantmgmtendpoint.Deps) {
				d.RevocationStrategy = store.RevocationStrategyJTIRegistry
				d.AccessTokens = revokeFailsAccessTokenRegistry{}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, func(d *grantmgmtendpoint.Deps) {
				d.RevokeEnabled = true
				tt.configure(d)
			})
			f.seedGrant(t, "grant-stuck")

			resp := f.do(t, http.MethodDelete, "grant-stuck")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusInternalServerError {
				t.Fatalf("status=%d want 500", resp.StatusCode)
			}
			body := decodeError(t, resp)
			if body["error"] != "server_error" {
				t.Errorf("error=%v want server_error", body["error"])
			}
			if _, err := f.store.Grants().Find(context.Background(), "grant-stuck"); err != nil {
				t.Errorf("grant should remain retryable after failed cascade: %v", err)
			}
			if got := len(f.audit.events); got != 0 {
				t.Errorf("success audit events=%d want 0", got)
			}
		})
	}
}

// TestHandler_PublicClient_Refused pins that a client registered with
// token_endpoint_auth_method=none cannot reach the endpoint even where
// no profile narrows the accepted authentication methods.
//
// A public client presents a client_id and nothing else, so admitting it
// would leave the grant_id in the request path as the only thing
// standing between a reader of a proxy log and another user's consent
// record — readable through GET, destroyable through DELETE.
func TestHandler_PublicClient_Refused(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newFixture(t, func(d *grantmgmtendpoint.Deps) {
		d.QueryEnabled = true
		d.RevokeEnabled = true
		// No profile is active, so every method a registered client
		// carries is admitted — including "none".
		d.AllowedClientAuthMethods = nil
	})

	publicClient := &store.Client{
		ID:                      "client-public",
		PublicClient:            true,
		TokenEndpointAuthMethod: "none",
		Scopes:                  []string{"openid"},
	}
	if err := f.store.RegisterClient(ctx, publicClient); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if err := f.store.Grants().Save(ctx, &store.Grant{
		ID:        "grant-public",
		Subject:   "user-gm",
		ClientID:  publicClient.ID,
		Scope:     []string{"openid"},
		CreatedAt: f.clock.now,
		UpdatedAt: f.clock.now,
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}

	target := f.endpoint + "/grant-public?client_id=" + publicClient.ID
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, err := http.NewRequestWithContext(ctx, method, target, http.NoBody)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := f.server.Client().Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			resp.Body.Close()
			t.Fatalf("%s status=%d want 401", method, resp.StatusCode)
		}
		if body := decodeError(t, resp); body["error"] != "invalid_client" {
			t.Errorf("%s error=%v want invalid_client", method, body["error"])
		}
		resp.Body.Close()
	}

	if _, err := f.store.Grants().Find(ctx, "grant-public"); err != nil {
		t.Errorf("grant was touched by a refused caller: %v", err)
	}
}

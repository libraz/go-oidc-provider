package op_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// stubStore is a minimal [store.Store] used by tests that need [op.New] to
// pass validation but do not exercise persistence. Methods that the router
// constructor calls eagerly return a no-op substore; the rest panic so that
// a code path that actually uses them is forced to substitute a real store.
type stubStore struct{}

func (stubStore) BeginTx(context.Context) (store.Tx, error) { return stubTx{}, nil }

// Clients is invoked eagerly by buildRouter to wire the /token handler;
// returning a no-op substore lets construction tests exercise op.New
// without seeding a real backend. The stub returns ErrNotFound for every
// lookup so any test that actually issues a /token request would still
// observe the missing-client behaviour.
func (stubStore) Clients() store.ClientStore { return stubClientStore{} }

// AuthorizationCodes is invoked eagerly by buildRouter to wire /token.
func (stubStore) AuthorizationCodes() store.AuthorizationCodeStore { return stubAuthCodeStore{} }

// RefreshTokens is invoked eagerly by buildRouter to wire /token.
func (stubStore) RefreshTokens() store.RefreshTokenStore { return stubRefreshStore{} }

// Grants is invoked eagerly by buildRouter to wire /token.
func (stubStore) Grants() store.GrantStore { return stubGrantStore{} }

// Sessions and Interactions are invoked eagerly by buildRouter to wire the
// /authorize and /interaction handlers; returning no-op substores lets
// construction tests exercise op.New without seeding a real backend.
func (stubStore) Sessions() store.SessionStore                     { return stubSessionStore{} }
func (stubStore) PushedAuthRequests() store.PushedAuthRequestStore { return stubPARStore{} }
func (stubStore) Interactions() store.InteractionStore             { return stubInteractionStore{} }
func (stubStore) ConsumedJTIs() store.ConsumedJTIStore             { return stubJTIStore{} }
func (stubStore) InitialAccessTokens() store.InitialAccessTokenStore {
	panic("not implemented")
}

func (stubStore) RegistrationAccessTokens() store.RegistrationAccessTokenStore {
	panic("not implemented")
}

func (stubStore) AccessTokens() store.AccessTokenRegistry { return stubAccessTokenRegistry{} }

// OpaqueAccessTokens returns nil; construction tests do not exercise
// op.WithAccessTokenFormat(AccessTokenFormatOpaque), so the library's
// fail-fast path that requires a non-nil substore for the opaque
// branch never fires.
func (stubStore) OpaqueAccessTokens() store.OpaqueAccessTokenStore { return nil }

// GrantRevocations is invoked eagerly by construction-time validation
// because the default revocation strategy is GrantTombstone. Returning a
// no-op substore keeps constructor tests focused on the option under
// test while still satisfying the fail-fast contract.
func (stubStore) GrantRevocations() store.GrantRevocationStore { return stubGrantRevocationStore{} }

// Metadata returns nil; construction tests skip the pairwise
// immutability gate, and the library tolerates a nil substore by
// emitting a startup warning and skipping the marker bookkeeping.
func (stubStore) Metadata() store.MetadataStore { return nil }

// DeviceCodes returns nil; construction tests do not enable the
// device_code grant, so the library never exercises this path.
// op.New rejects op.WithDeviceCodeGrant when the substore is missing.
func (stubStore) DeviceCodes() store.DeviceCodeStore { return nil }

// CIBARequests returns nil; construction tests do not enable CIBA, so
// the library never exercises this path. op.New rejects op.WithCIBA
// when the substore is missing.
func (stubStore) CIBARequests() store.CIBARequestStore { return nil }

// noClientsStore wraps [stubStore] and returns nil from Clients() so
// the substore-presence validator at op.New time can be exercised.
// Single-backend adapters (oidcredis when wired without composite)
// produce the same shape; the test confirms the validator catches
// every such config before the first request lands.
type noClientsStore struct{ stubStore }

func (noClientsStore) Clients() store.ClientStore { return nil }

// noSessionsStore wraps [stubStore] and returns nil from Sessions() so
// the SessionStore-presence check can be exercised. The default grant
// set mounts the browser authorize endpoint, which is the exact
// predicate (grantsRequireAuthorizeEndpoint) the runtime uses to decide
// whether it consumes the SessionStore — so a nil here MUST surface at
// op.New rather than at the first /authorize request.
type noSessionsStore struct{ stubStore }

func (noSessionsStore) Sessions() store.SessionStore { return nil }

type storeWithoutTransactions struct {
	store.Store
}

type interactionStoreWithoutCAS struct {
	store.InteractionStore
}

type storeWithoutInteractionCAS struct{ stubStore }

func (storeWithoutInteractionCAS) Interactions() store.InteractionStore {
	return interactionStoreWithoutCAS{InteractionStore: stubInteractionStore{}}
}

// grantStoreWithoutClientLister embeds the store.GrantStore interface so the
// optional ListClientIDsBySubject method stays out of the concrete method set,
// mirroring interactionStoreWithoutCAS. A value of this type satisfies
// store.GrantStore but not store.GrantClientLister.
type grantStoreWithoutClientLister struct {
	store.GrantStore
}

type storeWithoutGrantClientLister struct{ stubStore }

func (storeWithoutGrantClientLister) Grants() store.GrantStore {
	return grantStoreWithoutClientLister{GrantStore: stubGrantStore{}}
}

// refreshStoreWithoutRetry embeds the store.RefreshTokenStore interface so the
// optional retry-response methods stay out of the concrete method set. A value
// of this type satisfies store.RefreshTokenStore but not
// store.RefreshRetryResponseStore.
type refreshStoreWithoutRetry struct {
	store.RefreshTokenStore
}

type storeWithoutRefreshRetry struct{ stubStore }

func (storeWithoutRefreshRetry) RefreshTokens() store.RefreshTokenStore {
	return refreshStoreWithoutRetry{RefreshTokenStore: stubRefreshStore{}}
}

type stubAccessTokenRegistry struct{}

func (stubAccessTokenRegistry) Register(context.Context, store.AccessTokenRecord) error { return nil }

func (stubAccessTokenRegistry) Find(context.Context, string) (*store.AccessTokenRecord, error) {
	return nil, nil //nolint:nilnil // contract permits (nil, nil) for absent records.
}

func (stubAccessTokenRegistry) RevokeByJTI(context.Context, string) error { return nil }

func (stubAccessTokenRegistry) RevokeByGrant(context.Context, string) (int, error) {
	return 0, nil
}

func (stubAccessTokenRegistry) GC(context.Context, time.Time) (int, error) { return 0, nil }

type stubSessionStore struct{}

func (stubSessionStore) Save(context.Context, *store.Session) error { return store.ErrNotFound }

func (stubSessionStore) Find(context.Context, string) (*store.Session, error) {
	return nil, store.ErrNotFound
}

func (stubSessionStore) Touch(context.Context, string, time.Time, time.Time) error {
	return store.ErrNotFound
}

func (stubSessionStore) Delete(context.Context, string) error { return store.ErrNotFound }

func (stubSessionStore) ListByChooserGroup(context.Context, string) ([]*store.Session, error) {
	return nil, nil
}

type stubInteractionStore struct{}

// stubPARStore is the no-op [store.PushedAuthRequestStore] used by
// construction tests so [op.New] can wire the /par handler without
// seeding a real backend. Every method returns ErrNotFound so a test that
// actually drives /par would still observe the missing-record behaviour.
type stubPARStore struct{}

func (stubPARStore) Save(context.Context, *store.PushedAuthRequest) error { return store.ErrNotFound }

func (stubPARStore) Find(context.Context, string) (*store.PushedAuthRequest, error) {
	return nil, store.ErrNotFound
}

func (stubPARStore) Consume(context.Context, string) (*store.PushedAuthRequest, error) {
	return nil, store.ErrNotFound
}

func (stubInteractionStore) Save(context.Context, *store.Interaction) error { return store.ErrNotFound }

func (stubInteractionStore) Find(context.Context, string) (*store.Interaction, error) {
	return nil, store.ErrNotFound
}

func (stubInteractionStore) Delete(context.Context, string) error { return store.ErrNotFound }

func (stubInteractionStore) CompareAndSwap(
	context.Context,
	*store.Interaction,
	*store.Interaction,
) error {
	return store.ErrNotFound
}

func (stubInteractionStore) DeleteIfUnchanged(
	context.Context,
	*store.Interaction,
) error {
	return store.ErrNotFound
}

type stubTx struct{}

func (stubTx) AuthorizationCodes() store.AuthorizationCodeStore { return stubAuthCodeStore{} }
func (stubTx) Grants() store.GrantStore                         { return stubGrantStore{} }
func (stubTx) RefreshTokens() store.RefreshTokenStore           { return stubRefreshStore{} }
func (stubTx) PushedAuthRequests() store.PushedAuthRequestStore { return stubPARStore{} }
func (stubTx) AccessTokens() store.AccessTokenRegistry          { return stubAccessTokenRegistry{} }
func (stubTx) OpaqueAccessTokens() store.OpaqueAccessTokenStore { return nil }
func (stubTx) GrantRevocations() store.GrantRevocationStore     { return stubGrantRevocationStore{} }
func (stubTx) Commit() error                                    { return nil }
func (stubTx) Rollback() error                                  { return nil }

// Users is invoked eagerly by buildRouter to wire the /userinfo handler;
// returning a no-op substore lets construction tests exercise op.New
// without seeding a real backend. The stub returns ErrNotFound for every
// lookup so any test that actually issues a /userinfo request would still
// observe the missing-user behaviour.
func (stubStore) Users() store.UserStore { return stubUserStore{} }

type stubUserStore struct{}

func (stubUserStore) FindBySubject(context.Context, string) (*store.User, error) {
	return nil, store.ErrNotFound
}

type stubClientStore struct{}

func (stubClientStore) GetClient(context.Context, string) (*store.Client, error) {
	return nil, store.ErrNotFound
}

// stubJTIStore is the no-op [store.ConsumedJTIStore] used by construction
// tests so [op.New] can wire the private_key_jwt verifier without seeding
// a real JTI substore. Mark always succeeds (records nothing); Has always
// reports "absent" — a test that actually drives a private_key_jwt
// authentication observes a fresh-replay window each time, which is fine
// for construction smoke tests.
type stubJTIStore struct{}

func (stubJTIStore) Mark(context.Context, string, time.Time) error { return nil }

func (stubJTIStore) Has(context.Context, string) (bool, error) { return false, nil }

type stubAuthCodeStore struct{}

func (stubAuthCodeStore) Save(context.Context, *store.AuthorizationCode) error {
	return store.ErrNotFound
}

func (stubAuthCodeStore) Find(context.Context, string) (*store.AuthorizationCode, error) {
	return nil, store.ErrNotFound
}

func (stubAuthCodeStore) Consume(context.Context, string) (*store.AuthorizationCode, error) {
	return nil, store.ErrNotFound
}

type stubRefreshStore struct{}

func (stubRefreshStore) Save(context.Context, *store.RefreshToken) error {
	return store.ErrNotFound
}

func (stubRefreshStore) Find(context.Context, string) (*store.RefreshToken, error) {
	return nil, store.ErrNotFound
}

func (stubRefreshStore) Consume(context.Context, string) (*store.RefreshToken, error) {
	return nil, store.ErrNotFound
}

func (stubRefreshStore) RevokeChain(context.Context, string) error {
	return store.ErrNotFound
}

func (stubRefreshStore) RevokeByGrant(context.Context, string) error {
	return nil
}

// SaveRotationWithRetry and LoadRetryResponse make stubRefreshStore satisfy
// store.RefreshRetryResponseStore. op.New requires the extension once the
// refresh_token grant and cookie keys are both configured, which is the shape
// most tests in this package build.
func (stubRefreshStore) SaveRotationWithRetry(context.Context, *store.RefreshToken, []byte) error {
	return store.ErrNotFound
}

func (stubRefreshStore) LoadRetryResponse(context.Context, string) ([]byte, error) {
	return nil, store.ErrNotFound
}

type stubGrantStore struct{}

func (stubGrantStore) Save(context.Context, *store.Grant) error {
	return store.ErrNotFound
}

func (stubGrantStore) Find(context.Context, string) (*store.Grant, error) {
	return nil, store.ErrNotFound
}

func (stubGrantStore) FindBySubjectClient(context.Context, string, string) (*store.Grant, error) {
	return nil, store.ErrNotFound
}

type stubGrantRevocationStore struct{}

func (stubGrantRevocationStore) RevokeGrant(context.Context, store.GrantTombstone) error { return nil }

func (stubGrantRevocationStore) RevokeJTI(context.Context, store.RevokedJTI) error { return nil }

func (stubGrantRevocationStore) IsRevoked(context.Context, string, string, time.Time) (bool, error) {
	return false, nil
}

func (stubGrantRevocationStore) GC(context.Context, time.Time) (int, error) { return 0, nil }

func (stubGrantStore) ListBySubject(context.Context, string) ([]*store.Grant, error) {
	return nil, nil
}

func (stubGrantStore) ListClientIDsBySubject(
	context.Context,
	string,
	string,
	int,
) (store.GrantClientPage, error) {
	return store.GrantClientPage{}, nil
}

func (stubGrantStore) Delete(context.Context, string) error {
	return store.ErrNotFound
}

func (stubGrantStore) HasAny(context.Context) (bool, error) { return false, nil }

const validIssuer = "https://idp.example.com"

// fixtureFactor is the [op.FactorType] of the authenticator
// [validBaseOpts] registers. It is deliberately not one of the built-in
// factor constants so a test that registers a real factor of its own
// never collides with the fixture.
const fixtureFactor op.FactorType = "fixture.primary"

// validBaseOpts is the minimal option set that builds a provider. The
// default grant set includes authorization_code, which [op.New] refuses
// to construct without a way to authenticate anyone, so the fixture
// carries an authenticator. Tests exercising [op.WithLoginFlow] — which
// is mutually exclusive with [op.WithAuthenticators] — or the
// authenticator wiring itself want [validBaseOptsNoAuthn] instead.
func validBaseOpts(tb testing.TB) []op.Option {
	tb.Helper()
	return append(validBaseOptsNoAuthn(tb), fixtureAuthenticator())
}

// fixtureAuthenticator is the [op.Option] that satisfies the login
// configuration [op.New] requires alongside the authorization_code
// grant. Tests that assemble their own option slice rather than
// calling [validBaseOpts] append it.
func fixtureAuthenticator() op.Option {
	return op.WithAuthenticators(stubAuthenticator{typ: fixtureFactor, aal: op.AAL1})
}

// validBaseOptsNoAuthn is [validBaseOpts] without the fixture
// authenticator, for tests that supply their own login configuration or
// that assert on what happens when none is supplied.
func validBaseOptsNoAuthn(tb testing.TB) []op.Option {
	tb.Helper()
	return []op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(validKeyset(tb)),
		op.WithCookieKeys(newRandomCookieKey(tb)),
	}
}

func TestNew_RequiresIssuer(t *testing.T) {
	t.Parallel()

	_, err := op.New(op.WithStore(stubStore{}))
	if err == nil {
		t.Fatal("expected error when WithIssuer is missing, got nil")
	}
	if !errors.Is(err, op.ErrIssuerRequired) {
		t.Fatalf("expected ErrIssuerRequired, got %v", err)
	}
	if !op.IsServerError(err) {
		t.Fatal("ErrIssuerRequired should be classified as a server-side configuration error")
	}
	if op.IsClientError(err) {
		t.Fatal("ErrIssuerRequired must not be classified as a client error")
	}
}

func TestNew_RequiresStore(t *testing.T) {
	t.Parallel()

	_, err := op.New(op.WithIssuer(validIssuer))
	if !errors.Is(err, op.ErrStoreRequired) {
		t.Fatalf("expected ErrStoreRequired, got %v", err)
	}
	if !op.IsServerError(err) {
		t.Fatal("ErrStoreRequired should be classified as a server-side configuration error")
	}
}

// TestNew_RejectsMissingClientStore pins the rule that a store
// returning nil from Clients() MUST surface a configuration error
// at op.New rather than crashing the first request that touches
// the substore. The check is the unified replacement for the
// per-adapter panic policy that single-backend stores (e.g. the
// Redis adapter for out-of-scope substores) used to ship.
func TestNew_RejectsMissingClientStore(t *testing.T) {
	t.Parallel()

	_, err := op.New(append([]op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(noClientsStore{}),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
	}, []op.Option{}...)...)
	if err == nil {
		t.Fatal("expected configuration error for missing ClientStore")
	}
	if !op.IsServerError(err) {
		t.Errorf("missing ClientStore must surface as server configuration error: %v", err)
	}
}

// TestNew_RejectsMissingSessionStore pins that a store returning nil
// from Sessions() under a grant set that mounts the browser authorize
// endpoint surfaces a configuration error at op.New, not a nil-deref
// when the session manager is built. The default grant set satisfies
// the gate, so the bare wrapper is enough to trigger it.
func TestNew_RejectsMissingSessionStore(t *testing.T) {
	t.Parallel()

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(noSessionsStore{}),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
	)
	if err == nil {
		t.Fatal("expected configuration error for missing SessionStore")
	}
	if !strings.Contains(err.Error(), "SessionStore") {
		t.Errorf("err = %v, want it to mention SessionStore", err)
	}
	if !op.IsServerError(err) {
		t.Errorf("missing SessionStore must surface as server configuration error: %v", err)
	}
}

func TestNew_RejectsAuthorizationCodeStoreWithoutTransactions(t *testing.T) {
	t.Parallel()

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(storeWithoutTransactions{Store: stubStore{}}),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
	)
	if err == nil {
		t.Fatal("expected configuration error for missing Transactional capability")
	}
	if !strings.Contains(err.Error(), "Transactional") {
		t.Errorf("err = %v, want it to mention Transactional", err)
	}
}

func TestNew_RejectsAuthorizationCodeStoreWithoutInteractionCAS(t *testing.T) {
	t.Parallel()

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(storeWithoutInteractionCAS{}),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
	)
	if err == nil {
		t.Fatal("expected configuration error for missing InteractionStoreCAS capability")
	}
	if !strings.Contains(err.Error(), "InteractionStoreCAS") {
		t.Errorf("err = %v, want it to mention InteractionStoreCAS", err)
	}
}

func TestNew_RejectsAuthorizationCodeStoreWithoutGrantClientLister(t *testing.T) {
	t.Parallel()

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(storeWithoutGrantClientLister{}),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
	)
	if err == nil {
		t.Fatal("expected configuration error for missing GrantClientLister capability")
	}
	if !strings.Contains(err.Error(), "GrantClientLister") {
		t.Errorf("err = %v, want it to mention GrantClientLister", err)
	}
}

// The refresh rotation path seals a retry response whenever it holds
// encryption keys, and those keys are the cookie keys. A backend missing the
// extension used to construct cleanly and then fail every rotation at request
// time, so the rejection has to happen here.
func TestNew_RejectsRefreshGrantStoreWithoutRetryResponses(t *testing.T) {
	t.Parallel()

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(storeWithoutRefreshRetry{}),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
	)
	if err == nil {
		t.Fatal("expected configuration error for missing RefreshRetryResponseStore capability")
	}
	if !strings.Contains(err.Error(), "RefreshRetryResponseStore") {
		t.Errorf("err = %v, want it to mention RefreshRetryResponseStore", err)
	}
}

// Dropping the refresh_token grant removes the rotation path entirely, so the
// same backend must construct without complaint.
func TestNew_AllowsMissingRetryResponsesWithoutRefreshGrant(t *testing.T) {
	t.Parallel()

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(storeWithoutRefreshRetry{}),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithGrants(grant.AuthorizationCode),
		fixtureAuthenticator(),
	)
	if err != nil {
		t.Fatalf("unexpected error without the refresh_token grant: %v", err)
	}
}

func TestNew_AcceptsValidConfiguration(t *testing.T) {
	t.Parallel()

	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestWithIssuer_RejectsMalformedURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		issuer string
		want   error
	}{
		{"empty", "", op.ErrIssuerRequired},
		{"http-public-host", "http://idp.example.com", op.ErrIssuerInvalid},
		{"http-localhost-textual", "http://localhost:8080", op.ErrIssuerInvalid},
		{"with query", "https://idp.example.com?x=1", op.ErrIssuerInvalid},
		{"with fragment", "https://idp.example.com#x", op.ErrIssuerInvalid},
		{"trailing slash", "https://idp.example.com/", op.ErrIssuerInvalid},
		{"relative", "/idp", op.ErrIssuerInvalid},
		{"empty host with path", "https:///idp", op.ErrIssuerInvalid},
		{"empty host bare", "https://", op.ErrIssuerInvalid},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(op.WithIssuer(tc.issuer), op.WithStore(stubStore{}))
			if !errors.Is(err, tc.want) {
				t.Fatalf("op.New(%q): want %v, got %v", tc.issuer, tc.want, err)
			}
		})
	}
}

// TestWithIssuer_AcceptsLoopbackHTTP verifies the OIDC Discovery 1.0 §3 /
// FAPI 2.0 §5.4 carve-out for plain http: it is admitted when the host is a
// loopback IP literal (127.0.0.0/8 or [::1]) so a development boot can use
// http://127.0.0.1:port without fronting TLS. The validator delegates to
// internal/discovery.ValidateIssuer, so this also pins that the option
// site and the metadata-build pass agree.
func TestWithIssuer_AcceptsLoopbackHTTP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		issuer string
	}{
		{"http-loopback-v4", "http://127.0.0.1:8080"},
		{"http-loopback-v4-secondary", "http://127.0.0.2:8080"},
		{"http-loopback-v6", "http://[::1]:8080"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			provider, err := op.New(append(validBaseOpts(t), op.WithIssuer(tc.issuer))...)
			if err != nil {
				t.Fatalf("op.New(%q) unexpected error: %v", tc.issuer, err)
			}
			if provider == nil {
				t.Fatalf("op.New(%q) returned nil provider", tc.issuer)
			}
		})
	}
}

// TestWithIssuer_LocalhostNeedsTheOptIn pins both sides of the textual
// "localhost" carve-out. The default posture refuses it — the host can be
// DNS-hijacked where an IP literal cannot — and
// [op.WithAllowLocalhostLoopback] admits it, which is the only way to run
// a local WebAuthn deployment without TLS: a Relying Party ID must be a
// domain, so an http issuer on an IP literal has none to pair with.
//
// Both option orders are exercised because the check runs in the
// validation pass rather than at the WithIssuer call site, and an
// order-sensitive rule here would be a configuration that boots or fails
// depending on how the call was formatted.
func TestWithIssuer_LocalhostNeedsTheOptIn(t *testing.T) {
	t.Parallel()

	const issuer = "http://localhost:8080"

	t.Run("refused-by-default", func(t *testing.T) {
		t.Parallel()
		_, err := op.New(append(validBaseOpts(t), op.WithIssuer(issuer))...)
		if !errors.Is(err, op.ErrIssuerInvalid) {
			t.Fatalf("op.New(%q): want ErrIssuerInvalid, got %v", issuer, err)
		}
	})

	for _, tc := range []struct {
		name string
		opts func(*testing.T) []op.Option
	}{
		{
			name: "opt-in-after-issuer",
			opts: func(t *testing.T) []op.Option {
				return append(validBaseOpts(t), op.WithIssuer(issuer), op.WithAllowLocalhostLoopback())
			},
		},
		{
			name: "opt-in-before-issuer",
			opts: func(t *testing.T) []op.Option {
				return append(validBaseOpts(t), op.WithAllowLocalhostLoopback(), op.WithIssuer(issuer))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			provider, err := op.New(tc.opts(t)...)
			if err != nil {
				t.Fatalf("op.New(%q) unexpected error: %v", issuer, err)
			}
			if provider == nil {
				t.Fatalf("op.New(%q) returned nil provider", issuer)
			}
		})
	}
}

// TestWithIssuer_OptInDoesNotAdmitPublicHosts confirms the carve-out is
// scoped to the one host it names. Widening it to any http host would
// turn a development affordance into a way to publish an issuer no RP can
// verify the origin of.
func TestWithIssuer_OptInDoesNotAdmitPublicHosts(t *testing.T) {
	t.Parallel()

	for _, issuer := range []string{
		"http://idp.example.com",
		"http://localhost.example.com:8080",
		"http://notlocalhost:8080",
	} {
		t.Run(issuer, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t), op.WithIssuer(issuer), op.WithAllowLocalhostLoopback())...)
			if !errors.Is(err, op.ErrIssuerInvalid) {
				t.Fatalf("op.New(%q): want ErrIssuerInvalid, got %v", issuer, err)
			}
		})
	}
}

func TestWithStore_RejectsNil(t *testing.T) {
	t.Parallel()

	_, err := op.New(op.WithIssuer(validIssuer), op.WithStore(nil))
	if !errors.Is(err, op.ErrStoreRequired) {
		t.Fatalf("expected ErrStoreRequired for nil store, got %v", err)
	}
}

func TestWithStore_RejectsTypedNil(t *testing.T) {
	t.Parallel()

	var typedNil *inmem.Store
	_, err := op.New(op.WithIssuer(validIssuer), op.WithStore(typedNil))
	if !errors.Is(err, op.ErrStoreRequired) {
		t.Fatalf("expected ErrStoreRequired for typed-nil store, got %v", err)
	}
}

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

func TestWithClock_AcceptedAndUsable(t *testing.T) {
	t.Parallel()

	want := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	provider, err := op.New(append(validBaseOpts(t), op.WithClock(fakeClock{now: want}))...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestWithLogger_AcceptedAndUsable(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(testingDiscard{}, nil))
	provider, err := op.New(append(validBaseOpts(t), op.WithLogger(logger))...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

// testingDiscard is an [io.Writer] that drops every write. It exists so the
// logger test does not depend on [io.Discard()] behaviour or a buffer.
type testingDiscard struct{}

func (testingDiscard) Write(p []byte) (int, error) { return len(p), nil }

// Compile-time interface satisfaction checks.
var (
	_ op.Clock        = fakeClock{}
	_ store.Store     = stubStore{}
	_ context.Context // ensure context import is used by the file
)

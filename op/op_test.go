package op_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// stubStore is a minimal [store.Store] used by tests that need [op.New] to
// pass validation but do not exercise persistence. Methods that the router
// constructor calls eagerly return a no-op substore; the rest panic so that
// a code path that actually uses them is forced to substitute a real store.
type stubStore struct{}

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

// GrantRevocations returns nil; construction tests do not exercise the
// grant-tombstone JWT access-token revocation strategy (ADR 0025) so
// the library's fail-fast path that requires a non-nil substore never
// fires.
func (stubStore) GrantRevocations() store.GrantRevocationStore { return nil }

// Metadata returns nil; construction tests skip the pairwise
// immutability gate, and the library tolerates a nil substore by
// emitting a startup warning and skipping the marker bookkeeping.
func (stubStore) Metadata() store.MetadataStore { return nil }

// DeviceCodes returns nil; construction tests do not enable the
// device_code grant, so the library never exercises this path.
// op.New rejects op.WithDeviceCodeGrant when the substore is missing.
func (stubStore) DeviceCodes() store.DeviceCodeStore { return nil }

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

func (stubGrantStore) ListBySubject(context.Context, string) ([]*store.Grant, error) {
	return nil, nil
}

func (stubGrantStore) Delete(context.Context, string) error {
	return store.ErrNotFound
}

func (stubGrantStore) HasAny(context.Context) (bool, error) { return false, nil }

const validIssuer = "https://idp.example.com"

func validBaseOpts(tb testing.TB) []op.Option {
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
// [internal/discovery.ValidateIssuer], so this also pins that the option
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

func TestWithStore_RejectsNil(t *testing.T) {
	t.Parallel()

	_, err := op.New(op.WithIssuer(validIssuer), op.WithStore(nil))
	if !errors.Is(err, op.ErrStoreRequired) {
		t.Fatalf("expected ErrStoreRequired for nil store, got %v", err)
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

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
// pass validation but do not exercise persistence. The methods panic so that
// any code path calling them in a test is forced to substitute a real store.
type stubStore struct{}

func (stubStore) Clients() store.ClientStore                       { panic("not implemented") }
func (stubStore) AuthorizationCodes() store.AuthorizationCodeStore { panic("not implemented") }
func (stubStore) RefreshTokens() store.RefreshTokenStore           { panic("not implemented") }
func (stubStore) Grants() store.GrantStore                         { panic("not implemented") }
func (stubStore) Sessions() store.SessionStore                     { panic("not implemented") }
func (stubStore) PushedAuthRequests() store.PushedAuthRequestStore { panic("not implemented") }
func (stubStore) Interactions() store.InteractionStore             { panic("not implemented") }
func (stubStore) ConsumedJTIs() store.ConsumedJTIStore             { panic("not implemented") }
func (stubStore) Users() store.UserStore                           { panic("not implemented") }

const validIssuer = "https://idp.example.com"

func validBaseOpts(tb testing.TB) []op.Option {
	tb.Helper()
	return []op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(validKeyset(tb)),
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
		{"http", "http://idp.example.com", op.ErrIssuerInvalid},
		{"with query", "https://idp.example.com?x=1", op.ErrIssuerInvalid},
		{"with fragment", "https://idp.example.com#x", op.ErrIssuerInvalid},
		{"relative", "/idp", op.ErrIssuerInvalid},
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
// logger test does not depend on [io.Discard] behaviour or a buffer.
type testingDiscard struct{}

func (testingDiscard) Write(p []byte) (int, error) { return len(p), nil }

// Compile-time interface satisfaction checks.
var (
	_ op.Clock        = fakeClock{}
	_ store.Store     = stubStore{}
	_ context.Context // ensure context import is used by the file
)

package op_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// hashIATValueForTest mirrors the SHA-256 hex digest the library
// computes from an IAT bearer secret before persisting it. The helper
// lives here because op/registration.go's hashIATSecret is unexported;
// the formula is part of the contract documented on
// store.InitialAccessToken.HashedValue.
func hashIATValueForTest(tb testing.TB, secret string) string {
	tb.Helper()
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// noIATStore is a [store.Store] decorator that returns nil for the
// InitialAccessTokens substore so the WithDynamicRegistration cross-cut
// validation surfaces the missing substore as a configuration error.
type noIATStore struct{ *inmem.Store }

func (noIATStore) InitialAccessTokens() store.InitialAccessTokenStore { return nil }

// noRATStore is a [store.Store] decorator that returns nil for the
// RegistrationAccessTokens substore so the WithDynamicRegistration cross-cut
// validation surfaces the missing substore as a configuration error.
type noRATStore struct{ *inmem.Store }

func (noRATStore) RegistrationAccessTokens() store.RegistrationAccessTokenStore { return nil }

// nonRegistryStore is a [store.Store] that does not implement
// [store.ClientRegistry]. The struct embeds the inmem store via composition
// over a private pointer so the type assertion in op.validateRegistration
// fails even though every required substore is wired.
type nonRegistryStore struct {
	inner *inmem.Store
}

func (s nonRegistryStore) Clients() store.ClientStore { return s.inner.Clients() }
func (s nonRegistryStore) AuthorizationCodes() store.AuthorizationCodeStore {
	return s.inner.AuthorizationCodes()
}
func (s nonRegistryStore) RefreshTokens() store.RefreshTokenStore { return s.inner.RefreshTokens() }
func (s nonRegistryStore) Grants() store.GrantStore               { return s.inner.Grants() }
func (s nonRegistryStore) Sessions() store.SessionStore           { return s.inner.Sessions() }
func (s nonRegistryStore) PushedAuthRequests() store.PushedAuthRequestStore {
	return s.inner.PushedAuthRequests()
}
func (s nonRegistryStore) Interactions() store.InteractionStore { return s.inner.Interactions() }
func (s nonRegistryStore) ConsumedJTIs() store.ConsumedJTIStore { return s.inner.ConsumedJTIs() }
func (s nonRegistryStore) Users() store.UserStore               { return s.inner.Users() }
func (s nonRegistryStore) InitialAccessTokens() store.InitialAccessTokenStore {
	return s.inner.InitialAccessTokens()
}

func (s nonRegistryStore) RegistrationAccessTokens() store.RegistrationAccessTokenStore {
	return s.inner.RegistrationAccessTokens()
}

func (s nonRegistryStore) AccessTokens() store.AccessTokenRegistry {
	return s.inner.AccessTokens()
}

func (s nonRegistryStore) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return s.inner.OpaqueAccessTokens()
}

func (s nonRegistryStore) GrantRevocations() store.GrantRevocationStore {
	return s.inner.GrantRevocations()
}

func (s nonRegistryStore) Metadata() store.MetadataStore { return s.inner.Metadata() }

func (s nonRegistryStore) DeviceCodes() store.DeviceCodeStore { return s.inner.DeviceCodes() }

func (s nonRegistryStore) CIBARequests() store.CIBARequestStore { return s.inner.CIBARequests() }

// dcrBaseOpts returns the option slice that satisfies op.New for a
// DCR-enabled provider when paired with WithDynamicRegistration. The
// helper centralises the deterministic clock so tests that observe
// IAT expiry can pin "now" precisely.
func dcrBaseOpts(tb testing.TB, s store.Store, clock op.Clock) []op.Option {
	tb.Helper()
	return []op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(s),
		op.WithKeyset(validKeyset(tb)),
		op.WithCookieKeys(newRandomCookieKey(tb)),
		op.WithClock(clock),
		fixtureAuthenticator(),
	}
}

// dcrFixedClock is a deterministic clock anchored at the project's
// "today" baseline so IAT issuance / expiry tests share an identical
// view of "now" with the provider under test.
func dcrFixedClock() fakeClock {
	return fakeClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
}

// configurationDescription extracts the Description from a configuration_error
// [*op.Error]. Tests use it to pin the wire-stable description string the
// library returns, which is the only way to distinguish "missing
// substore" from "feature flag drift" since [*op.Error.Is] compares
// Codes only and every configuration_error therefore matches every
// other.
func configurationDescription(tb testing.TB, err error) string {
	tb.Helper()
	var e *op.Error
	if !errors.As(err, &e) {
		tb.Fatalf("error is not *op.Error: %v", err)
	}
	return e.Description
}

func TestWithDynamicRegistration_RejectsMissingIATStore(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := noIATStore{Store: inmem.New(inmem.WithClock(clock))}
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected configuration error for missing IAT substore, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("missing substore must be classified as a server-side configuration error: %v", err)
	}
	desc := configurationDescription(t, err)
	if !strings.Contains(desc, "InitialAccessTokens") {
		t.Errorf("description=%q must mention the missing InitialAccessTokens substore", desc)
	}
}

func TestWithDynamicRegistration_RejectsMissingRATStore(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := noRATStore{Store: inmem.New(inmem.WithClock(clock))}
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected configuration error for missing RAT substore, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("missing substore must be classified as a server-side configuration error: %v", err)
	}
	desc := configurationDescription(t, err)
	if !strings.Contains(desc, "RegistrationAccessTokens") {
		t.Errorf("description=%q must mention the missing RegistrationAccessTokens substore", desc)
	}
}

func TestWithDynamicRegistration_RejectsStoreWithoutClientRegistry(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := nonRegistryStore{inner: inmem.New(inmem.WithClock(clock))}
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected configuration error when store does not implement ClientRegistry")
	}
	if !op.IsServerError(err) {
		t.Errorf("missing ClientRegistry must be classified as a server-side configuration error: %v", err)
	}
}

func TestWithDynamicRegistration_RejectsNegativeIATTTL(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{IATTTL: -time.Second}),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected configuration error for negative IATTTL, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("negative IATTTL must surface as server configuration error: %v", err)
	}
}

func TestWithDynamicRegistration_RejectsNegativeIATUses(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{IATUses: -1}),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected configuration error for negative IATUses, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("negative IATUses must surface as server configuration error: %v", err)
	}
}

func TestWithDynamicRegistration_RejectsUnknownGrantType(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{
			AllowedGrantTypes: []string{"client_credentials"},
		}),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected configuration error for unsupported grant_type in DCR allowlist")
	}
	if !op.IsServerError(err) {
		t.Errorf("unsupported grant_type must surface as server configuration error: %v", err)
	}
}

func TestWithDynamicRegistration_RejectsNonCodeResponseType(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{
			AllowedResponseTypes: []string{"token"},
		}),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected configuration error for non-code response_type in DCR allowlist")
	}
	if !op.IsServerError(err) {
		t.Errorf("non-code response_type must surface as server configuration error: %v", err)
	}
}

// TestWithDynamicRegistration_RejectsUnknownOpenDefaultScope pins
// the construction-time guard: an OpenRegistrationDefaultScopes
// entry that names a scope no [WithScope] call (or the
// standard-scope auto-fill) registered MUST fail [op.New] rather
// than silently producing a runtime invalid_client_metadata on
// every open registration.
func TestWithDynamicRegistration_RejectsUnknownOpenDefaultScope(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{
			Open:                          true,
			OpenRegistrationDefaultScopes: []string{"openid", "definitely-not-registered"},
		}),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected configuration error for unknown scope in OpenRegistrationDefaultScopes")
	}
	if !op.IsServerError(err) {
		t.Errorf("unknown scope must surface as server configuration error: %v", err)
	}
}

// TestWithDynamicRegistration_RejectsEmptyOpenDefaultScope pins the
// invariant that an embedder who supplies
// OpenRegistrationDefaultScopes MUST not include the empty string —
// the registry has no anonymous entry, and a silent skip would mask
// a typo.
func TestWithDynamicRegistration_RejectsEmptyOpenDefaultScope(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{
			Open:                          true,
			OpenRegistrationDefaultScopes: []string{"openid", ""},
		}),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected configuration error for empty scope entry")
	}
	if !op.IsServerError(err) {
		t.Errorf("empty scope must surface as server configuration error: %v", err)
	}
}

func TestWithDynamicRegistration_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{}),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected configuration error when WithDynamicRegistration is supplied twice")
	}
	if !op.IsServerError(err) {
		t.Errorf("duplicate WithDynamicRegistration must surface as server configuration error: %v", err)
	}
}

// TestWithDynamicRegistration_RejectsRedundantFeatureFlag confirms that an
// embedder who passes feature.DynamicRegistration through WithFeature in
// addition to WithDynamicRegistration receives a deterministic configuration
// error rather than silent double-enablement.
//
// Both call orders are covered because WithFeature is idempotent: it
// returns without touching the config when the flag is already present.
// A duplicate check that lived at the option site therefore only saw the
// second declaration in one of the two orders, and the same
// configuration booted or failed depending on the order the embedder
// happened to list the options in.
func TestWithDynamicRegistration_RejectsRedundantFeatureFlag(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts func(t *testing.T) []op.Option
	}{
		{
			name: "flag first",
			opts: func(t *testing.T) []op.Option {
				t.Helper()
				clock := dcrFixedClock()
				return append(dcrBaseOpts(t, inmem.New(inmem.WithClock(clock)), clock),
					op.WithFeature(feature.DynamicRegistration),
					op.WithDynamicRegistration(op.RegistrationOption{}),
				)
			},
		},
		{
			name: "option first",
			opts: func(t *testing.T) []op.Option {
				t.Helper()
				clock := dcrFixedClock()
				return append(dcrBaseOpts(t, inmem.New(inmem.WithClock(clock)), clock),
					op.WithDynamicRegistration(op.RegistrationOption{}),
					op.WithFeature(feature.DynamicRegistration),
				)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := op.New(tc.opts(t)...)
			if err == nil {
				t.Fatal("expected configuration error when feature flag and option are both supplied")
			}
			if !op.IsServerError(err) {
				t.Errorf("redundant feature flag must surface as server configuration error: %v", err)
			}
			if desc := configurationDescription(t, err); !strings.Contains(desc, "more than once") {
				t.Errorf("description=%q must report the duplicate declaration", desc)
			}
		})
	}
}

func TestWithDynamicRegistration_AcceptsZeroValue(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New rejected zero-value RegistrationOption: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}

	// The defaults documented on RegistrationOption must be applied when
	// the option is supplied with zero-value fields. We verify by issuing
	// an IAT and checking the ExpiresAt is at least one default IATTTL
	// (24h) ahead of the deterministic clock.
	issued, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}
	want := clock.now.Add(24 * time.Hour)
	if !issued.ExpiresAt.Equal(want) {
		t.Errorf("default IATTTL (24h) expected ExpiresAt=%s, got %s", want, issued.ExpiresAt)
	}
}

func TestProvider_IssueInitialAccessToken_DCRDisabled(t *testing.T) {
	t.Parallel()

	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	_, err = provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if !errors.Is(err, op.ErrDynamicRegistrationDisabled) {
		t.Fatalf("expected ErrDynamicRegistrationDisabled, got %v", err)
	}
}

func TestProvider_IssueInitialAccessToken_HappyPath(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{
			IATTTL:  time.Hour,
			IATUses: 3,
		}),
	)
	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	issued, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}
	if issued.ID == "" {
		t.Error("issued.ID must not be empty")
	}
	if issued.Value == "" {
		t.Error("issued.Value must not be empty")
	}
	want := clock.now.Add(time.Hour)
	if !issued.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt=%s want %s", issued.ExpiresAt, want)
	}
	// Issuance must produce fresh material on every call: two back-to-back
	// IATs MUST differ in both ID and Value.
	other, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("second IssueInitialAccessToken: %v", err)
	}
	if other.ID == issued.ID {
		t.Error("two IATs share an ID; randomness contract broken")
	}
	if other.Value == issued.Value {
		t.Error("two IATs share a Value; randomness contract broken")
	}
}

func TestProvider_IssueInitialAccessToken_AppliesDefaults(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{
			IATTTL:  2 * time.Hour,
			IATUses: 5,
		}),
	)
	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	// Spec leaves TTL / MaxUses zero; option-level defaults must apply.
	issued, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}
	wantExpiry := clock.now.Add(2 * time.Hour)
	if !issued.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("default TTL not applied: ExpiresAt=%s want %s", issued.ExpiresAt, wantExpiry)
	}
	// Lookup the underlying record to verify MaxUses defaulted to 5.
	rec, lookErr := s.InitialAccessTokens().GetByHash(context.Background(), hashIATValueForTest(t, issued.Value))
	if lookErr != nil {
		t.Fatalf("GetByHash: %v", lookErr)
	}
	if rec.MaxUses != 5 {
		t.Errorf("MaxUses=%d want 5 (option default)", rec.MaxUses)
	}
}

func TestProvider_IssueInitialAccessToken_PersistsAllowedScopesAndTag(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	issued, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{
		AllowedScopes: []string{"openid", "profile"},
		Tag:           "tenant-acme-2026-04",
	})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}
	rec, lookErr := s.InitialAccessTokens().GetByHash(context.Background(), hashIATValueForTest(t, issued.Value))
	if lookErr != nil {
		t.Fatalf("GetByHash: %v", lookErr)
	}
	if got := strings.Join(rec.AllowedScopes, " "); got != "openid profile" {
		t.Errorf("AllowedScopes=%q want %q", got, "openid profile")
	}
	if rec.Tag != "tenant-acme-2026-04" {
		t.Errorf("Tag=%q want tenant-acme-2026-04", rec.Tag)
	}
}

func TestProvider_IssueInitialAccessToken_RejectsNegativeTTL(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	_, err = provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{
		TTL: -time.Second,
	})
	if err == nil {
		t.Fatal("expected error for negative TTL, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("negative TTL must surface as a server-side configuration error: %v", err)
	}
}

func TestProvider_IssueInitialAccessToken_RejectsNegativeMaxUses(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	_, err = provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{
		MaxUses: -1,
	})
	if err == nil {
		t.Fatal("expected error for negative MaxUses, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("negative MaxUses must surface as a server-side configuration error: %v", err)
	}
}

func TestProvider_RevokeInitialAccessToken_DCRDisabled(t *testing.T) {
	t.Parallel()

	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if err := provider.RevokeInitialAccessToken(context.Background(), "any"); !errors.Is(err, op.ErrDynamicRegistrationDisabled) {
		t.Fatalf("expected ErrDynamicRegistrationDisabled, got %v", err)
	}
}

func TestProvider_RevokeInitialAccessToken_HappyPath(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	issued, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}
	// Issue a second IAT so we can confirm revocation does not affect siblings.
	other, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken (second): %v", err)
	}
	if err := provider.RevokeInitialAccessToken(context.Background(), issued.ID); err != nil {
		t.Fatalf("RevokeInitialAccessToken: %v", err)
	}
	// The revoked IAT must be absent from the store.
	if _, err := s.InitialAccessTokens().GetByHash(context.Background(), hashIATValueForTest(t, issued.Value)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("revoked IAT lookup: want ErrNotFound, got %v", err)
	}
	// The sibling IAT must still resolve cleanly.
	if _, err := s.InitialAccessTokens().GetByHash(context.Background(), hashIATValueForTest(t, other.Value)); err != nil {
		t.Errorf("unrelated IAT lookup: want nil, got %v", err)
	}
}

// TestProvider_RevokeInitialAccessToken_NotFoundIsIdempotent pins the
// "missing token is not an error" semantics: the operation's
// post-condition is "the token does not exist", which holds whether
// the row was deleted by this call or had already been deleted by a
// prior one. Returning store.ErrNotFound would force every embedder
// to wrap the call in errors.Is just to defend against the harmless
// concurrent-revoke race.
func TestProvider_RevokeInitialAccessToken_NotFoundIsIdempotent(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if err := provider.RevokeInitialAccessToken(context.Background(), "no-such-id"); err != nil {
		t.Fatalf("missing IAT must report success, got %v", err)
	}
	// Second revoke after a successful issue+revoke MUST also report
	// success: the post-condition still holds.
	issued, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}
	if err := provider.RevokeInitialAccessToken(context.Background(), issued.ID); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	secondErr := provider.RevokeInitialAccessToken(context.Background(), issued.ID)
	if secondErr != nil {
		t.Fatalf("second revoke must be idempotent, got %v", secondErr)
	}
	// store.ErrNotFound MUST NOT propagate through the public
	// surface: callers branch on idempotent success, not on the
	// internal error sentinel. Pin the contract explicitly so a
	// regression that re-introduced the wrapping fails this test
	// rather than the implicit nil-check above.
	if errors.Is(secondErr, store.ErrNotFound) {
		t.Errorf("ErrNotFound leaked through the public surface: %v", secondErr)
	}
}

func TestProvider_RevokeInitialAccessToken_RejectsEmptyID(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	opts := append(dcrBaseOpts(t, s, clock),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	err = provider.RevokeInitialAccessToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty IAT id, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("empty id must surface as a server-side configuration error: %v", err)
	}
}

// TestIntegration_DCR_IssuerPath_ClientManagementIsReachable drives the
// RFC 7592 management endpoint under an issuer that carries a path, the
// shape a multi-tenant deployment has. An issuer path is part of the
// public endpoint namespace, so the handler is mounted below it; the
// registration_client_uri the OP itself advertises therefore also carries
// it, and every read / update / delete an RP performs against that URL
// must be classified as a management request rather than as a second
// registration under a longer path.
func TestIntegration_DCR_IssuerPath_ClientManagementIsReachable(t *testing.T) {
	t.Parallel()

	const tenantIssuer = validIssuer + "/tenant"

	clock := dcrFixedClock()
	s := inmem.New(inmem.WithClock(clock))
	provider, err := op.New(
		op.WithIssuer(tenantIssuer),
		op.WithStore(s),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithClock(clock),
		fixtureAuthenticator(),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)

	iat, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}

	created := postJSON(t, srv.URL+"/tenant/oidc/register", iat.Value,
		map[string]any{"redirect_uris": []string{"https://rp.test.invalid/callback"}})
	if created.status != http.StatusCreated {
		t.Fatalf("POST /register: status=%d want 201 body=%s", created.status, created.raw)
	}
	manageURL, _ := created.body["registration_client_uri"].(string)
	rat, _ := created.body["registration_access_token"].(string)
	clientID, _ := created.body["client_id"].(string)
	if manageURL == "" || rat == "" || clientID == "" {
		t.Fatalf("registration response is missing management credentials: %v", created.body)
	}
	// The advertised URL is rooted at the issuer, which is not the
	// ephemeral host the test server listens on. Only the host is
	// rewritten: the path is exactly what an RP would follow, and it is
	// the value under test.
	want := tenantIssuer + "/oidc/register/" + clientID
	if manageURL != want {
		t.Fatalf("registration_client_uri=%q want %q", manageURL, want)
	}
	manageURL = srv.URL + strings.TrimPrefix(manageURL, validIssuer)

	read := requestJSON(t, http.MethodGet, manageURL, rat, nil)
	if read.status != http.StatusOK {
		t.Errorf("GET registration_client_uri: status=%d want 200 body=%s", read.status, read.raw)
	}
	// A successful management request rotates the registration access
	// token, so each step below presents the token the previous response
	// carried.
	if rotated, _ := read.body["registration_access_token"].(string); rotated != "" {
		rat = rotated
	}

	// A POST to the management URL is not a registration. Answering it as
	// one would mint a second client behind a URL the OP told the RP was
	// the handle on the first.
	dup := requestJSON(t, http.MethodPost, manageURL, rat,
		map[string]any{"redirect_uris": []string{"https://rp.test.invalid/other"}})
	if dup.status != http.StatusMethodNotAllowed {
		t.Errorf("POST registration_client_uri: status=%d want 405 body=%s", dup.status, dup.raw)
	}
	if _, ok := dup.body["client_id"]; ok {
		t.Errorf("POST registration_client_uri minted a duplicate registration: %v", dup.body)
	}

	updated := requestJSON(t, http.MethodPut, manageURL, rat, map[string]any{
		"client_id":     clientID,
		"redirect_uris": []string{"https://rp.test.invalid/updated"},
	})
	if updated.status != http.StatusOK {
		t.Fatalf("PUT registration_client_uri: status=%d want 200 body=%s", updated.status, updated.raw)
	}
	if rotated, _ := updated.body["registration_access_token"].(string); rotated != "" {
		rat = rotated
	}

	deleted := requestJSON(t, http.MethodDelete, manageURL, rat, nil)
	if deleted.status != http.StatusNoContent {
		t.Errorf("DELETE registration_client_uri: status=%d want 204 body=%s", deleted.status, deleted.raw)
	}
}

// jsonResponse is the decoded shape the DCR round-trip helpers return.
// raw is retained so a failing assertion can name the body the OP sent
// even when it is not valid JSON.
type jsonResponse struct {
	status int
	raw    string
	body   map[string]any
}

// postJSON issues an RFC 7591 registration request authenticated with an
// initial access token.
func postJSON(tb testing.TB, url, token string, payload map[string]any) jsonResponse {
	tb.Helper()
	return requestJSON(tb, http.MethodPost, url, token, payload)
}

// requestJSON issues one bearer-authenticated JSON request and decodes
// the response. A nil payload sends no body, which is the shape GET and
// DELETE take.
func requestJSON(tb testing.TB, method, url, token string, payload map[string]any) jsonResponse {
	tb.Helper()

	var body io.Reader = http.NoBody
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			tb.Fatalf("marshal payload: %v", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}
	out := jsonResponse{status: resp.StatusCode, raw: string(raw)}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

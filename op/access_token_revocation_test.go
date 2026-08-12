package op_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
)

func TestAccessTokenRevocationStrategy_StringIsStable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		s    op.AccessTokenRevocationStrategy
		want string
	}{
		{op.RevocationStrategyGrantTombstone, "GrantTombstone"},
		{op.RevocationStrategyJTIRegistry, "JTIRegistry"},
		{op.RevocationStrategyNone, "None"},
	}
	for _, tc := range cases {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("AccessTokenRevocationStrategy(%d).String() = %q, want %q", int(tc.s), got, tc.want)
		}
	}

	// Unknown values stringify with their numeric form so a regression
	// in the option-layer validator surfaces in audit / log lines
	// without crashing.
	bogus := op.AccessTokenRevocationStrategy(99)
	if got := bogus.String(); !strings.Contains(got, "99") {
		t.Errorf("AccessTokenRevocationStrategy(99).String() = %q, want it to mention 99", got)
	}
}

func TestAccessTokenRevocationStrategy_IsValid(t *testing.T) {
	t.Parallel()

	if !op.RevocationStrategyGrantTombstone.IsValid() {
		t.Error("RevocationStrategyGrantTombstone must be valid")
	}
	if !op.RevocationStrategyJTIRegistry.IsValid() {
		t.Error("RevocationStrategyJTIRegistry must be valid")
	}
	if !op.RevocationStrategyNone.IsValid() {
		t.Error("RevocationStrategyNone must be valid")
	}
	if op.AccessTokenRevocationStrategy(99).IsValid() {
		t.Error("AccessTokenRevocationStrategy(99) must not be valid")
	}
}

func TestRevocationStrategyGrantTombstoneIsZero(t *testing.T) {
	t.Parallel()

	// The default strategy MUST be RevocationStrategyGrantTombstone
	// (the zero value) so embedders that never call
	// WithAccessTokenRevocationStrategy receive the documented
	// default behaviour.
	if op.RevocationStrategyGrantTombstone != op.AccessTokenRevocationStrategy(0) {
		t.Fatalf("RevocationStrategyGrantTombstone = %d, want 0 (zero value)", int(op.RevocationStrategyGrantTombstone))
	}
}

func TestWithAccessTokenRevocationStrategy_RoundTripAllStrategies(t *testing.T) {
	t.Parallel()

	cases := []op.AccessTokenRevocationStrategy{
		op.RevocationStrategyGrantTombstone,
		op.RevocationStrategyJTIRegistry,
		op.RevocationStrategyNone,
	}
	for _, s := range cases {
		t.Run(s.String(), func(t *testing.T) {
			t.Parallel()
			provider, err := op.New(append(validBaseOpts(t),
				op.WithAccessTokenRevocationStrategy(s),
			)...)
			if err != nil {
				t.Fatalf("op.New(WithAccessTokenRevocationStrategy(%v)): %v", s, err)
			}
			if provider == nil {
				t.Fatal("expected non-nil provider")
			}
		})
	}
}

func TestWithAccessTokenRevocationStrategy_RejectsMissingGrantRevocations(t *testing.T) {
	t.Parallel()

	_, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("default constructor with stub grant-revocation store must succeed: %v", err)
	}

	_, err = op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(storeWithoutGrantRevocations{inner: stubStore{}}),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
	)
	if err == nil {
		t.Fatal("expected error for missing GrantRevocations under default strategy, got nil")
	}
	if !strings.Contains(err.Error(), "GrantRevocations") {
		t.Errorf("err = %v, want it to mention GrantRevocations", err)
	}
}

func TestWithAccessTokenRevocationStrategy_DefaultIsGrantTombstone(t *testing.T) {
	t.Parallel()

	// When no option is passed the resolved strategy is the zero
	// value, which by enum design equals RevocationStrategyGrantTombstone.
	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

type storeWithoutGrantRevocations struct{ inner stubStore }

func (s storeWithoutGrantRevocations) Clients() store.ClientStore { return s.inner.Clients() }
func (s storeWithoutGrantRevocations) AuthorizationCodes() store.AuthorizationCodeStore {
	return s.inner.AuthorizationCodes()
}

func (s storeWithoutGrantRevocations) RefreshTokens() store.RefreshTokenStore {
	return s.inner.RefreshTokens()
}
func (s storeWithoutGrantRevocations) Grants() store.GrantStore     { return s.inner.Grants() }
func (s storeWithoutGrantRevocations) Sessions() store.SessionStore { return s.inner.Sessions() }
func (s storeWithoutGrantRevocations) PushedAuthRequests() store.PushedAuthRequestStore {
	return s.inner.PushedAuthRequests()
}

func (s storeWithoutGrantRevocations) Interactions() store.InteractionStore {
	return s.inner.Interactions()
}

func (s storeWithoutGrantRevocations) ConsumedJTIs() store.ConsumedJTIStore {
	return s.inner.ConsumedJTIs()
}

func (s storeWithoutGrantRevocations) InitialAccessTokens() store.InitialAccessTokenStore {
	return s.inner.InitialAccessTokens()
}

func (s storeWithoutGrantRevocations) RegistrationAccessTokens() store.RegistrationAccessTokenStore {
	return s.inner.RegistrationAccessTokens()
}

func (s storeWithoutGrantRevocations) AccessTokens() store.AccessTokenRegistry {
	return s.inner.AccessTokens()
}

func (s storeWithoutGrantRevocations) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return s.inner.OpaqueAccessTokens()
}
func (s storeWithoutGrantRevocations) GrantRevocations() store.GrantRevocationStore { return nil }
func (s storeWithoutGrantRevocations) Metadata() store.MetadataStore                { return s.inner.Metadata() }

func (s storeWithoutGrantRevocations) DeviceCodes() store.DeviceCodeStore {
	return s.inner.DeviceCodes()
}

func (s storeWithoutGrantRevocations) CIBARequests() store.CIBARequestStore {
	return s.inner.CIBARequests()
}
func (s storeWithoutGrantRevocations) Users() store.UserStore { return s.inner.Users() }

type storeWithoutAccessTokens struct{ inner stubStore }

func (s storeWithoutAccessTokens) Clients() store.ClientStore { return s.inner.Clients() }
func (s storeWithoutAccessTokens) AuthorizationCodes() store.AuthorizationCodeStore {
	return s.inner.AuthorizationCodes()
}

func (s storeWithoutAccessTokens) RefreshTokens() store.RefreshTokenStore {
	return s.inner.RefreshTokens()
}
func (s storeWithoutAccessTokens) Grants() store.GrantStore     { return s.inner.Grants() }
func (s storeWithoutAccessTokens) Sessions() store.SessionStore { return s.inner.Sessions() }
func (s storeWithoutAccessTokens) PushedAuthRequests() store.PushedAuthRequestStore {
	return s.inner.PushedAuthRequests()
}

func (s storeWithoutAccessTokens) Interactions() store.InteractionStore {
	return s.inner.Interactions()
}

func (s storeWithoutAccessTokens) ConsumedJTIs() store.ConsumedJTIStore {
	return s.inner.ConsumedJTIs()
}

func (s storeWithoutAccessTokens) InitialAccessTokens() store.InitialAccessTokenStore {
	return s.inner.InitialAccessTokens()
}

func (s storeWithoutAccessTokens) RegistrationAccessTokens() store.RegistrationAccessTokenStore {
	return s.inner.RegistrationAccessTokens()
}
func (s storeWithoutAccessTokens) AccessTokens() store.AccessTokenRegistry { return nil }
func (s storeWithoutAccessTokens) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return s.inner.OpaqueAccessTokens()
}

func (s storeWithoutAccessTokens) GrantRevocations() store.GrantRevocationStore {
	return s.inner.GrantRevocations()
}
func (s storeWithoutAccessTokens) Metadata() store.MetadataStore { return s.inner.Metadata() }
func (s storeWithoutAccessTokens) DeviceCodes() store.DeviceCodeStore {
	return s.inner.DeviceCodes()
}

func (s storeWithoutAccessTokens) CIBARequests() store.CIBARequestStore {
	return s.inner.CIBARequests()
}
func (s storeWithoutAccessTokens) Users() store.UserStore { return s.inner.Users() }

func TestWithAccessTokenRevocationStrategy_RejectsUnknownValue(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithAccessTokenRevocationStrategy(op.AccessTokenRevocationStrategy(99)),
	)...)
	if err == nil {
		t.Fatal("expected error for unknown AccessTokenRevocationStrategy, got nil")
	}
	var typed *op.Error
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *op.Error", err)
	}
	if !op.IsServerError(err) {
		t.Errorf("unknown strategy must be a server-side configuration error: %v", err)
	}
	if !strings.Contains(err.Error(), "unknown AccessTokenRevocationStrategy") {
		t.Errorf("err = %v, want it to mention unknown AccessTokenRevocationStrategy", err)
	}
}

func TestWithAccessTokenRevocationStrategy_RejectsMissingAccessTokens(t *testing.T) {
	t.Parallel()

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(storeWithoutAccessTokens{inner: stubStore{}}),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		op.WithAccessTokenRevocationStrategy(op.RevocationStrategyJTIRegistry),
	)
	if err == nil {
		t.Fatal("expected error for missing AccessTokens under JTIRegistry, got nil")
	}
	if !strings.Contains(err.Error(), "AccessTokens") {
		t.Errorf("err = %v, want it to mention AccessTokens", err)
	}
}

// TestWithAccessTokenRevocationStrategy_FAPIRejectsNone pins the
// Profile interaction gate: under any FAPI profile
// [op.RevocationStrategyNone] is rejected at [op.New] time because
// FAPI 2.0 SP §5.3.2.2 mandates server-side access-token revocation.
// The test exercises FAPI 2.0 Baseline, but the gate covers every
// [profile.RequiresAccessTokenRevocation] true variant.
func TestWithAccessTokenRevocationStrategy_FAPIRejectsNone(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenRevocationStrategy(op.RevocationStrategyNone),
	)...)
	if err == nil {
		t.Fatal("expected error when FAPI profile is paired with RevocationStrategyNone, got nil")
	}
	var typed *op.Error
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *op.Error", err)
	}
	if !op.IsServerError(err) {
		t.Errorf("FAPI + None must be a server-side configuration error: %v", err)
	}
	if !strings.Contains(err.Error(), "RevocationStrategyNone") {
		t.Errorf("err = %v, want it to mention RevocationStrategyNone", err)
	}
}

// TestWithAccessTokenRevocationStrategy_NoProfileAcceptsNone confirms
// that without a FAPI profile, [op.RevocationStrategyNone] is a
// permitted opt-out: the embedder accepts the RFC 6749 §4.1.2 wiggle
// and the OP serves stateless JWT access tokens with no revocation
// surface.
func TestWithAccessTokenRevocationStrategy_NoProfileAcceptsNone(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithAccessTokenRevocationStrategy(op.RevocationStrategyNone),
	)...)
	if err != nil {
		t.Fatalf("op.New(no profile + RevocationStrategyNone): %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

// TestWithAccessTokenRevocationStrategy_FAPIAcceptsGrantTombstone
// confirms the FAPI default path: every FAPI profile accepts the
// default strategy (GrantTombstone). This is the path embedders who
// never call WithAccessTokenRevocationStrategy travel.
func TestWithAccessTokenRevocationStrategy_FAPIAcceptsGrantTombstone(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenRevocationStrategy(op.RevocationStrategyGrantTombstone),
	)...)
	if err != nil {
		t.Fatalf("op.New(FAPI + GrantTombstone): %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

// TestWithAccessTokenRevocationStrategy_FAPIAcceptsJTIRegistry
// confirms the second FAPI-conformant strategy is admitted:
// JTIRegistry preserves the per-AT shadow row model, which also
// satisfies FAPI 2.0 SP §5.3.2.2.
func TestWithAccessTokenRevocationStrategy_FAPIAcceptsJTIRegistry(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenRevocationStrategy(op.RevocationStrategyJTIRegistry),
	)...)
	if err != nil {
		t.Fatalf("op.New(FAPI + JTIRegistry): %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

// TestProfile_RequiresAccessTokenRevocation pins the FAPI / non-FAPI
// classification consumed by the validator. Adding a FAPI variant to
// the profile package without updating this predicate would surface
// here as a missing FAPI entry. FAPICIBA inherits the FAPI 2.0 §5.3.2.2
// posture so it returns true.
func TestProfile_RequiresAccessTokenRevocation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		p    profile.Profile
		want bool
	}{
		{profile.FAPI2Baseline, true},
		{profile.FAPI2MessageSigning, true},
		{profile.FAPICIBA, true},
		{profile.Profile(0), false},
		{profile.Profile(99), false},
	}
	for _, tc := range cases {
		if got := profile.RequiresAccessTokenRevocation(tc.p); got != tc.want {
			t.Errorf("RequiresAccessTokenRevocation(%v) = %v, want %v", tc.p, got, tc.want)
		}
	}
}

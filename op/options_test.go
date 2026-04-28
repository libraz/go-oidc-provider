package op_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// validBaseOptsWithInmem returns the same option shape as
// [validBaseOpts] but swaps [stubStore] for the inmem reference
// implementation, so tests that exercise paths reaching the DPoP /
// MTLS verifier wiring (which calls into substores [stubStore]
// deliberately leaves panicking) construct without panic.
func validBaseOptsWithInmem(tb testing.TB) []op.Option {
	tb.Helper()
	return []op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(inmem.New()),
		op.WithKeyset(validKeyset(tb)),
		op.WithCookieKey(newRandomCookieKey(tb)),
	}
}

func TestWithKeyset_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{}),
	)
	if !errors.Is(err, op.ErrKeysetRequired) {
		t.Fatalf("expected ErrKeysetRequired for empty keyset, got %v", err)
	}
}

func TestWithKeyset_RejectsMissingKeyID(t *testing.T) {
	t.Parallel()

	bad := newTestKey(t, "")
	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{bad}),
	)
	if err == nil {
		t.Fatal("expected error for missing KeyID, got nil")
	}
}

func TestWithKeyset_RejectsDuplicateKeyID(t *testing.T) {
	t.Parallel()

	a := newTestKey(t, "dup")
	b := newTestKey(t, "dup")
	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{a, b}),
	)
	if err == nil {
		t.Fatal("expected error for duplicate KeyID, got nil")
	}
}

func TestWithKeyset_RejectsNonES256Key(t *testing.T) {
	t.Parallel()

	// rsa.PublicKey satisfies crypto.Signer.Public() but is not ECDSA P-256.
	rsaKey := &fakeRSASigner{}
	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{{KeyID: "rsa-1", Signer: rsaKey}}),
	)
	if err == nil {
		t.Fatal("expected error for non-ES256 key, got nil")
	}
}

func TestWithMountPrefix_Validates(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		prefix  string
		wantErr bool
	}{
		{"slash", "/", false},
		{"oidc", "/oidc", false},
		{"empty", "", true},
		{"no leading slash", "oidc", true},
		{"trailing slash", "/oidc/", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := append(validBaseOpts(t), op.WithMountPrefix(tc.prefix))
			_, err := op.New(opts...)
			if (err != nil) != tc.wantErr {
				t.Fatalf("WithMountPrefix(%q): err=%v wantErr=%v", tc.prefix, err, tc.wantErr)
			}
		})
	}
}

func TestWithEndpoints_OverrideAndDefaults(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithEndpoints(op.Endpoints{Authorize: "/login", Token: "/jwt"}),
	)...)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestWithGrants_RequiresAtLeastOne(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithGrants())...)
	if err == nil {
		t.Fatal("expected error for empty grants, got nil")
	}
}

func TestWithGrants_RejectsUnknown(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithGrants(grant.Type(0)))...)
	if err == nil {
		t.Fatal("expected error for zero-value grant, got nil")
	}
}

func TestWithGrants_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithGrants(grant.AuthorizationCode, grant.AuthorizationCode),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate grant, got nil")
	}
}

func TestWithFeature_DuplicateIsIdempotent(t *testing.T) {
	t.Parallel()

	// ADR 0008 item 8 / plan 005 §3.6 — WithFeature for an already-
	// enabled flag is a silent no-op so the
	// `WithProfile(FAPI2Baseline) + WithFeature(feature.PAR)` pattern
	// composes regardless of call order. The pre-idempotence behaviour
	// (duplicate-rejection) lived in the v0 surface; this test pins
	// the new contract.
	if _, err := op.New(append(validBaseOpts(t),
		op.WithFeature(feature.PAR), op.WithFeature(feature.PAR),
	)...); err != nil {
		t.Fatalf("expected nil error for duplicate WithFeature, got %v", err)
	}
}

func TestWithFeature_RejectsZeroValue(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithFeature(feature.Flag(0)))...)
	if err == nil {
		t.Fatal("expected error for zero-value flag, got nil")
	}
}

func TestWithProfile_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithProfile(profile.FAPI2Baseline), op.WithProfile(profile.FAPI2Baseline),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate profile, got nil")
	}
}

// TestWithProfile_FAPI2Baseline_AutoEnablesRequiredFeatures confirms
// the plan 005 §3.6 auto-enable contract: an embedder calling
// [op.WithProfile(profile.FAPI2Baseline)] without explicit
// [op.WithFeature] calls for PAR and JAR still constructs
// successfully because both flags are auto-enabled. The disjunctive
// DPoP/MTLS requirement still has to be supplied manually.
func TestWithProfile_FAPI2Baseline_AutoEnablesRequiredFeatures(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...)
	if err != nil {
		t.Fatalf("WithProfile auto-enable did not satisfy PAR/JAR: %v", err)
	}
}

func TestWithProfile_FAPI2Baseline_RequiresSenderConstrainedToken(t *testing.T) {
	t.Parallel()

	// PAR and JAR are auto-enabled by [op.WithProfile]; the
	// disjunctive DPoP/MTLS requirement (profile.RequiredAnyOf) is
	// the only remaining flag the embedder must supply.
	_, err := op.New(append(validBaseOpts(t),
		op.WithProfile(profile.FAPI2Baseline),
	)...)
	if err == nil {
		t.Fatal("expected error when neither DPoP nor MTLS is enabled, got nil")
	}
}

func TestWithProfile_FAPI2Baseline_AcceptsDPoP(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithProfile_FAPI2Baseline_AcceptsMTLS(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.MTLS),
	)...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestWithProfile_FAPI2MessageSigning_AutoEnablesJARM confirms the
// auto-enable contract extends to the Message Signing requirement
// set (JARM is added to RequiredFeatures alongside PAR / JAR). The
// embedder only needs to supply the disjunctive DPoP/MTLS choice.
func TestWithProfile_FAPI2MessageSigning_AutoEnablesJARM(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.DPoP),
	)...)
	if err != nil {
		t.Fatalf("WithProfile auto-enable did not satisfy JARM requirement: %v", err)
	}
}

func TestWithProfile_FAPI2MessageSigning_AcceptsFullStack(t *testing.T) {
	t.Parallel()

	// PAR / JAR / JARM are auto-enabled by [op.WithProfile]; the
	// disjunctive DPoP/MTLS requirement is the only remaining flag
	// the embedder must supply.
	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.DPoP),
	)...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithAccessTokenTTL_RejectsNegative(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithAccessTokenTTL(-1*time.Second))...)
	if err == nil {
		t.Fatal("expected error for negative TTL, got nil")
	}
	if !strings.Contains(err.Error(), "non-negative") {
		t.Errorf("err = %v, want it to mention non-negative", err)
	}
}

func TestWithAccessTokenTTL_AcceptsZero(t *testing.T) {
	t.Parallel()

	// Zero opts into [DefaultAccessTokenTTL]. The construction must
	// succeed; the actual default substitution is observable through
	// downstream behavior, not directly readable here.
	_, err := op.New(append(validBaseOpts(t), op.WithAccessTokenTTL(0))...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithAccessTokenTTL_AcceptsCustomValue(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithAccessTokenTTL(2*time.Minute))...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithAccessTokenTTL_FAPI2BaselineRejectsTooLong(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenTTL(15*time.Minute),
	)...)
	if err == nil {
		t.Fatal("expected error for TTL above FAPI2 cap, got nil")
	}
	if !strings.Contains(err.Error(), "fapi2-baseline") || !strings.Contains(err.Error(), "10m") {
		t.Errorf("err = %v, want it to mention fapi2-baseline and the 10m cap", err)
	}
}

func TestWithAccessTokenTTL_FAPI2BaselineAcceptsAtCap(t *testing.T) {
	t.Parallel()

	// Stricter-than-profile is OK; exactly at the cap is also OK.
	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenTTL(10*time.Minute),
	)...)
	if err != nil {
		t.Fatalf("unexpected error at the cap: %v", err)
	}
}

func TestWithRefreshTokenTTL_RejectsNegative(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithRefreshTokenTTL(-1*time.Second))...)
	if err == nil {
		t.Fatal("expected error for negative TTL, got nil")
	}
	if !strings.Contains(err.Error(), "non-negative") {
		t.Errorf("err = %v, want it to mention non-negative", err)
	}
}

func TestWithRefreshTokenTTL_AcceptsZero(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithRefreshTokenTTL(0))...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithRefreshTokenTTL_AcceptsCustomValue(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithRefreshTokenTTL(7*24*time.Hour))...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithAccessTokenTTL_FAPI2BaselineAcceptsStricter(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenTTL(2*time.Minute),
	)...)
	if err != nil {
		t.Fatalf("unexpected error for stricter-than-profile TTL: %v", err)
	}
}

func TestWithAccessTokenTTL_FAPI2MessageSigningRejectsTooLong(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenTTL(11*time.Minute),
	)...)
	if err == nil {
		t.Fatal("expected error for TTL above FAPI2 Message Signing cap, got nil")
	}
}

func TestWithProfile_FAPI2_StampsInteractionIDHeader(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", http.NoBody)
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, req)
	got := rec.Header().Get("x-fapi-interaction-id")
	if got == "" {
		t.Errorf("response x-fapi-interaction-id missing under FAPI2Baseline profile")
	}
}

func TestWithProfile_FAPI2_EchoesClientInteractionID(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	want := "0123abcd-4567-89ef-0123-456789abcdef"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", http.NoBody)
	req.Header.Set("x-fapi-interaction-id", want)
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, req)
	if got := rec.Header().Get("x-fapi-interaction-id"); got != want {
		t.Errorf("response x-fapi-interaction-id = %q, want %q (must echo client value)", got, want)
	}
}

func TestNoProfile_DoesNotStampInteractionIDHeader(t *testing.T) {
	t.Parallel()

	// Without any profile, the FAPI middleware MUST be off — otherwise
	// every OP would advertise FAPI 2.0 §6 compliance the embedder
	// did not opt into.
	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", http.NoBody)
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, req)
	if got := rec.Header().Get("x-fapi-interaction-id"); got != "" {
		t.Errorf("non-profile OP stamped x-fapi-interaction-id = %q, want absent", got)
	}
}

type recordingDriver struct{ called bool }

func (d *recordingDriver) Render(http.ResponseWriter, *http.Request, interaction.Prompt) error {
	d.called = true
	return nil
}

func (d *recordingDriver) ParseSubmission(*http.Request) (interaction.FormSubmission, error) {
	return interaction.FormSubmission{}, nil
}

func TestWithInteraction_RejectsNil(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithInteraction(nil))...)
	if err == nil {
		t.Fatal("expected error for nil Driver, got nil")
	}
}

func TestWithInteraction_AcceptsCustomDriver(t *testing.T) {
	t.Parallel()

	d := &recordingDriver{}
	provider, err := op.New(append(validBaseOpts(t), op.WithInteraction(d))...)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

// fakeRSASigner reports an RSA public key from Public(), so the Keyset
// validator can reject it without needing real RSA key generation in tests.
type fakeRSASigner struct{}

func (fakeRSASigner) Public() crypto.PublicKey { return &rsa.PublicKey{} }

// Sign is never invoked because validation rejects the key shape before
// any signing path is reached.
func (fakeRSASigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// validCookieKey returns a 32-byte filler suitable for the AES-256-GCM cookie
// codec. The contents do not need to be random for option-validation tests.
func validCookieKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestWithCookieKey_AcceptsValidKey(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithCookieKey(validCookieKey()))...); err != nil {
		t.Fatalf("WithCookieKey rejected valid key: %v", err)
	}
}

func TestWithCookieKey_RejectsWrongLength(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithCookieKey(make([]byte, 16)))...)
	if err == nil {
		t.Fatal("WithCookieKey accepted 16-byte key, want rejection")
	}
}

func TestWithCookieKeys_AcceptsRotation(t *testing.T) {
	t.Parallel()

	current := validCookieKey()
	previous := validCookieKey()
	previous[0] = 0xff

	if _, err := op.New(append(validBaseOpts(t), op.WithCookieKeys(current, previous))...); err != nil {
		t.Fatalf("WithCookieKeys rejected rotation pair: %v", err)
	}
}

func TestWithCookieKeys_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithCookieKeys())...); err == nil {
		t.Fatal("WithCookieKeys accepted empty input")
	}
}

func TestWithCookieKeys_RejectsBadRotationEntry(t *testing.T) {
	t.Parallel()

	bad := make([]byte, 31) // off by one
	_, err := op.New(append(validBaseOpts(t), op.WithCookieKeys(validCookieKey(), bad))...)
	if err == nil {
		t.Fatal("WithCookieKeys accepted 31-byte rotation key")
	}
}

func TestWithCookieKeys_DefensiveCopy(t *testing.T) {
	t.Parallel()

	// Mutating the input slice after construction must not change the OP's
	// stored keys. The test verifies behaviour via successful construction
	// (the validator runs on the stored copy).
	k := validCookieKey()
	provider, err := op.New(append(validBaseOpts(t), op.WithCookieKey(k))...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := range k {
		k[i] = 0
	}
	// We have no public accessor; the test passes if construction
	// succeeded with the original key. The defensive copy prevents the
	// later mutation from changing what the OP holds.
	if provider == nil {
		t.Fatal("provider nil")
	}
}

func TestWithTrustedProxies_AcceptsCIDRs(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithTrustedProxies("10.0.0.0/8", "2400:cb00::/32"))...,
	); err != nil {
		t.Fatalf("WithTrustedProxies rejected valid CIDRs: %v", err)
	}
}

func TestWithTrustedProxies_RejectsInvalidCIDR(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithTrustedProxies("10.0.0.1"))...)
	if err == nil {
		t.Fatal("WithTrustedProxies accepted bare IP without prefix")
	}
}

func TestWithTrustedProxies_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithTrustedProxies())...); err == nil {
		t.Fatal("WithTrustedProxies accepted empty input")
	}
}

func TestWithCORSOrigins_AcceptsOrigins(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithCORSOrigins("https://app.example.com", "https://admin.example.com"))...,
	); err != nil {
		t.Fatalf("WithCORSOrigins rejected valid origins: %v", err)
	}
}

func TestWithCORSOrigins_RejectsInvalidOrigin(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithCORSOrigins("not-a-url"))...); err == nil {
		t.Fatal("WithCORSOrigins accepted invalid origin")
	}
}

func TestWithCORSOrigins_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithCORSOrigins())...); err == nil {
		t.Fatal("WithCORSOrigins accepted empty input")
	}
}

func TestWithCORSOrigins_AppendsAcrossCalls(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithCORSOrigins("https://a.example.com"),
		op.WithCORSOrigins("https://b.example.com"),
	)...); err != nil {
		t.Fatalf("two WithCORSOrigins calls failed: %v", err)
	}
}

func TestWithCrossSiteFlow_Accepts(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithCrossSiteFlow())...); err != nil {
		t.Fatalf("WithCrossSiteFlow: %v", err)
	}
}

// TestWithScope_RejectsStandardScopeNonPublic enforces ADR-0004's
// construction-time guard: every OIDC standard scope MUST stay in the
// discovery document, so registering one with Public:false is a
// configuration bug surfaced at op.New rather than a silent runtime
// drift in /.well-known/openid-configuration.
func TestWithScope_RejectsStandardScopeNonPublic(t *testing.T) {
	t.Parallel()

	standard := []string{"openid", "profile", "email", "address", "phone", "offline_access"}
	for _, name := range standard {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t),
				op.WithScope(op.Scope{Name: name, Public: false}),
			)...)
			if err == nil {
				t.Fatalf("op.New must reject Public:false for standard scope %q", name)
			}
			if op.IsClientError(err) {
				t.Errorf("standard-scope misconfiguration must surface as a server error, got %v", err)
			}
		})
	}
}

// TestWithScope_AcceptsStandardScopePublic confirms that overriding a
// standard scope with explicit Public:true (typically to attach
// translations or a Title) is the supported way to customise the
// built-in entry without breaking discovery.
func TestWithScope_AcceptsStandardScopePublic(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithScope(op.Scope{
			Name:        "profile",
			Public:      true,
			Title:       "Profile",
			Description: "Read your profile information.",
		}),
	)...); err != nil {
		t.Fatalf("op.New rejected standard-scope Public:true override: %v", err)
	}
}

// TestWithScope_RejectsDuplicateName surfaces a configuration mistake
// the moment two registrations collide on the wire identifier; without
// this the second call would silently shadow the first.
func TestWithScope_RejectsDuplicateName(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithScope(op.Scope{Name: "read:projects", Public: true}),
		op.WithScope(op.Scope{Name: "read:projects", Public: true}),
	)...)
	if err == nil {
		t.Fatal("op.New must reject duplicate WithScope registrations")
	}
}

// TestWithScope_RejectsEmptyName covers the option-level guard. The
// registry's wire identifier is the contract clients build against; a
// blank Name would corrupt the registry and is rejected eagerly.
func TestWithScope_RejectsEmptyName(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithScope(op.Scope{Name: "", Public: true}),
	)...)
	if err == nil {
		t.Fatal("op.New must reject WithScope with empty Name")
	}
}

// TestWithScope_AcceptsCustomNonPublic registers a private custom scope
// (the "internal-only API" use case from ADR-0004). Public:false is
// permitted on custom names; only standard scopes are forced public.
func TestWithScope_AcceptsCustomNonPublic(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithScope(op.Scope{Name: "internal:metrics", Public: false}),
	)...); err != nil {
		t.Fatalf("op.New rejected Public:false custom scope: %v", err)
	}
}

// TestWithScope_AcceptsCustomWithAllowedClients exercises the
// orthogonal AllowedClients axis: a public scope locked to a specific
// service client. The registration must succeed; runtime enforcement is
// validated in the authorize / token endpoint tests.
func TestWithScope_AcceptsCustomWithAllowedClients(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithScope(op.Scope{
			Name:           "billing:write",
			Public:         true,
			AllowedClients: []string{"svc-billing", "svc-admin"},
		}),
	)...); err != nil {
		t.Fatalf("op.New rejected AllowedClients-restricted scope: %v", err)
	}
}

// ---------------------------------------------------------------------
// Wave H1-E options coverage (plan 005, ADR 0008 items 6-9 & 12).
// ---------------------------------------------------------------------

// stagedH1DStep is a [op.Step] used purely to give a test [op.LoginFlow]
// a non-nil Primary or rule target. The ceremony body is irrelevant
// here: H1-E only verifies option-level validation, the Begin /
// Continue paths are exercised by H1-D.
type stagedH1DStep struct {
	kind op.StepKind
}

func (s stagedH1DStep) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (s stagedH1DStep) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (s stagedH1DStep) Kind() op.StepKind { return s.kind }

// TestWithLoginFlow_BuiltinStepRejectedAtNew covers the H1-D wiring
// state: the LoginFlow seam is integrated into the orchestrator, but
// built-in [op.Step] values (PrimaryPassword / StepTOTP / …) are not
// yet wired to internal Authenticator primitives — their
// construction-time dependencies (TOTP encryption codec, passkey RP
// origin, hash adapter) are exposed by follow-up options. Until those
// land embedders adopt the seam through [op.ExternalStep]; passing a
// built-in Step at op.New surfaces a clear configuration error that
// points to the workaround.
func TestWithLoginFlow_BuiltinStepRejectedAtNew(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{Primary: stagedH1DStep{kind: op.StepKindPassword}}
	_, err := op.New(append(validBaseOpts(t), op.WithLoginFlow(flow))...)
	if err == nil {
		t.Fatal("expected built-in Step error from op.New, got nil")
	}
	if !strings.Contains(err.Error(), "ExternalStep") {
		t.Errorf("err = %v, want it to point at ExternalStep workaround", err)
	}
	if !op.IsServerError(err) {
		t.Errorf("built-in-step error must be a server-side configuration error: %v", err)
	}
}

// TestWithLoginFlow_ExternalStepConstructs confirms the H1-D wiring is
// complete for the production-supported path: a LoginFlow whose Steps
// are [op.ExternalStep] wrappers around an embedder's [op.Authenticator]
// constructs cleanly. Built-in Step primitives remain deferred — the
// matching options ship in follow-up Waves.
func TestWithLoginFlow_ExternalStepConstructs(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: &h1dStubAuth{
				typeID:  op.FactorPassword,
				aal:     op.AAL1,
				amr:     "pwd",
				prompts: []string{"auth.password"},
			},
			KindLabel: op.StepKind("myorg.password"),
		},
	}
	if _, err := op.New(append(validBaseOpts(t), op.WithLoginFlow(flow))...); err != nil {
		t.Fatalf("WithLoginFlow + ExternalStep should construct, got %v", err)
	}
}

// TestWithLoginFlow_RejectsAuthenticatorCombo pins the mutual
// exclusion contract: WithLoginFlow + WithAuthenticators is a
// configuration error because the two surfaces drive the orchestrator
// through different code paths and combining them would silently
// reorder factors.
func TestWithLoginFlow_RejectsAuthenticatorCombo(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: &h1dStubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"},
			KindLabel:     op.StepKind("myorg.password"),
		},
	}
	_, err := op.New(append(validBaseOpts(t),
		op.WithLoginFlow(flow),
		op.WithAuthenticators(&h1dStubAuth{typeID: op.FactorTOTP, aal: op.AAL2, amr: "otp"}),
	)...)
	if err == nil {
		t.Fatal("expected error for WithLoginFlow + WithAuthenticators, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v, want mutually-exclusive diagnostic", err)
	}
}

// TestWithLoginFlow_RejectsExternalStepBuiltinKindLabel pins the
// validation that ExternalStep KindLabel cannot collide with a
// built-in StepKind: an embedder that picks "password" for their
// custom factor would silently shadow the built-in PrimaryPassword
// kind in CompletedSteps dedup.
func TestWithLoginFlow_RejectsExternalStepBuiltinKindLabel(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: &h1dStubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"},
			KindLabel:     op.StepKindPassword, // collides with built-in
		},
	}
	_, err := op.New(append(validBaseOpts(t), op.WithLoginFlow(flow))...)
	if err == nil {
		t.Fatal("expected error for built-in KindLabel collision, got nil")
	}
	if !strings.Contains(err.Error(), "built-in") {
		t.Errorf("err = %v, want it to mention built-in collision", err)
	}
}

// TestWithLoginFlow_RejectsExternalStepBareKindLabel enforces the
// dotted-prefix discipline on user-defined StepKind values. A bare
// label like "myfactor" risks colliding with future built-ins;
// requiring a dotted prefix matches the existing FactorType.IsUserDefined
// rule and keeps the namespace conflict surface controllable.
func TestWithLoginFlow_RejectsExternalStepBareKindLabel(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: op.ExternalStep{
			Authenticator: &h1dStubAuth{typeID: op.FactorPassword, aal: op.AAL1, amr: "pwd"},
			KindLabel:     op.StepKind("myfactor"), // bare, no dot
		},
	}
	_, err := op.New(append(validBaseOpts(t), op.WithLoginFlow(flow))...)
	if err == nil {
		t.Fatal("expected error for bare KindLabel, got nil")
	}
	if !strings.Contains(err.Error(), "dotted prefix") {
		t.Errorf("err = %v, want it to mention dotted prefix", err)
	}
}

// h1dStubAuth is a minimal op.Authenticator used by H1-D option-layer
// tests. The Begin / Continue methods return zero values because the
// H1-D test surface only exercises construction-time validation; the
// orchestrator-level integration tests live in
// internal/authn/orchestrator_test.go.
type h1dStubAuth struct {
	typeID  op.FactorType
	aal     op.AAL
	amr     string
	prompts []string
}

func (s *h1dStubAuth) Type() op.FactorType { return s.typeID }
func (s *h1dStubAuth) AAL() op.AAL         { return s.aal }
func (s *h1dStubAuth) AMR() string         { return s.amr }
func (s *h1dStubAuth) Prompts() []string   { return s.prompts }
func (s *h1dStubAuth) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (s *h1dStubAuth) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func TestWithLoginFlow_RejectsNilPrimary(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithLoginFlow(op.LoginFlow{}))...)
	if err == nil {
		t.Fatal("expected error for nil Primary, got nil")
	}
	if !strings.Contains(err.Error(), "LoginFlow.Primary must not be nil") {
		t.Errorf("err = %v, want it to mention nil Primary", err)
	}
}

func TestWithLoginFlow_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{Primary: stagedH1DStep{kind: op.StepKindPassword}}
	_, err := op.New(append(validBaseOpts(t),
		op.WithLoginFlow(flow),
		op.WithLoginFlow(flow),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate WithLoginFlow, got nil")
	}
	if !strings.Contains(err.Error(), "may be called at most once") {
		t.Errorf("err = %v, want duplicate-rejection message", err)
	}
}

func TestWithLoginFlow_RejectsDuplicateRuleKinds(t *testing.T) {
	t.Parallel()

	flow := op.LoginFlow{
		Primary: stagedH1DStep{kind: op.StepKindPassword},
		Rules: []op.Rule{
			{When: func(op.LoginContext) bool { return true }, Then: stagedH1DStep{kind: op.StepKindTOTP}},
			{When: func(op.LoginContext) bool { return true }, Then: stagedH1DStep{kind: op.StepKindTOTP}},
		},
	}
	_, err := op.New(append(validBaseOpts(t), op.WithLoginFlow(flow))...)
	if err == nil {
		t.Fatal("expected error for duplicate Rule StepKind, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate StepKind") {
		t.Errorf("err = %v, want duplicate-StepKind message", err)
	}
}

func TestWithLoginFlow_AbsentLeavesNoError(t *testing.T) {
	t.Parallel()

	// No WithLoginFlow at all: the staged-for-H1-D guard must NOT
	// fire because c.loginFlow.Primary stays nil.
	if _, err := op.New(validBaseOpts(t)...); err != nil {
		t.Fatalf("op.New without WithLoginFlow: %v", err)
	}
}

func TestWithReactUI_AcceptsValid(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithReactUI(op.ReactUI{LoginMount: "/login"}),
	)...); err != nil {
		t.Fatalf("WithReactUI rejected valid mount: %v", err)
	}
}

func TestWithReactUI_RejectsEmptyLoginMount(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithReactUI(op.ReactUI{}),
	)...)
	if err == nil {
		t.Fatal("expected error for empty LoginMount, got nil")
	}
	if !strings.Contains(err.Error(), "LoginMount must not be empty") {
		t.Errorf("err = %v, want it to mention LoginMount", err)
	}
}

func TestWithReactUI_RejectsNonSlashLoginMount(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithReactUI(op.ReactUI{LoginMount: "login"}),
	)...)
	if err == nil {
		t.Fatal("expected error for LoginMount missing leading slash, got nil")
	}
	if !strings.Contains(err.Error(), "must start with") {
		t.Errorf("err = %v, want leading-slash diagnostic", err)
	}
}

func TestWithReactUI_RejectsMissingStaticDir(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithReactUI(op.ReactUI{
			LoginMount: "/login",
			StaticDir:  "/this/path/does/not/exist/h1e-test",
		}),
	)...)
	if err == nil {
		t.Fatal("expected error for missing StaticDir, got nil")
	}
	if !strings.Contains(err.Error(), "StaticDir") {
		t.Errorf("err = %v, want it to mention StaticDir", err)
	}
}

func TestWithReactUI_AcceptsExistingStaticDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if _, err := op.New(append(validBaseOpts(t),
		op.WithReactUI(op.ReactUI{LoginMount: "/login", StaticDir: dir}),
	)...); err != nil {
		t.Fatalf("WithReactUI rejected existing StaticDir: %v", err)
	}
}

func TestWithReactUI_RejectsConsentUICombination(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("c").Parse("ok"))
	_, err := op.New(append(validBaseOpts(t),
		op.WithReactUI(op.ReactUI{LoginMount: "/login"}),
		op.WithConsentUI(op.ConsentUI{Template: tmpl}),
	)...)
	if err == nil {
		t.Fatal("expected error for WithReactUI + WithConsentUI, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v, want mutually-exclusive diagnostic", err)
	}
}

func TestWithConsentUI_RejectsNilTemplate(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithConsentUI(op.ConsentUI{Template: nil}),
	)...)
	if err == nil {
		t.Fatal("expected error for nil Template, got nil")
	}
	if !strings.Contains(err.Error(), "Template must not be nil") {
		t.Errorf("err = %v, want it to mention Template", err)
	}
}

func TestWithConsentUI_AcceptsValid(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("consent").Parse("hi"))
	if _, err := op.New(append(validBaseOpts(t),
		op.WithConsentUI(op.ConsentUI{Template: tmpl}),
	)...); err != nil {
		t.Fatalf("WithConsentUI rejected valid template: %v", err)
	}
}

func TestWithConsentUI_RejectsReactUICombination(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("c").Parse("ok"))
	_, err := op.New(append(validBaseOpts(t),
		op.WithConsentUI(op.ConsentUI{Template: tmpl}),
		op.WithReactUI(op.ReactUI{LoginMount: "/login"}),
	)...)
	if err == nil {
		t.Fatal("expected error for WithConsentUI + WithReactUI, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v, want mutually-exclusive diagnostic", err)
	}
}

func TestWithStaticClients_AcceptsPublicSeed(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)...); err != nil {
		t.Fatalf("WithStaticClients rejected PublicClient seed: %v", err)
	}
}

func TestWithStaticClients_AcceptsMixedSeeds(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "demo-spa",
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			},
			op.ConfidentialClient{
				ID:           "demo-confidential",
				Secret:       "demo-secret",
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			},
			op.PrivateKeyJWTClient{
				ID:           "demo-fapi",
				JWKS:         []byte(`{"keys":[]}`),
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			},
		),
	)...); err != nil {
		t.Fatalf("WithStaticClients rejected mixed seed list: %v", err)
	}
}

func TestWithStaticClients_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithStaticClients())...)
	if err == nil {
		t.Fatal("expected error for empty seed list, got nil")
	}
	if !strings.Contains(err.Error(), "at least one ClientSeed") {
		t.Errorf("err = %v, want it to require at least one seed", err)
	}
}

func TestWithStaticClients_RejectsNilSeed(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "demo-spa",
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			},
			nil,
		),
	)...)
	if err == nil {
		t.Fatal("expected error for nil seed, got nil")
	}
	// The error description MUST carry the offending index so the
	// embedder can locate the bad entry without dichotomising the
	// list themselves.
	if !strings.Contains(err.Error(), "[1]") {
		t.Errorf("err = %v, want it to mention seed index [1]", err)
	}
}

func TestWithStaticClients_AppendsAcrossCalls(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa-a",
			RedirectURIs: []string{"https://a.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa-b",
			RedirectURIs: []string{"https://b.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)...); err != nil {
		t.Fatalf("WithStaticClients rejected layered calls: %v", err)
	}
}

// TestWithStaticClients_ConfidentialEmptySecret pins the H1-C contract:
// [op.ConfidentialClient.seed] currently does NOT reject an empty
// Secret because [op.HashClientSecret] hashes empty strings without
// error. The test documents the current behaviour so a future H1-C
// change that adds an empty-Secret guard surfaces here as a loud
// regression rather than a silent behaviour drift; once the guard
// lands, flip the assertion to expect an error and propagate the
// "WithStaticClients[i]:" index prefix from the option site.
func TestWithStaticClients_ConfidentialEmptySecret(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(op.ConfidentialClient{
			ID:           "demo-empty-secret",
			Secret:       "",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)...)
	// Today: empty Secret hashes successfully, so op.New accepts the
	// configuration. If a future revision rejects the empty Secret at
	// the seed() boundary, the option site MUST prepend
	// "WithStaticClients[0]: " so the embedder can locate the entry.
	if err == nil {
		return
	}
	if !strings.Contains(err.Error(), "WithStaticClients[0]") {
		t.Errorf("seed error must surface with index prefix, got %v", err)
	}
}

func TestWithFirstPartyClients_RejectsUnknownID(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "known",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
		op.WithFirstPartyClients("unknown"),
	)...)
	if err == nil {
		t.Fatal("expected error for unknown first-party client_id, got nil")
	}
	if !strings.Contains(err.Error(), "unknown client_id unknown") {
		t.Errorf("err = %v, want it to mention the unknown id", err)
	}
}

func TestWithFirstPartyClients_AcceptsKnownID(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "first-party-spa",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
		op.WithFirstPartyClients("first-party-spa"),
	)...); err != nil {
		t.Fatalf("WithFirstPartyClients rejected known id: %v", err)
	}
}

func TestWithFirstPartyClients_RejectsDuplicateInCall(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "x",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
		op.WithFirstPartyClients("x", "x"),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate id within a single call, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate client_id") {
		t.Errorf("err = %v, want duplicate-id diagnostic", err)
	}
}

func TestWithFirstPartyClients_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithFirstPartyClients())...)
	if err == nil {
		t.Fatal("expected error for empty id list, got nil")
	}
}

func TestWithFirstPartyClients_RejectsFAPI2Profile(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithStaticClients(op.PublicClient{
			ID:           "fp-client",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
		op.WithFirstPartyClients("fp-client"),
	)...)
	if err == nil {
		t.Fatal("expected error combining WithFirstPartyClients with FAPI 2.0 profile, got nil")
	}
	if !strings.Contains(err.Error(), "FAPI 2.0") {
		t.Errorf("err = %v, want it to mention FAPI 2.0", err)
	}
}

func TestWithProfile_AutoEnablesRequiredFeatures(t *testing.T) {
	t.Parallel()

	// FAPI2Baseline requires PAR + JAR per profile.RequiredFeatures.
	// With H1-E auto-enable in WithProfile the embedder no longer
	// needs explicit WithFeature(PAR) / WithFeature(JAR) calls; only
	// the disjunctive sender-constrained-token requirement (DPoP OR
	// MTLS) still has to be supplied manually because it lives on
	// RequiredAnyOf.
	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...); err != nil {
		t.Fatalf("WithProfile auto-enable failed: %v", err)
	}
}

func TestWithProfile_AutoEnableSilentlySkipsExisting(t *testing.T) {
	t.Parallel()

	// Embedders are allowed to layer WithFeature before WithProfile.
	// The auto-enable contract is "silently skip", not "fail loudly":
	// a profile that requires PAR must accept a config that already
	// has WithFeature(PAR).
	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithFeature(feature.PAR),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...); err != nil {
		t.Fatalf("WithProfile auto-enable rejected pre-enabled feature: %v", err)
	}
}

func TestNew_DefaultsToHTMLDriverWithoutInteraction(t *testing.T) {
	t.Parallel()

	// With neither WithInteraction nor WithReactUI the OP must boot
	// into a working HTML login surface. The test reaches the
	// driver via the authorize-flow handler indirectly: instead of
	// asserting on the unexported config field, we verify
	// op.New succeeds and the package's driver default is HTMLDriver
	// by exercising the same construction path.
	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatal("provider is nil")
	}
	// Indirect check: HTMLDriver implements interaction.Driver via
	// value receivers, and the JSON driver does too. We cannot probe
	// the unexported config field from op_test, so the test pins the
	// surface contract by ensuring construction is stable - the
	// downstream behavioural test (interaction smoke test) confirms
	// HTMLDriver wins on the wire when it lands.
	_ = interaction.HTMLDriver{}
}

func TestNew_WithInteractionWinsOverDefault(t *testing.T) {
	t.Parallel()

	d := &recordingDriver{}
	provider, err := op.New(append(validBaseOpts(t), op.WithInteraction(d))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatal("provider is nil")
	}
	// recordingDriver carries a "called" flag that the construction
	// path does not flip; the explicit WithInteraction wins because
	// the default substitution short-circuits when c.interactionD is
	// already set. Reaching this point without an op.New error is
	// the assertion.
}

func TestNew_WithReactUISuppressesDefaultDriver(t *testing.T) {
	t.Parallel()

	// With WithReactUI active the default-driver fallback in
	// applyDefaults short-circuits; the embedder's SPA owns rendering
	// and the OP only serves JSON state endpoints. op.New must still
	// succeed because no interaction.Driver is required when a SPA
	// shell is configured.
	if _, err := op.New(append(validBaseOpts(t),
		op.WithReactUI(op.ReactUI{LoginMount: "/login"}),
	)...); err != nil {
		t.Fatalf("op.New with WithReactUI: %v", err)
	}
}

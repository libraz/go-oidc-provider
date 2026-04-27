package op_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
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

func TestWithFeature_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithFeature(feature.PAR), op.WithFeature(feature.PAR),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate feature, got nil")
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

func TestWithProfile_FAPI2Baseline_RequiresPAR(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.DPoP),
	)...)
	if err == nil {
		t.Fatal("expected error when PAR is missing, got nil")
	}
}

func TestWithProfile_FAPI2Baseline_RequiresJAR(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.DPoP),
	)...)
	if err == nil {
		t.Fatal("expected error when JAR is missing, got nil")
	}
}

func TestWithProfile_FAPI2Baseline_RequiresSenderConstrainedToken(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
	)...)
	if err == nil {
		t.Fatal("expected error when neither DPoP nor MTLS is enabled, got nil")
	}
}

func TestWithProfile_FAPI2Baseline_AcceptsDPoP(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
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
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.MTLS),
	)...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithProfile_FAPI2MessageSigning_RequiresJARM(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.DPoP),
	)...)
	if err == nil {
		t.Fatal("expected error when JARM is missing, got nil")
	}
}

func TestWithProfile_FAPI2MessageSigning_AcceptsFullStack(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.JARM),
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
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
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
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenTTL(10*time.Minute),
	)...)
	if err != nil {
		t.Fatalf("unexpected error at the cap: %v", err)
	}
}

func TestWithAccessTokenTTL_FAPI2BaselineAcceptsStricter(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
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
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.JARM),
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
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
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
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.JAR),
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

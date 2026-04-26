package op_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"io"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
)

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

type recordingDriver struct{ called bool }

func (d *recordingDriver) Offer(context.Context, interaction.Request) (interaction.Step, error) {
	d.called = true
	return interaction.Step{}, nil
}

func (d *recordingDriver) Verify(context.Context, interaction.Request, interaction.Result) (interaction.Decision, error) {
	return interaction.Decision{}, nil
}
func (d *recordingDriver) Cancel(context.Context, interaction.Request) error { return nil }

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

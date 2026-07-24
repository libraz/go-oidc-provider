package keys_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

// TestNewEncryptionSet_RejectsEmpty pins the empty-input contract
// (the parallel of [keys.NewSet]'s empty rejection): encryption is
// optional at the op layer but, when supplied, MUST contain at least
// one key.
func TestNewEncryptionSet_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := keys.NewEncryptionSet(nil)
	if !errors.Is(err, keys.ErrInvalidEncryptionKey) {
		t.Fatalf("want ErrInvalidEncryptionKey, got %v", err)
	}
}

func TestNewEncryptionSet_RejectsTypedNilPrivateKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		key  any
	}{
		{name: "rsa", key: (*rsa.PrivateKey)(nil)},
		{name: "ecdsa", key: (*ecdsa.PrivateKey)(nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := keys.NewEncryptionSet([]keys.EncryptionEntry{{
				KeyID:      "typed-nil-" + tc.name,
				PrivateKey: tc.key,
			}})
			if !errors.Is(err, keys.ErrInvalidEncryptionKey) {
				t.Fatalf("error = %v, want ErrInvalidEncryptionKey", err)
			}
		})
	}
}

// TestNewEncryptionSet_RejectsDuplicateKID guards JWKS shape: every
// kid MUST be unique within the set so RPs can route an inbound JWE
// to a single private key.
func TestNewEncryptionSet_RejectsDuplicateKID(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSA(t)
	_, err := keys.NewEncryptionSet([]keys.EncryptionEntry{
		{KeyID: "dup", PrivateKey: rsaKey},
		{KeyID: "dup", PrivateKey: rsaKey},
	})
	if !errors.Is(err, keys.ErrInvalidEncryptionKey) {
		t.Fatalf("want ErrInvalidEncryptionKey, got %v", err)
	}
}

// TestNewEncryptionSet_RejectsSubMinimumRSA pins the 2048-bit floor.
// Keys below the floor would weaken the OAEP-256 padding guarantee.
func TestNewEncryptionSet_RejectsSubMinimumRSA(t *testing.T) {
	t.Parallel()

	// 1024-bit RSA is intentionally weak — we want to verify the
	// validator rejects it. gosec G403 fires on weak key generation
	// in non-test code; the linter exemption covers this fixture.
	short, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // intentional weak key for floor-rejection test
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	_, err = keys.NewEncryptionSet([]keys.EncryptionEntry{
		{KeyID: "k1", PrivateKey: short},
	})
	if !errors.Is(err, keys.ErrInvalidEncryptionKey) {
		t.Fatalf("want ErrInvalidEncryptionKey, got %v", err)
	}
}

// TestNewEncryptionSet_RejectsP224 pins the curve allow-list. P-224
// is rejected because no JWE alg in the v0.9.1 ship list pairs with
// it, and admitting unsupported curves quietly would just defer the
// failure to the first decrypt attempt.
func TestNewEncryptionSet_RejectsP224(t *testing.T) {
	t.Parallel()

	ec, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	_, err = keys.NewEncryptionSet([]keys.EncryptionEntry{
		{KeyID: "k1", PrivateKey: ec},
	})
	if !errors.Is(err, keys.ErrInvalidEncryptionKey) {
		t.Fatalf("want ErrInvalidEncryptionKey, got %v", err)
	}
}

// TestEncryptionSet_Resolve_HappyPath asserts that a known kid
// resolves to the private key, and an unknown kid returns ok=false.
// Decrypt callers depend on this distinction to surface
// ErrJWEKidUnknown vs falling back to trial decryption.
func TestEncryptionSet_Resolve_HappyPath(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSA(t)
	set, err := keys.NewEncryptionSet([]keys.EncryptionEntry{
		{KeyID: "k1", PrivateKey: rsaKey},
	})
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}
	got, ok := set.Resolve("k1")
	if !ok {
		t.Fatalf("Resolve(k1): want ok=true")
	}
	if got != rsaKey {
		t.Fatalf("Resolve(k1): wrong key returned")
	}
	if _, ok := set.Resolve("nope"); ok {
		t.Fatalf("Resolve(nope): want ok=false")
	}
}

// TestEncryptionSet_RetirementGate asserts that NotAfter is
// honoured: a kid past its deadline is reported as unknown so
// decrypt callers cannot use a retired key.
func TestEncryptionSet_RetirementGate(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSA(t)
	frozen := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	set, err := keys.NewEncryptionSet(
		[]keys.EncryptionEntry{
			{KeyID: "retired", PrivateKey: rsaKey, NotAfter: frozen},
		},
		keys.WithClock(func() time.Time { return frozen.Add(time.Hour) }),
	)
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}
	if _, ok := set.Resolve("retired"); ok {
		t.Fatalf("Resolve(retired): want ok=false after deadline")
	}
}

// TestEncryptionSet_All_HoldsLiveKeysOnly asserts the kid-absent
// fallback iterator skips retired entries; otherwise an attacker
// could induce trial decryption against a key the OP no longer
// trusts.
func TestEncryptionSet_All_HoldsLiveKeysOnly(t *testing.T) {
	t.Parallel()

	rsaA := mustRSA(t)
	rsaB := mustRSA(t)
	frozen := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	set, err := keys.NewEncryptionSet(
		[]keys.EncryptionEntry{
			{KeyID: "live", PrivateKey: rsaA},
			{KeyID: "retired", PrivateKey: rsaB, NotAfter: frozen},
		},
		keys.WithClock(func() time.Time { return frozen.Add(time.Hour) }),
	)
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}
	all := set.All()
	if len(all) != 1 {
		t.Fatalf("All: want 1 live key, got %d", len(all))
	}
	if all[0] != rsaA {
		t.Fatalf("All: returned the wrong key")
	}
}

// TestEncryptionSet_JWKS_PublishesUseEnc asserts every published JWK
// carries use=enc, the right kid, and an alg label the v0.9.1 ship
// list recognises.
func TestEncryptionSet_JWKS_PublishesUseEnc(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSA(t)
	set, err := keys.NewEncryptionSet([]keys.EncryptionEntry{
		{KeyID: "k1", PrivateKey: rsaKey},
	})
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}
	jwks := set.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("JWKS: want 1 key, got %d", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.Use != "enc" {
		t.Fatalf("Use: want enc, got %q", k.Use)
	}
	if k.KeyID != "k1" {
		t.Fatalf("KeyID: want k1, got %q", k.KeyID)
	}
	if k.Algorithm != "RSA-OAEP-256" {
		t.Fatalf("Algorithm: want RSA-OAEP-256, got %q", k.Algorithm)
	}
}

// TestEncryptionSet_JWKS_OmitsRetiredEntries keeps publication aligned with
// decryption: a recipient that is no longer accepted must not remain in the
// OP JWKS for an RP to select.
func TestEncryptionSet_JWKS_OmitsRetiredEntries(t *testing.T) {
	t.Parallel()

	deadline := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	set, err := keys.NewEncryptionSet(
		[]keys.EncryptionEntry{
			{KeyID: "active", PrivateKey: mustRSA(t)},
			{KeyID: "retired", PrivateKey: mustRSA(t), NotAfter: deadline},
		},
		keys.WithClock(func() time.Time { return deadline }),
	)
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}

	jwks := set.JWKS()
	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "active" {
		t.Fatalf("JWKS = %#v, want only active key", jwks.Keys)
	}
	if _, ok := set.Resolve("retired"); ok {
		t.Fatal("Resolve(retired) succeeded after its publication/decryption deadline")
	}
}

// TestEncryptionSet_ExplicitECDHESVariant asserts that an ECDH-ES key
// can pin a specific key-wrap variant via [EncryptionEntry.Algorithm];
// the published JWK reflects the explicit alg rather than the inferred
// "ECDH-ES" default.
func TestEncryptionSet_ExplicitECDHESVariant(t *testing.T) {
	t.Parallel()

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	set, err := keys.NewEncryptionSet([]keys.EncryptionEntry{
		{KeyID: "k1", PrivateKey: ec, Algorithm: "ECDH-ES+A256KW"},
	})
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}
	if set.JWKS().Keys[0].Algorithm != "ECDH-ES+A256KW" {
		t.Fatalf("explicit alg not preserved on JWKS")
	}
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

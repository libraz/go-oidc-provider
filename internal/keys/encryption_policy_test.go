package keys_test

import (
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/keys"
)

// TestEncryptionSet_JWEPolicy_ReachesDecrypt walks the whole inbound
// chain a narrowing has to survive: op.WithSupportedEncryptionAlgs
// becomes a [jose.JWEPolicy], the policy rides on the
// [keys.EncryptionSet] the OP hands to every JWE verifier, and
// [jose.Decrypt] reads it back off the resolver. Without the last link
// the narrowing would only shrink the discovery document while the OP
// kept decrypting the excluded algorithm.
// The narrowing keeps one member of the key's own family, which is the
// only shape a set can be built in: a narrowing that excluded the family
// outright would leave the entry with no advertisable alg and fail
// construction instead of reaching Decrypt.
func TestEncryptionSet_JWEPolicy_ReachesDecrypt(t *testing.T) {
	t.Parallel()

	ecKey := mustECDSAKey(t)
	ciphertext, err := jose.Encrypt([]byte("request object"), jose.EncryptionRecipient{
		Alg:   jose.JWEAlgECDHES,
		Enc:   jose.JWEEncA256GCM,
		KeyID: "enc-1",
		Key:   &ecKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	entries := []keys.EncryptionEntry{{KeyID: "enc-1", PrivateKey: ecKey}}

	unnarrowed, err := keys.NewEncryptionSet(entries)
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}
	if _, err := jose.Decrypt(ciphertext, unnarrowed); err != nil {
		t.Fatalf("Decrypt without narrowing: %v", err)
	}

	narrowed, err := keys.NewEncryptionSet(entries, keys.WithJWEPolicy(jose.JWEPolicy{
		Algs: []jose.JWEAlg{jose.JWEAlgECDHESA256KW},
		Encs: []jose.JWEEnc{jose.JWEEncA256GCM},
	}))
	if err != nil {
		t.Fatalf("NewEncryptionSet with policy: %v", err)
	}
	if _, err := jose.Decrypt(ciphertext, narrowed); !errors.Is(err, jose.ErrJWEAlgNotAllowed) {
		t.Fatalf("Decrypt with narrowing: got %v want %v", err, jose.ErrJWEAlgNotAllowed)
	}
}

// TestNewEncryptionSet_RejectsFamilyExcludedByNarrowing pins the
// construction-time half of the same coupling. A key whose family the
// narrowing removed can never decrypt anything, so publishing it — with
// any alg label at all — would point relying parties at a recipient the
// OP unconditionally refuses.
func TestNewEncryptionSet_RejectsFamilyExcludedByNarrowing(t *testing.T) {
	t.Parallel()

	for name, entry := range map[string]keys.EncryptionEntry{
		"inferred alg": {KeyID: "enc-1", PrivateKey: mustRSA(t)},
		"explicit alg": {KeyID: "enc-1", PrivateKey: mustRSA(t), Algorithm: "RSA-OAEP-256"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := keys.NewEncryptionSet(
				[]keys.EncryptionEntry{entry},
				keys.WithJWEPolicy(jose.JWEPolicy{Algs: []jose.JWEAlg{jose.JWEAlgECDHES}}),
			)
			if !errors.Is(err, keys.ErrInvalidEncryptionKey) {
				t.Fatalf("NewEncryptionSet err = %v, want ErrInvalidEncryptionKey", err)
			}
		})
	}
}

// TestNewEncryptionSet_PublishesEveryAlgWithinNarrowing is the positive
// counterpart: whatever alg survives onto the published JWK must be a
// member of the very policy [jose.Decrypt] enforces, so an RP reading
// the JWKS document and an RP reading the discovery document reach the
// same conclusion.
func TestNewEncryptionSet_PublishesEveryAlgWithinNarrowing(t *testing.T) {
	t.Parallel()

	// The default label for an EC key is ECDH-ES; narrowing it away must
	// move the advertisement onto a surviving family member rather than
	// leave the excluded default on the wire.
	policy := jose.JWEPolicy{Algs: []jose.JWEAlg{jose.JWEAlgECDHESA128KW, jose.JWEAlgRSAOAEP256}}
	set, err := keys.NewEncryptionSet([]keys.EncryptionEntry{
		{KeyID: "ec-1", PrivateKey: mustECDSAKey(t)},
		{KeyID: "rsa-1", PrivateKey: mustRSA(t)},
	}, keys.WithJWEPolicy(policy))
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}
	for _, jwk := range set.JWKS().Keys {
		alg, ok := jose.ParseJWEAlg(jwk.Algorithm)
		if !ok {
			t.Fatalf("published JWK %q carries unparseable alg %q", jwk.KeyID, jwk.Algorithm)
		}
		if !policy.AllowsAlg(alg) {
			t.Errorf("published JWK %q advertises alg %q the deployment narrowing excludes", jwk.KeyID, alg)
		}
	}
}

// TestNewEncryptionSet_EmptyNarrowingOmitsAlg pins the deliberate
// "publish keys, negotiate nothing" posture documented on
// op.WithSupportedEncryptionAlgs. No alg can truthfully be advertised
// there, and RFC 7517 §4.4 makes the member OPTIONAL, so the key is
// published without one rather than rejected or mislabelled.
func TestNewEncryptionSet_EmptyNarrowingOmitsAlg(t *testing.T) {
	t.Parallel()

	set, err := keys.NewEncryptionSet(
		[]keys.EncryptionEntry{{KeyID: "enc-1", PrivateKey: mustRSA(t)}},
		keys.WithJWEPolicy(jose.JWEPolicy{Algs: []jose.JWEAlg{}}),
	)
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}
	for _, jwk := range set.JWKS().Keys {
		if jwk.Algorithm != "" {
			t.Errorf("published JWK %q advertises alg %q under an empty narrowing", jwk.KeyID, jwk.Algorithm)
		}
	}
}

// TestEncryptionSet_JWEPolicy_DefaultsToLibraryCeiling pins the
// omitted-option case: a set built without [keys.WithJWEPolicy] must
// present the zero policy, which [jose.Decrypt] reads as "the package
// allow-list, unmodified".
func TestEncryptionSet_JWEPolicy_DefaultsToLibraryCeiling(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSA(t)
	set, err := keys.NewEncryptionSet([]keys.EncryptionEntry{{KeyID: "enc-1", PrivateKey: rsaKey}})
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}
	policy := set.JWEPolicy()
	if policy.Algs != nil || policy.Encs != nil {
		t.Fatalf("default policy is not the zero value: %+v", policy)
	}
	for _, alg := range jose.AllowedJWEAlgs() {
		if !policy.AllowsAlg(alg) {
			t.Errorf("default policy rejects shipped alg %q", alg)
		}
	}
}

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
func TestEncryptionSet_JWEPolicy_ReachesDecrypt(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSA(t)
	ciphertext, err := jose.Encrypt([]byte("request object"), jose.EncryptionRecipient{
		Alg:   jose.JWEAlgRSAOAEP256,
		Enc:   jose.JWEEncA256GCM,
		KeyID: "enc-1",
		Key:   &rsaKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	entries := []keys.EncryptionEntry{{KeyID: "enc-1", PrivateKey: rsaKey}}

	unnarrowed, err := keys.NewEncryptionSet(entries)
	if err != nil {
		t.Fatalf("NewEncryptionSet: %v", err)
	}
	if _, err := jose.Decrypt(ciphertext, unnarrowed); err != nil {
		t.Fatalf("Decrypt without narrowing: %v", err)
	}

	narrowed, err := keys.NewEncryptionSet(entries, keys.WithJWEPolicy(jose.JWEPolicy{
		Algs: []jose.JWEAlg{jose.JWEAlgECDHES},
		Encs: []jose.JWEEnc{jose.JWEEncA256GCM},
	}))
	if err != nil {
		t.Fatalf("NewEncryptionSet with policy: %v", err)
	}
	if _, err := jose.Decrypt(ciphertext, narrowed); !errors.Is(err, jose.ErrJWEAlgNotAllowed) {
		t.Fatalf("Decrypt with narrowing: got %v want %v", err, jose.ErrJWEAlgNotAllowed)
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

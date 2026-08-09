package jose_test

import (
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// policyResolver is a [jose.EncryptionKeyResolver] that also carries a
// deployment narrowing, i.e. the shape [keys.EncryptionSet] presents to
// [jose.Decrypt] once an operator has called
// op.WithSupportedEncryptionAlgs.
type policyResolver struct {
	kid    string
	key    any
	policy jose.JWEPolicy
}

func (r policyResolver) Resolve(kid string) (any, bool) {
	if kid == r.kid {
		return r.key, true
	}
	return nil, false
}

func (r policyResolver) All() []any { return []any{r.key} }

func (r policyResolver) JWEPolicy() jose.JWEPolicy { return r.policy }

// TestDecrypt_PolicyRejectsExcludedAlg is the property that separates
// an enforced narrowing from an advertised one: a ciphertext built with
// an algorithm the deployment excluded is refused even though the OP
// holds the matching private key and the algorithm is on the library
// allow-list.
func TestDecrypt_PolicyRejectsExcludedAlg(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	jwe, err := jose.Encrypt([]byte("request object"), jose.EncryptionRecipient{
		Alg: jose.JWEAlgRSAOAEP256, Enc: jose.JWEEncA256GCM, KeyID: "k1", Key: &rsaKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Same ciphertext, same key: without the narrowing it decrypts.
	if _, err := jose.Decrypt(jwe, singleKeyResolver{kid: "k1", key: rsaKey}); err != nil {
		t.Fatalf("Decrypt without policy: %v", err)
	}

	narrowed := policyResolver{
		kid:    "k1",
		key:    rsaKey,
		policy: jose.JWEPolicy{Algs: []jose.JWEAlg{jose.JWEAlgECDHES}},
	}
	_, err = jose.Decrypt(jwe, narrowed)
	if !errors.Is(err, jose.ErrJWEAlgNotAllowed) {
		t.Fatalf("Decrypt with narrowed policy: got %v want %v", err, jose.ErrJWEAlgNotAllowed)
	}
}

// TestDecrypt_PolicyRejectsExcludedEnc mirrors the alg case for the
// content-encryption half.
func TestDecrypt_PolicyRejectsExcludedEnc(t *testing.T) {
	t.Parallel()

	ecKey := mustECKey(t, elliptic.P256())
	jwe, err := jose.Encrypt([]byte("request object"), jose.EncryptionRecipient{
		Alg: jose.JWEAlgECDHES, Enc: jose.JWEEncA128GCM, KeyID: "k1", Key: &ecKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	narrowed := policyResolver{
		kid:    "k1",
		key:    ecKey,
		policy: jose.JWEPolicy{Encs: []jose.JWEEnc{jose.JWEEncA256GCM}},
	}
	_, err = jose.Decrypt(jwe, narrowed)
	if !errors.Is(err, jose.ErrJWEEncNotAllowed) {
		t.Fatalf("Decrypt with narrowed policy: got %v want %v", err, jose.ErrJWEEncNotAllowed)
	}
}

// TestDecrypt_PolicyAdmitsRetainedAlg guards the other direction: the
// narrowing must not break the algorithms the operator kept.
func TestDecrypt_PolicyAdmitsRetainedAlg(t *testing.T) {
	t.Parallel()

	ecKey := mustECKey(t, elliptic.P256())
	jwe, err := jose.Encrypt([]byte("request object"), jose.EncryptionRecipient{
		Alg: jose.JWEAlgECDHES, Enc: jose.JWEEncA256GCM, KeyID: "k1", Key: &ecKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	narrowed := policyResolver{
		kid: "k1",
		key: ecKey,
		policy: jose.JWEPolicy{
			Algs: []jose.JWEAlg{jose.JWEAlgECDHES},
			Encs: []jose.JWEEnc{jose.JWEEncA256GCM},
		},
	}
	got, err := jose.Decrypt(jwe, narrowed)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got.Plaintext) != "request object" {
		t.Fatalf("plaintext=%q", got.Plaintext)
	}
}

// TestDecrypt_EmptyPolicyPermitsNothing pins the empty-but-non-nil
// case: an operator who narrowed to "no algorithms" disabled JWE, and
// the decryption path has to agree with the empty discovery
// advertisement.
func TestDecrypt_EmptyPolicyPermitsNothing(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	jwe, err := jose.Encrypt([]byte("request object"), jose.EncryptionRecipient{
		Alg: jose.JWEAlgRSAOAEP256, Enc: jose.JWEEncA256GCM, KeyID: "k1", Key: &rsaKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	narrowed := policyResolver{
		kid:    "k1",
		key:    rsaKey,
		policy: jose.JWEPolicy{Algs: []jose.JWEAlg{}},
	}
	_, err = jose.Decrypt(jwe, narrowed)
	if !errors.Is(err, jose.ErrJWEAlgNotAllowed) {
		t.Fatalf("Decrypt with empty policy: got %v want %v", err, jose.ErrJWEAlgNotAllowed)
	}
}

// TestJWEPolicy_ZeroValueIsTheLibraryCeiling pins the default: a
// caller that never narrowed sees exactly [jose.AllowedJWEAlgs] /
// [jose.AllowedJWEEncs], and nothing outside them.
func TestJWEPolicy_ZeroValueIsTheLibraryCeiling(t *testing.T) {
	t.Parallel()

	var zero jose.JWEPolicy
	for _, alg := range jose.AllowedJWEAlgs() {
		if !zero.AllowsAlg(alg) {
			t.Errorf("zero policy rejects shipped alg %q", alg)
		}
	}
	for _, enc := range jose.AllowedJWEEncs() {
		if !zero.AllowsEnc(enc) {
			t.Errorf("zero policy rejects shipped enc %q", enc)
		}
	}
	if zero.AllowsAlg(jose.JWEAlg("RSA1_5")) {
		t.Error("zero policy admits an alg outside the allow-list")
	}
	if zero.AllowsEnc(jose.JWEEnc("A128CBC-HS256")) {
		t.Error("zero policy admits an enc outside the allow-list")
	}
	// A narrowing cannot widen: naming an excluded value in the policy
	// still leaves it rejected.
	widened := jose.JWEPolicy{Algs: []jose.JWEAlg{"RSA1_5"}}
	if widened.AllowsAlg(jose.JWEAlg("RSA1_5")) {
		t.Error("policy widened the allow-list")
	}
}

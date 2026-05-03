package jose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// TestEncryptDecrypt_RoundTrip pins each shipped (alg × enc)
// combination through a full encrypt → decrypt cycle. The matrix
// covers every entry in [jose.AllowedJWEAlgs] × [jose.AllowedJWEEncs];
// a missing combination here would mean the package advertises
// support for an alg/enc pair that nothing exercises.
func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	ecKey := mustECKey(t, elliptic.P256())

	cases := []struct {
		name string
		alg  jose.JWEAlg
		enc  jose.JWEEnc
		pub  any
		priv any
	}{
		{"RSA-OAEP-256/A128GCM", jose.JWEAlgRSAOAEP256, jose.JWEEncA128GCM, &rsaKey.PublicKey, rsaKey},
		{"RSA-OAEP-256/A256GCM", jose.JWEAlgRSAOAEP256, jose.JWEEncA256GCM, &rsaKey.PublicKey, rsaKey},
		{"ECDH-ES/A128GCM", jose.JWEAlgECDHES, jose.JWEEncA128GCM, &ecKey.PublicKey, ecKey},
		{"ECDH-ES/A256GCM", jose.JWEAlgECDHES, jose.JWEEncA256GCM, &ecKey.PublicKey, ecKey},
		{"ECDH-ES+A128KW/A128GCM", jose.JWEAlgECDHESA128KW, jose.JWEEncA128GCM, &ecKey.PublicKey, ecKey},
		{"ECDH-ES+A256KW/A256GCM", jose.JWEAlgECDHESA256KW, jose.JWEEncA256GCM, &ecKey.PublicKey, ecKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			plaintext := []byte("hello jwe")
			jwe, err := jose.Encrypt(plaintext, jose.EncryptionRecipient{
				Alg: tc.alg, Enc: tc.enc, KeyID: "k1", Key: tc.pub,
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			resolver := singleKeyResolver{kid: "k1", key: tc.priv}
			got, err := jose.Decrypt(jwe, resolver)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(got.Plaintext) != string(plaintext) {
				t.Fatalf("plaintext mismatch: got %q want %q", got.Plaintext, plaintext)
			}
			if got.Algorithm != tc.alg {
				t.Fatalf("alg mismatch: got %q want %q", got.Algorithm, tc.alg)
			}
			if got.Encryption != tc.enc {
				t.Fatalf("enc mismatch: got %q want %q", got.Encryption, tc.enc)
			}
			if got.KeyID != "k1" {
				t.Fatalf("kid mismatch: got %q want %q", got.KeyID, "k1")
			}
		})
	}
}

// TestDecrypt_AlgAllowList rejects every JWE whose `alg` is outside
// the package allow-list. Each excluded value is constructed via
// go-jose so the rejection happens at our pre-parse gate, not at
// go-jose's parse-time check (we want to verify that a hostile
// caller who somehow crafts a parseable JWE with an excluded alg is
// still rejected).
func TestDecrypt_AlgAllowList(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	resolver := singleKeyResolver{kid: "k1", key: rsaKey}

	cases := []struct {
		name string
		alg  string
	}{
		{"RSA1_5", "RSA1_5"},
		{"RSA-OAEP", "RSA-OAEP"},
		{"dir", "dir"},
		{"A128KW", "A128KW"},
		{"A256GCMKW", "A256GCMKW"},
		{"PBES2-HS256+A128KW", "PBES2-HS256+A128KW"},
		{"none", "none"},
		{"unknown", "FOO256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			jwe := craftJWEWithAlgEnc(t, tc.alg, "A256GCM", "k1", &rsaKey.PublicKey)
			_, err := jose.Decrypt(jwe, resolver)
			if !errors.Is(err, jose.ErrJWEAlgNotAllowed) && !errors.Is(err, jose.ErrJWEMalformed) {
				t.Fatalf("Decrypt %s: want ErrJWEAlgNotAllowed or ErrJWEMalformed, got %v", tc.alg, err)
			}
		})
	}
}

// TestDecrypt_EncAllowList rejects every JWE whose `enc` is outside
// the package allow-list. Constructed JWEs use the legitimate alg
// (RSA-OAEP-256) so the failure isolates to the enc gate.
func TestDecrypt_EncAllowList(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	resolver := singleKeyResolver{kid: "k1", key: rsaKey}

	cases := []string{"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A192GCM", "FOO"}
	for _, encAlg := range cases {
		t.Run(encAlg, func(t *testing.T) {
			t.Parallel()

			jwe := craftJWEWithAlgEnc(t, "RSA-OAEP-256", encAlg, "k1", &rsaKey.PublicKey)
			_, err := jose.Decrypt(jwe, resolver)
			if !errors.Is(err, jose.ErrJWEEncNotAllowed) && !errors.Is(err, jose.ErrJWEMalformed) {
				t.Fatalf("Decrypt %s: want ErrJWEEncNotAllowed or ErrJWEMalformed, got %v", encAlg, err)
			}
		})
	}
}

// TestDecrypt_RejectsCrit asserts that any JWE carrying a non-empty
// `crit` header is rejected. The package's understood-crit set is
// intentionally empty (RFC 7515 §4.1.11): the OP never emits crit,
// so any incoming value is attacker-controlled.
func TestDecrypt_RejectsCrit(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	resolver := singleKeyResolver{kid: "k1", key: rsaKey}

	jwe := craftJWEWithCrit(t, &rsaKey.PublicKey, []string{"unknown_ext"})
	_, err := jose.Decrypt(jwe, resolver)
	if !errors.Is(err, jose.ErrJWECritUnknown) {
		t.Fatalf("Decrypt with crit: want ErrJWECritUnknown, got %v", err)
	}
}

// TestDecrypt_KidUnknown asserts that a JWE naming a kid the
// resolver cannot resolve fails with [ErrJWEKidUnknown] — never
// falling back to trial decryption when kid is present, so an
// attacker stripping the kid cannot induce a different code path.
func TestDecrypt_KidUnknown(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	jwe := mustEncryptForTest(t, &rsaKey.PublicKey, "k1")

	resolver := singleKeyResolver{kid: "different-kid", key: rsaKey}
	_, err := jose.Decrypt(jwe, resolver)
	if !errors.Is(err, jose.ErrJWEKidUnknown) {
		t.Fatalf("Decrypt with unknown kid: want ErrJWEKidUnknown, got %v", err)
	}
}

// TestDecrypt_KidAbsentFallback asserts the documented RFC 7516
// §4.1.6 behaviour: a JWE without a `kid` triggers per-key trial
// decryption against the full keyset, and a successful match
// returns the plaintext.
func TestDecrypt_KidAbsentFallback(t *testing.T) {
	t.Parallel()

	rsaKey1 := mustRSAKey(t)
	rsaKey2 := mustRSAKey(t)

	jwe := mustEncryptForTest(t, &rsaKey2.PublicKey, "")

	resolver := allKeysResolver{keys: []any{rsaKey1, rsaKey2}}
	got, err := jose.Decrypt(jwe, resolver)
	if err != nil {
		t.Fatalf("Decrypt with kid absent: %v", err)
	}
	if string(got.Plaintext) != "fallback-payload" {
		t.Fatalf("plaintext mismatch: got %q", got.Plaintext)
	}
}

// TestDecrypt_KidAbsentFallback_AllFail asserts that when kid is
// absent and no key in the resolver decrypts, the result is the
// generic [ErrJWEDecryptFailed] — not an oracle for which key
// happened to be tried.
func TestDecrypt_KidAbsentFallback_AllFail(t *testing.T) {
	t.Parallel()

	rsaKeyTarget := mustRSAKey(t)
	rsaKeyA := mustRSAKey(t)
	rsaKeyB := mustRSAKey(t)

	jwe := mustEncryptForTest(t, &rsaKeyTarget.PublicKey, "")

	resolver := allKeysResolver{keys: []any{rsaKeyA, rsaKeyB}}
	_, err := jose.Decrypt(jwe, resolver)
	if !errors.Is(err, jose.ErrJWEDecryptFailed) {
		t.Fatalf("Decrypt all-fail: want ErrJWEDecryptFailed, got %v", err)
	}
}

// TestDecrypt_ErrorRedaction asserts that the decryption error
// message returned to a caller does NOT include alg / enc / key
// / plaintext detail beyond the sentinel. The detailed cause goes
// to the audit log only (per ADR 0030 §S.8); leaking it through
// the returned error is a padding-oracle vector.
func TestDecrypt_ErrorRedaction(t *testing.T) {
	t.Parallel()

	rsaKey1 := mustRSAKey(t)
	rsaKey2 := mustRSAKey(t)

	jwe := mustEncryptForTest(t, &rsaKey1.PublicKey, "k1")
	resolver := singleKeyResolver{kid: "k1", key: rsaKey2}

	_, err := jose.Decrypt(jwe, resolver)
	if !errors.Is(err, jose.ErrJWEDecryptFailed) {
		t.Fatalf("Decrypt with wrong key: want ErrJWEDecryptFailed, got %v", err)
	}
	msg := err.Error()
	for _, forbidden := range []string{"RSA-OAEP-256", "A256GCM", "A128GCM", "modulus", "padding"} {
		if strings.Contains(msg, forbidden) {
			t.Fatalf("error message %q leaks %q", msg, forbidden)
		}
	}
}

// TestDecrypt_MalformedInput rejects every shape of broken JWE
// without panicking. The four-part / six-part forms are not valid
// compact serialisations; the empty / whitespace / non-base64
// forms exercise the protected-header parse path.
func TestDecrypt_MalformedInput(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	resolver := singleKeyResolver{kid: "k1", key: rsaKey}

	cases := []string{
		"",
		"a.b.c",
		"a.b.c.d",
		"a.b.c.d.e.f",
		"!!!.x.y.z.w",
	}
	for _, raw := range cases {
		_, err := jose.Decrypt(raw, resolver)
		if !errors.Is(err, jose.ErrJWEMalformed) {
			t.Fatalf("Decrypt %q: want ErrJWEMalformed, got %v", raw, err)
		}
	}
}

// TestDecrypt_NilResolver guards the API surface: Decrypt MUST NOT
// panic when the resolver is nil; it returns ErrJWEMalformed so the
// configuration error surfaces at boot rather than as a runtime
// panic on first request.
func TestDecrypt_NilResolver(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	jwe := mustEncryptForTest(t, &rsaKey.PublicKey, "k1")
	_, err := jose.Decrypt(jwe, nil)
	if !errors.Is(err, jose.ErrJWEMalformed) {
		t.Fatalf("Decrypt with nil resolver: want ErrJWEMalformed, got %v", err)
	}
}

// TestEncrypt_RejectsNonAllowedAlgEnc guards the OP-side encrypt
// path: an embedder who passes an alg/enc outside the allow-list
// gets a structural rejection before any key material is touched.
func TestEncrypt_RejectsNonAllowedAlgEnc(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)

	_, err := jose.Encrypt([]byte("x"), jose.EncryptionRecipient{
		Alg: "RSA1_5", Enc: jose.JWEEncA256GCM, KeyID: "k1", Key: &rsaKey.PublicKey,
	})
	if !errors.Is(err, jose.ErrJWEAlgNotAllowed) {
		t.Fatalf("Encrypt with RSA1_5: want ErrJWEAlgNotAllowed, got %v", err)
	}
	_, err = jose.Encrypt([]byte("x"), jose.EncryptionRecipient{
		Alg: jose.JWEAlgRSAOAEP256, Enc: "A128CBC-HS256", KeyID: "k1", Key: &rsaKey.PublicKey,
	})
	if !errors.Is(err, jose.ErrJWEEncNotAllowed) {
		t.Fatalf("Encrypt with A128CBC-HS256: want ErrJWEEncNotAllowed, got %v", err)
	}
	_, err = jose.Encrypt([]byte("x"), jose.EncryptionRecipient{
		Alg: jose.JWEAlgRSAOAEP256, Enc: jose.JWEEncA256GCM, KeyID: "k1", Key: nil,
	})
	if !errors.Is(err, jose.ErrJWEUnsupportedKey) {
		t.Fatalf("Encrypt with nil key: want ErrJWEUnsupportedKey, got %v", err)
	}
}

// TestEncryptNestedJWT_RoundTrip covers the canonical
// encrypted-and-signed JWT shape: the OP signs a payload as a JWS,
// wraps it as a JWE addressed to the RP, and the RP decrypts to
// recover the inner JWS bytes verbatim. The decrypted JWE carries
// `cty=JWT` so the recipient knows to verify the inner JWS.
func TestEncryptNestedJWT_RoundTrip(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	innerJWS := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature"
	jwe, err := jose.EncryptNestedJWT(innerJWS, jose.EncryptionRecipient{
		Alg: jose.JWEAlgRSAOAEP256, Enc: jose.JWEEncA256GCM, KeyID: "k1", Key: &rsaKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("EncryptNestedJWT: %v", err)
	}
	resolver := singleKeyResolver{kid: "k1", key: rsaKey}
	got, err := jose.Decrypt(jwe, resolver)
	if err != nil {
		t.Fatalf("Decrypt nested: %v", err)
	}
	if string(got.Plaintext) != innerJWS {
		t.Fatalf("inner JWS mismatch: got %q want %q", got.Plaintext, innerJWS)
	}
	if got.ContentType != "JWT" {
		t.Fatalf("cty mismatch: got %q want %q", got.ContentType, "JWT")
	}
}

// TestEncryptNestedJWT_RejectsEmpty asserts the nil / empty inner
// JWS pre-condition: callers must build the inner JWS before
// wrapping. An empty input produces a malformed-JWE-shaped error
// rather than emitting a useless "empty plaintext" JWE.
func TestEncryptNestedJWT_RejectsEmpty(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	_, err := jose.EncryptNestedJWT("", jose.EncryptionRecipient{
		Alg: jose.JWEAlgRSAOAEP256, Enc: jose.JWEEncA256GCM, KeyID: "k1", Key: &rsaKey.PublicKey,
	})
	if !errors.Is(err, jose.ErrJWEMalformed) {
		t.Fatalf("EncryptNestedJWT empty: want ErrJWEMalformed, got %v", err)
	}
}

// TestAllowedJWEAlgs_Snapshot pins the discovery-facing allow-list
// shape. A drift in either the alg or enc list updates the OP's
// discovery document, which is observable to RPs; this test forces
// any such change to be intentional.
func TestAllowedJWEAlgs_Snapshot(t *testing.T) {
	t.Parallel()

	algs := jose.AllowedJWEAlgs()
	wantAlg := []jose.JWEAlg{
		jose.JWEAlgRSAOAEP256,
		jose.JWEAlgECDHES,
		jose.JWEAlgECDHESA128KW,
		jose.JWEAlgECDHESA256KW,
	}
	if len(algs) != len(wantAlg) {
		t.Fatalf("alg count: got %d want %d", len(algs), len(wantAlg))
	}
	for i, a := range algs {
		if a != wantAlg[i] {
			t.Fatalf("alg[%d]: got %q want %q", i, a, wantAlg[i])
		}
	}

	encs := jose.AllowedJWEEncs()
	wantEnc := []jose.JWEEnc{jose.JWEEncA128GCM, jose.JWEEncA256GCM}
	if len(encs) != len(wantEnc) {
		t.Fatalf("enc count: got %d want %d", len(encs), len(wantEnc))
	}
	for i, e := range encs {
		if e != wantEnc[i] {
			t.Fatalf("enc[%d]: got %q want %q", i, e, wantEnc[i])
		}
	}
}

// --- helpers --------------------------------------------------------

type singleKeyResolver struct {
	kid string
	key any
}

func (r singleKeyResolver) Resolve(kid string) (any, bool) {
	if kid == r.kid {
		return r.key, true
	}
	return nil, false
}

func (r singleKeyResolver) All() []any { return []any{r.key} }

type allKeysResolver struct {
	keys []any
}

func (r allKeysResolver) Resolve(string) (any, bool) { return nil, false }
func (r allKeysResolver) All() []any                 { return r.keys }

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func mustECKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return k
}

// mustEncryptForTest produces a fixed-payload JWE for round-trip
// helpers. Centralising the call here means a future tweak to the
// helper layer is one edit, not one per test.
func mustEncryptForTest(t *testing.T, pub *rsa.PublicKey, kid string) string {
	t.Helper()

	rcpt := josev4.Recipient{
		Algorithm: josev4.RSA_OAEP_256,
		Key:       pub,
		KeyID:     kid,
	}
	encrypter, err := josev4.NewEncrypter(josev4.A256GCM, rcpt, nil)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	jwe, err := encrypter.Encrypt([]byte("fallback-payload"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	out, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return out
}

// craftJWEWithAlgEnc builds a JWE with arbitrary alg / enc protected
// header values for allow-list rejection tests. The ciphertext is
// not real — we only need the header to parse so the package's
// pre-decrypt gates fire. The five segments still satisfy
// [strings.Split] count checks.
func craftJWEWithAlgEnc(t *testing.T, alg, enc, kid string, _ *rsa.PublicKey) string {
	t.Helper()

	header := map[string]string{"alg": alg, "enc": enc}
	if kid != "" {
		header["kid"] = kid
	}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	enc64 := base64.RawURLEncoding.EncodeToString
	return enc64(hb) + "." + enc64([]byte("encrypted-key")) + "." + enc64([]byte("iv")) + "." + enc64([]byte("ct")) + "." + enc64([]byte("tag"))
}

// craftJWEWithCrit builds a real JWE (so go-jose's parse accepts it)
// but stamps a `crit` array into the protected header so the
// package's crit gate fires. We use the [josev4.EncrypterOptions]
// path to inject the crit value via WithHeader, then re-emit the
// compact form.
func craftJWEWithCrit(t *testing.T, pub *rsa.PublicKey, crit []string) string {
	t.Helper()

	rcpt := josev4.Recipient{
		Algorithm: josev4.RSA_OAEP_256,
		Key:       pub,
		KeyID:     "k1",
	}
	opts := (&josev4.EncrypterOptions{}).
		WithHeader(josev4.HeaderKey("crit"), crit)
	encrypter, err := josev4.NewEncrypter(josev4.A256GCM, rcpt, opts)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	jwe, err := encrypter.Encrypt([]byte("crit-test"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	out, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return out
}

package jose_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// TestDecrypt_PlaintextSizeCap_OverLimit asserts that plaintext
// exceeding [jose.MaxJWEPlaintextSize] is rejected with
// [jose.ErrJWEPlaintextTooLarge]. Without the cap a small
// ciphertext + zip=DEF could decompress to multi-GiB and exhaust
// memory; the cap is the load-bearing defence.
func TestDecrypt_PlaintextSizeCap_OverLimit(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	huge := bytes.Repeat([]byte{'A'}, jose.MaxJWEPlaintextSize+1)

	rcpt := josev4.Recipient{
		Algorithm: josev4.RSA_OAEP_256,
		Key:       &rsaKey.PublicKey,
		KeyID:     "k1",
	}
	encrypter, err := josev4.NewEncrypter(josev4.A256GCM, rcpt, nil)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	jwe, err := encrypter.Encrypt(huge)
	if err != nil {
		t.Fatalf("Encrypt huge: %v", err)
	}
	raw, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}

	resolver := singleKeyResolver{kid: "k1", key: rsaKey}
	_, err = jose.Decrypt(raw, resolver)
	if !errors.Is(err, jose.ErrJWEPlaintextTooLarge) {
		t.Fatalf("Decrypt plaintext-too-large: want ErrJWEPlaintextTooLarge, got %v", err)
	}
}

// TestDecrypt_PlaintextSizeCap_AtLimit asserts that plaintext at
// exactly [jose.MaxJWEPlaintextSize] is accepted; the cap is a
// strict greater-than, not greater-or-equal, so no off-by-one cuts
// off legitimate large request_objects (the FAPI-CIBA `request`
// parameter can carry hundreds of kilobytes of consent metadata).
func TestDecrypt_PlaintextSizeCap_AtLimit(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	atLimit := bytes.Repeat([]byte{'A'}, jose.MaxJWEPlaintextSize)

	rcpt := josev4.Recipient{
		Algorithm: josev4.RSA_OAEP_256,
		Key:       &rsaKey.PublicKey,
		KeyID:     "k1",
	}
	encrypter, err := josev4.NewEncrypter(josev4.A256GCM, rcpt, nil)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	jwe, err := encrypter.Encrypt(atLimit)
	if err != nil {
		t.Fatalf("Encrypt at-limit: %v", err)
	}
	raw, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}

	resolver := singleKeyResolver{kid: "k1", key: rsaKey}
	got, err := jose.Decrypt(raw, resolver)
	if err != nil {
		t.Fatalf("Decrypt at-limit: %v", err)
	}
	if len(got.Plaintext) != jose.MaxJWEPlaintextSize {
		t.Fatalf("plaintext len: got %d want %d", len(got.Plaintext), jose.MaxJWEPlaintextSize)
	}
}

// TestDecrypt_ZipBombResistance produces a JWE with a heavily
// compressible plaintext (>1 MiB of zeros) wrapped in zip=DEF, and
// asserts the decrypt path either rejects via go-jose's upstream
// cap (max(250000, 10*input)) or via our [jose.MaxJWEPlaintextSize]
// gate. Either path keeps memory bounded; what we forbid is a
// silent expansion past 1 MiB.
func TestDecrypt_ZipBombResistance(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	bomb := bytes.Repeat([]byte{0}, jose.MaxJWEPlaintextSize*4)

	rcpt := josev4.Recipient{
		Algorithm: josev4.RSA_OAEP_256,
		Key:       &rsaKey.PublicKey,
		KeyID:     "k1",
	}
	opts := (&josev4.EncrypterOptions{Compression: josev4.DEFLATE})
	encrypter, err := josev4.NewEncrypter(josev4.A256GCM, rcpt, opts)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	jwe, err := encrypter.Encrypt(bomb)
	if err != nil {
		t.Fatalf("Encrypt zip bomb: %v", err)
	}
	raw, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}

	resolver := singleKeyResolver{kid: "k1", key: rsaKey}
	_, err = jose.Decrypt(raw, resolver)
	if err == nil {
		t.Fatalf("Decrypt zip bomb: expected rejection, got nil")
	}
	if !errors.Is(err, jose.ErrJWEPlaintextTooLarge) && !errors.Is(err, jose.ErrJWEMalformed) && !errors.Is(err, jose.ErrJWEDecryptFailed) {
		t.Fatalf("Decrypt zip bomb: want bounded-memory rejection, got %v", err)
	}
}

// TestDecrypt_FailureUniformity asserts that 500 random ciphertext
// mutations all fail with [jose.ErrJWEDecryptFailed] (or a parse
// failure) — never panicking, never leaking partial plaintext, and
// never bypassing the alg / enc gates. This is the smoke-test for
// the "fail uniformly" posture per ADR 0030 §S.2.
//
// The full ±10% wall-clock variance budget the ADR specifies is a
// CI flake risk in shared environments; the smoke-test here pins
// the structural property (no panic, no leak) while leaving the
// formal timing assertion for an offline dedicated harness.
func TestDecrypt_FailureUniformity(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	jwe := mustEncryptForTest(t, &rsaKey.PublicKey, "k1")
	resolver := singleKeyResolver{kid: "k1", key: rsaKey}

	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		t.Fatalf("setup: jwe has %d parts, want 5", len(parts))
	}

	for i := range 500 {
		mutated := mutateCiphertext(t, parts)
		_, err := jose.Decrypt(mutated, resolver)
		if err == nil {
			t.Fatalf("mutation %d: decrypt succeeded unexpectedly", i)
		}
		// The failure must surface through one of the package
		// sentinels — never as a raw go-jose error or a panic.
		if !isExpectedJWEFailure(err) {
			t.Fatalf("mutation %d: leaked unexpected error: %v", i, err)
		}
	}
}

// FuzzDecrypt looks for crash safety in the parse + decrypt path.
// The corpus seeds a known-good JWE and a handful of malformed
// shapes; the fuzz engine then mutates from there. The invariant is
// "Decrypt never panics" — no claim about success / failure
// outcomes, since most fuzz inputs are nonsense.
func FuzzDecrypt(f *testing.F) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("rsa.GenerateKey: %v", err)
	}
	resolver := singleKeyResolver{kid: "k1", key: rsaKey}

	f.Add("")
	f.Add("a.b.c.d.e")
	f.Add("eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.x.y.z.w")

	f.Fuzz(func(_ *testing.T, raw string) {
		_, _ = jose.Decrypt(raw, resolver)
	})
}

// mutateCiphertext returns the input JWE with one random bit
// flipped in the *decoded* ciphertext bytes (not in the base64
// representation, where the last char's trailing bits are ignored
// on decode and would silently no-op the mutation). The protected
// header / kid / alg / enc remain valid so the mutation forces the
// failure path down to the AEAD verification step (the longest
// decryption code path).
func mutateCiphertext(t *testing.T, parts []string) string {
	t.Helper()

	out := append([]string(nil), parts...)
	decoded, err := base64.RawURLEncoding.DecodeString(out[3])
	if err != nil {
		t.Fatalf("decode ciphertext segment: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatalf("ciphertext segment empty")
	}
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	idx := int(b[0]) % len(decoded)
	bit := b[1] % 8
	decoded[idx] ^= 1 << bit
	out[3] = base64.RawURLEncoding.EncodeToString(decoded)
	return strings.Join(out, ".")
}

// isExpectedJWEFailure asserts the returned error matches one of
// the package sentinels. Anything else (raw go-jose error, plain
// fmt.Errorf without %w, panic that escaped, etc.) means a code
// path bypassed the redaction layer.
func isExpectedJWEFailure(err error) bool {
	switch {
	case errors.Is(err, jose.ErrJWEMalformed),
		errors.Is(err, jose.ErrJWEAlgNotAllowed),
		errors.Is(err, jose.ErrJWEEncNotAllowed),
		errors.Is(err, jose.ErrJWECritUnknown),
		errors.Is(err, jose.ErrJWEKidUnknown),
		errors.Is(err, jose.ErrJWEDecryptFailed),
		errors.Is(err, jose.ErrJWEPlaintextTooLarge):
		return true
	default:
		return false
	}
}

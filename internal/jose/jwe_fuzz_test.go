package jose_test

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// mustRSAKeyB is the [testing.TB]-shaped sibling of mustRSAKey. The
// fuzz harness needs to mint a key during f.Setup-equivalent code
// where only [*testing.F] is available; the helper exists so the
// production-test key path stays untouched.
func mustRSAKeyB(tb testing.TB) *rsa.PrivateKey {
	tb.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

// FuzzJWENested seeds [jose.DecryptChain] with deeply nested JWE
// payloads and feeds the harness arbitrary mutations on top. The
// invariants the fuzzer asserts are deliberately structural:
//
//   - The function MUST NOT panic for any input. JOSE input arrives
//     from untrusted RPs; a panic on the JAR verifier path would
//     translate into a denial-of-service vector.
//   - When [jose.DecryptChain] returns nil error, the reported
//     [jose.NestedDecryption.JWELayers] MUST be on the closed
//     interval [0, MaxJOSENestingDepth-1] (the budget the JAR caller
//     passes). A return outside that range would indicate the depth
//     accounting drifted from the documented contract.
//   - When the function returns an error, no plaintext bytes are
//     leaked through the Plaintext field. The caller relies on the
//     "either-or" envelope.
//
// The fuzz target seeds a 1-, 5-, 10-, and 11-layer JWE chain so the
// corpus already covers the boundary; the engine then mutates the
// bytes of those chains. Per CLAUDE.md "DB / 外部 IdP のモック使用は禁止"
// the fuzzer exercises JOSE primitives directly without any mocked
// transport.
func FuzzJWENested(f *testing.F) {
	rsaKey := mustRSAKeyB(f)
	resolver := singleKeyResolver{kid: "k1", key: rsaKey}

	leaf := "leaf-payload"
	for _, depth := range []int{0, 1, 5, 10, 11} {
		payload := leaf
		for i := 0; i < depth; i++ {
			out, err := jose.Encrypt([]byte(payload), jose.EncryptionRecipient{
				Alg:   jose.JWEAlgRSAOAEP256,
				Enc:   jose.JWEEncA256GCM,
				KeyID: "k1",
				Key:   &rsaKey.PublicKey,
			})
			if err != nil {
				f.Fatalf("seed Encrypt: %v", err)
			}
			payload = out
		}
		f.Add(payload)
	}
	// Add a few non-JWE shapes so the engine explores the
	// looksLikeJWE = false branch as well.
	f.Add("")
	f.Add("not.a.jwe")
	f.Add("a.b.c.d.e") // 5-segment but malformed JWE
	f.Add(strings.Repeat("a.", 10))

	f.Fuzz(func(t *testing.T, raw string) {
		// The fuzz engine drives this closure many times; the work
		// inside is CPU-bound RSA decrypt attempts, so we let the
		// scheduler run them in parallel like every other test in
		// this package.
		t.Parallel()
		out, err := jose.DecryptChain(raw, resolver, jose.MaxJOSENestingDepth-1)
		if err != nil {
			// On error, no plaintext escapes.
			if len(out.Plaintext) != 0 {
				t.Fatalf("error path leaked plaintext (%d bytes): err=%v", len(out.Plaintext), err)
			}
			return
		}
		if out.JWELayers < 0 || out.JWELayers > jose.MaxJOSENestingDepth-1 {
			t.Fatalf("JWELayers=%d outside [0, %d]", out.JWELayers, jose.MaxJOSENestingDepth-1)
		}
	})
}

// FuzzJWENestedDecrypt complements [FuzzJWENested] by driving the
// single-layer [jose.Decrypt] entry point with the same corpus shape.
// The boundary checks differ: Decrypt has no depth concept, so the
// invariants reduce to "no panic" + "error xor plaintext".
func FuzzJWENestedDecrypt(f *testing.F) {
	rsaKey := mustRSAKeyB(f)
	resolver := singleKeyResolver{kid: "k1", key: rsaKey}

	out, err := jose.Encrypt([]byte("leaf"), jose.EncryptionRecipient{
		Alg:   jose.JWEAlgRSAOAEP256,
		Enc:   jose.JWEEncA256GCM,
		KeyID: "k1",
		Key:   &rsaKey.PublicKey,
	})
	if err != nil {
		f.Fatalf("seed Encrypt: %v", err)
	}
	f.Add(out)
	f.Add("")
	f.Add("not.a.jwe")
	f.Add("a.b.c.d.e")

	f.Fuzz(func(t *testing.T, raw string) {
		t.Parallel()
		got, derr := jose.Decrypt(raw, resolver)
		if derr != nil && len(got.Plaintext) != 0 {
			t.Fatalf("error path leaked plaintext: %d bytes, err=%v", len(got.Plaintext), derr)
		}
	})
}

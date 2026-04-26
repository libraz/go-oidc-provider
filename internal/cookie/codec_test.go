package cookie_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/cookie"
)

// newKey returns a 32-byte random AES-256 key. The fixture lives in the test
// package so the production code never imports crypto/rand for the sole
// purpose of "generate me a key" — that responsibility stays with callers.
func newKey(tb testing.TB) []byte {
	tb.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		tb.Fatalf("rand.Read: %v", err)
	}
	return k
}

func TestNewCodec_RejectsBadKeyLength(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		"empty":   nil,
		"short":   make([]byte, 16),
		"too_big": make([]byte, 64),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := cookie.NewCodec(key)
			if !errors.Is(err, cookie.ErrInvalidKey) {
				t.Errorf("err=%v want ErrInvalidKey", err)
			}
		})
	}
}

func TestNewCodec_RejectsBadPreviousKey(t *testing.T) {
	t.Parallel()

	_, err := cookie.NewCodec(newKey(t), make([]byte, 8))
	if !errors.Is(err, cookie.ErrInvalidKey) {
		t.Errorf("err=%v want ErrInvalidKey on rotation slot", err)
	}
}

func TestCodec_RoundTrip(t *testing.T) {
	t.Parallel()

	c, err := cookie.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	plaintext := []byte(`{"chooser":"abc","sid":"S1"}`)
	aad := []byte("__Host-oidc_session")

	sealed, err := c.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := c.Open(sealed, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch: %q want %q", got, plaintext)
	}
}

func TestCodec_AADBindingPreventsCookieSwap(t *testing.T) {
	t.Parallel()

	c, err := cookie.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	sealed, err := c.Seal([]byte("payload"), []byte("__Host-oidc_session"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := c.Open(sealed, []byte("__Host-oidc_interaction")); !errors.Is(err, cookie.ErrDecrypt) {
		t.Errorf("Open with mismatched aad: err=%v want ErrDecrypt", err)
	}
}

func TestCodec_OpenRejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()

	c, err := cookie.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	sealed, err := c.Seal([]byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Decode, flip a byte in the middle of the GCM ciphertext, re-encode.
	// Mutating the base64 string directly is unreliable because trailing
	// base64 bits can be silently dropped by the decoder.
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	raw[len(raw)/2] ^= 0xff
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	if _, err := c.Open(tampered, []byte("aad")); !errors.Is(err, cookie.ErrDecrypt) {
		t.Errorf("Open with tampered ciphertext: err=%v want ErrDecrypt", err)
	}
}

func TestCodec_OpenRejectsGarbage(t *testing.T) {
	t.Parallel()

	c, err := cookie.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	cases := map[string]string{
		"empty":      "",
		"not_b64":    "!!! not valid base64 !!!",
		"too_short":  "AA", // valid b64 but shorter than nonce
		"random_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := c.Open(in, []byte("aad")); !errors.Is(err, cookie.ErrDecrypt) {
				t.Errorf("Open(%q) err=%v want ErrDecrypt", in, err)
			}
		})
	}
}

func TestCodec_RotationDecryptsWithPreviousKey(t *testing.T) {
	t.Parallel()

	oldKey := newKey(t)
	newKeyBytes := newKey(t)

	// Encrypt with the original key.
	old, err := cookie.NewCodec(oldKey)
	if err != nil {
		t.Fatalf("NewCodec old: %v", err)
	}
	sealed, err := old.Seal([]byte("rotation-test"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Rotate: new key is current, old key is in the rotation list.
	rotated, err := cookie.NewCodec(newKeyBytes, oldKey)
	if err != nil {
		t.Fatalf("NewCodec rotated: %v", err)
	}
	got, err := rotated.Open(sealed, []byte("aad"))
	if err != nil {
		t.Fatalf("Open after rotation: %v", err)
	}
	if string(got) != "rotation-test" {
		t.Errorf("plaintext=%q want rotation-test", got)
	}
}

func TestCodec_RotationReencryptsWithCurrentKey(t *testing.T) {
	t.Parallel()

	oldKey := newKey(t)
	newKeyBytes := newKey(t)

	rotated, err := cookie.NewCodec(newKeyBytes, oldKey)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	sealed, err := rotated.Seal([]byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// A codec holding only the OLD key must NOT be able to decrypt the
	// payload — proves new encryptions go to the current (new) key only.
	oldOnly, err := cookie.NewCodec(oldKey)
	if err != nil {
		t.Fatalf("NewCodec old-only: %v", err)
	}
	if _, err := oldOnly.Open(sealed, []byte("aad")); !errors.Is(err, cookie.ErrDecrypt) {
		t.Errorf("old-only codec opened new-key payload: err=%v want ErrDecrypt", err)
	}
}

func TestCodec_DistinctNoncesPerSeal(t *testing.T) {
	t.Parallel()

	c, err := cookie.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	a, _ := c.Seal([]byte("same-payload"), []byte("aad"))
	b, _ := c.Seal([]byte("same-payload"), []byte("aad"))
	if a == b {
		t.Error("two seals of the same plaintext produced identical ciphertext (nonce reuse)")
	}
}

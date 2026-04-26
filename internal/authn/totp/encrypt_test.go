package totp_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn/totp"
)

// newKey returns a 32-byte random AES-256 key. Lives in the test
// package so production code never reaches for crypto/rand for the
// sole purpose of fixture generation.
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
			_, err := totp.NewCodec(key)
			if !errors.Is(err, totp.ErrInvalidKey) {
				t.Errorf("err=%v want ErrInvalidKey", err)
			}
		})
	}
}

func TestNewCodec_RejectsBadPreviousKey(t *testing.T) {
	t.Parallel()

	_, err := totp.NewCodec(newKey(t), make([]byte, 8))
	if !errors.Is(err, totp.ErrInvalidKey) {
		t.Errorf("err=%v want ErrInvalidKey on rotation slot", err)
	}
}

func TestCodec_RoundTrip(t *testing.T) {
	t.Parallel()

	c, err := totp.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	secret := []byte("12345678901234567890")
	aad := []byte("user-12345")

	blob, err := c.Seal(secret, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := c.Open(blob, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("plaintext mismatch: %x want %x", got, secret)
	}
}

func TestCodec_AADBindingPreventsCrossUserReplay(t *testing.T) {
	t.Parallel()

	c, err := totp.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	blob, err := c.Seal([]byte("12345678901234567890"), []byte("user-alice"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := c.Open(blob, []byte("user-bob")); !errors.Is(err, totp.ErrDecrypt) {
		t.Errorf("Open with mismatched aad: err=%v want ErrDecrypt", err)
	}
}

func TestCodec_OpenRejectsTooShort(t *testing.T) {
	t.Parallel()

	c, err := totp.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if _, err := c.Open([]byte{0x00}, []byte("aad")); !errors.Is(err, totp.ErrDecrypt) {
		t.Errorf("Open(short) err=%v want ErrDecrypt", err)
	}
	if _, err := c.Open(nil, []byte("aad")); !errors.Is(err, totp.ErrDecrypt) {
		t.Errorf("Open(nil) err=%v want ErrDecrypt", err)
	}
}

func TestCodec_OpenRejectsTamperedBlob(t *testing.T) {
	t.Parallel()

	c, err := totp.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	blob, err := c.Seal([]byte("12345678901234567890"), []byte("user-alice"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	tampered := bytes.Clone(blob)
	tampered[len(tampered)/2] ^= 0xff
	if _, err := c.Open(tampered, []byte("user-alice")); !errors.Is(err, totp.ErrDecrypt) {
		t.Errorf("Open(tampered) err=%v want ErrDecrypt", err)
	}
}

func TestCodec_RotationDecryptsWithPreviousKey(t *testing.T) {
	t.Parallel()

	oldKey := newKey(t)
	newKeyBytes := newKey(t)

	old, err := totp.NewCodec(oldKey)
	if err != nil {
		t.Fatalf("NewCodec old: %v", err)
	}
	blob, err := old.Seal([]byte("12345678901234567890"), []byte("user-alice"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	rotated, err := totp.NewCodec(newKeyBytes, oldKey)
	if err != nil {
		t.Fatalf("NewCodec rotated: %v", err)
	}
	got, err := rotated.Open(blob, []byte("user-alice"))
	if err != nil {
		t.Fatalf("Open after rotation: %v", err)
	}
	if string(got) != "12345678901234567890" {
		t.Errorf("plaintext=%q want 12345678901234567890", got)
	}
}

func TestCodec_NewEncryptionsUseCurrentKey(t *testing.T) {
	t.Parallel()

	oldKey := newKey(t)
	newKeyBytes := newKey(t)

	rotated, err := totp.NewCodec(newKeyBytes, oldKey)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	blob, err := rotated.Seal([]byte("12345678901234567890"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Old-only codec must NOT decrypt: proves new encryptions go to
	// the current key only.
	oldOnly, err := totp.NewCodec(oldKey)
	if err != nil {
		t.Fatalf("NewCodec old-only: %v", err)
	}
	if _, err := oldOnly.Open(blob, []byte("aad")); !errors.Is(err, totp.ErrDecrypt) {
		t.Errorf("old-only codec opened new-key payload: err=%v want ErrDecrypt", err)
	}
}

func TestCodec_DistinctNoncesPerSeal(t *testing.T) {
	t.Parallel()

	c, err := totp.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	a, _ := c.Seal([]byte("same-payload-of-twenty-bytes"), []byte("aad"))
	b, _ := c.Seal([]byte("same-payload-of-twenty-bytes"), []byte("aad"))
	if bytes.Equal(a, b) {
		t.Error("two seals of the same plaintext produced identical bytes (nonce reuse)")
	}
}

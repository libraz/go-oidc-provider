package keys_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

var errTestBadKey = errors.New("bad key")

func ringKey(b byte) []byte { return bytes.Repeat([]byte{b}, keys.AEADKeyLen) }

func TestAEADRing_RoundTripAndRotation(t *testing.T) {
	t.Parallel()
	old, err := keys.NewAEADRing(errTestBadKey, ringKey(1))
	if err != nil {
		t.Fatal(err)
	}
	blob := old.Seal([]byte("secret"), []byte("aad"))

	rotated, err := keys.NewAEADRing(errTestBadKey, ringKey(2), ringKey(1))
	if err != nil {
		t.Fatal(err)
	}
	pt, ok := rotated.Open(blob, []byte("aad"))
	if !ok || string(pt) != "secret" {
		t.Fatalf("Open after rotation = %q, %v", pt, ok)
	}
	if _, ok := rotated.Open(blob, []byte("other")); ok {
		t.Fatal("Open accepted a blob under a different aad")
	}
	if _, ok := rotated.Open(blob[:5], []byte("aad")); ok {
		t.Fatal("Open accepted a truncated blob")
	}
}

// The ring's wire format must stay nonce||ciphertext||tag so blobs sealed
// by the earlier explicit-nonce GCM construction keep opening.
func TestAEADRing_OpensExplicitNonceBlob(t *testing.T) {
	t.Parallel()
	block, err := aes.NewCipher(ringKey(3))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{9}, gcm.NonceSize())
	blob := gcm.Seal(bytes.Clone(nonce), nonce, []byte("legacy"), []byte("aad"))

	r, err := keys.NewAEADRing(errTestBadKey, ringKey(3))
	if err != nil {
		t.Fatal(err)
	}
	pt, ok := r.Open(blob, []byte("aad"))
	if !ok || string(pt) != "legacy" {
		t.Fatalf("Open legacy blob = %q, %v", pt, ok)
	}
}

func TestNewAEADRing_RejectsBadKeyLength(t *testing.T) {
	t.Parallel()
	if _, err := keys.NewAEADRing(errTestBadKey, ringKey(1)[:31]); err != errTestBadKey { //nolint:errorlint // the current-key error is returned bare.
		t.Fatalf("short current key: err = %v", err)
	}
	_, err := keys.NewAEADRing(errTestBadKey, ringKey(1), ringKey(2)[:16])
	if !errors.Is(err, errTestBadKey) {
		t.Fatalf("short previous key: err = %v", err)
	}
}

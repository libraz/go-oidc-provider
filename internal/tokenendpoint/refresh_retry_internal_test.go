package tokenendpoint

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// sealRefreshRetryLegacy is the AES-GCM layout stored records already use:
// a zero version byte, then nonce||ciphertext||tag under the derived key.
func sealRefreshRetryLegacy(t *testing.T, material []byte, predecessor string, response successResponse) []byte {
	t.Helper()
	plain, err := json.Marshal(response) //nolint:gosec // test fixture sealing a synthetic response.
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(deriveRefreshRetryKey(material))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	out := append([]byte{0}, nonce...)
	return gcm.Seal(out, nonce, plain, []byte(predecessor))
}

func TestRefreshRetryResponse_OpensLegacyBlob(t *testing.T) {
	t.Parallel()
	active, rotated := []byte("active-cookie-key-material-0000"), []byte("older-cookie-key-material-00000")
	want := successResponse{AccessToken: "at", RefreshToken: "rt"}

	blob := sealRefreshRetryLegacy(t, rotated, "pred", want)
	got, err := openRefreshRetryResponse([][]byte{active, rotated}, "pred", blob)
	if err != nil {
		t.Fatalf("open legacy blob: %v", err)
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if _, err := openRefreshRetryResponse([][]byte{active, rotated}, "other", blob); err == nil {
		t.Fatal("blob opened under a different predecessor")
	}
}

func TestRefreshRetryResponse_SealedBlobKeepsLegacyLayout(t *testing.T) {
	t.Parallel()
	material := []byte("active-cookie-key-material-0000")
	want := successResponse{AccessToken: "at", RefreshToken: "rt"}

	sealed, err := sealRefreshRetryResponse([][]byte{material}, "pred", want)
	if err != nil {
		t.Fatal(err)
	}
	if sealed[0] != 0 {
		t.Fatalf("version byte = %d, want 0", sealed[0])
	}
	block, _ := aes.NewCipher(deriveRefreshRetryKey(material))
	gcm, _ := cipher.NewGCM(block)
	ns := gcm.NonceSize()
	plain, err := gcm.Open(nil, sealed[1:1+ns], sealed[1+ns:], []byte("pred"))
	if err != nil {
		t.Fatalf("legacy opener rejected new blob: %v", err)
	}
	var got successResponse
	if err := json.Unmarshal(plain, &got); err != nil || got.AccessToken != "at" {
		t.Fatalf("plaintext = %s (%v)", plain, err)
	}
}

package keys_test

import (
	"encoding/base64"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

func TestRandomBase64URL_LengthAndAlphabet(t *testing.T) {
	t.Parallel()
	for _, n := range []int{16, 32} {
		got, err := keys.RandomBase64URL(n)
		if err != nil {
			t.Fatalf("RandomBase64URL(%d): %v", n, err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(got)
		if err != nil {
			t.Fatalf("RandomBase64URL(%d) = %q is not unpadded base64url: %v", n, got, err)
		}
		if len(raw) != n {
			t.Fatalf("RandomBase64URL(%d) decoded to %d bytes", n, len(raw))
		}
	}
	a, _ := keys.RandomBase64URL(32)
	b, _ := keys.RandomBase64URL(32)
	if a == b {
		t.Fatal("two draws returned the same value")
	}
}

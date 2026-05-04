package totpkit_test

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/totpkit"
)

// newKey returns a 32-byte AES-256 key sourced from crypto/rand. The
// helper centralises fixture generation so production paths never
// reach for crypto/rand for testing-only purposes.
func newKey(tb testing.TB) []byte {
	tb.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		tb.Fatalf("rand.Read: %v", err)
	}
	return k
}

// TestNewCodec_RejectsShortKey pins the AES-256-GCM 32-byte
// requirement against a 16-byte (AES-128-sized) key. Accepting it
// would silently weaken the cipher; ErrInvalidKey at construction
// time forces the operator to surface the misconfiguration before
// any record is sealed.
func TestNewCodec_RejectsShortKey(t *testing.T) {
	t.Parallel()

	_, err := totpkit.NewCodec(make([]byte, 16))
	if !errors.Is(err, totpkit.ErrInvalidKey) {
		t.Errorf("err=%v want ErrInvalidKey", err)
	}
}

// TestNewCodec_RejectsLongKey pins the same property against an
// over-sized key. AES-256-GCM is exactly 32 bytes; a 64-byte key
// would either truncate or be rejected by the AEAD constructor —
// neither outcome is acceptable, so NewCodec MUST refuse up front.
func TestNewCodec_RejectsLongKey(t *testing.T) {
	t.Parallel()

	_, err := totpkit.NewCodec(make([]byte, 64))
	if !errors.Is(err, totpkit.ErrInvalidKey) {
		t.Errorf("err=%v want ErrInvalidKey", err)
	}
}

// TestNewCodec_RejectsZeroKey covers nil and empty slices. Both
// represent "the operator forgot to wire WithMFAEncryptionKeys"; the
// construction-time error makes that misconfiguration loud rather
// than letting the codec encrypt under whatever zero-bytes-key the
// AEAD would build.
func TestNewCodec_RejectsZeroKey(t *testing.T) {
	t.Parallel()

	for _, key := range [][]byte{nil, {}} {
		_, err := totpkit.NewCodec(key)
		if !errors.Is(err, totpkit.ErrInvalidKey) {
			t.Errorf("err=%v want ErrInvalidKey", err)
		}
	}
}

// TestNewCodec_AcceptsRotation verifies the rotation-history slot
// accepts multiple 32-byte keys. The verify path reads the same
// codec, so accepting two prior keys at construction time matches
// the production posture: an embedder rotating cookie / TOTP keys in
// lock-step will hand both predecessors to NewCodec.
func TestNewCodec_AcceptsRotation(t *testing.T) {
	t.Parallel()

	codec, err := totpkit.NewCodec(newKey(t), newKey(t), newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if codec == nil {
		t.Fatal("codec is nil after successful NewCodec")
	}
}

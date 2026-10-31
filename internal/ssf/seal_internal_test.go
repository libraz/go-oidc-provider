package ssf

import (
	"bytes"
	"errors"
	"testing"
)

const testHeader = "Bearer receiver-secret"

func newTestSealer(t *testing.T, current []byte, previous ...[]byte) *Sealer {
	t.Helper()
	s, err := NewSealer(current, previous...)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return s
}

func TestSeal_RoundTripAndLayout(t *testing.T) {
	t.Parallel()
	s := newTestSealer(t, testSealKey(t))
	a := s.Seal("stream-1", testHeader)
	b := s.Seal("stream-1", testHeader)
	if want := 12 + len(testHeader) + 16; len(a) != want {
		t.Errorf("sealed length = %d, want nonce(12)+plaintext+tag(16) = %d", len(a), want)
	}
	if bytes.Equal(a[:12], b[:12]) {
		t.Error("two seals reused a nonce")
	}
	if bytes.Contains(a, []byte(testHeader)) {
		t.Error("sealed value contains the plaintext")
	}
	got, err := s.Unseal("stream-1", a)
	if err != nil || got != testHeader {
		t.Fatalf("Unseal = %q, %v", got, err)
	}
}

func TestSeal_StreamIDIsBound(t *testing.T) {
	t.Parallel()
	s := newTestSealer(t, testSealKey(t))
	sealed := s.Seal("stream-1", testHeader)
	if _, err := s.Unseal("stream-2", sealed); !errors.Is(err, ErrUnseal) {
		t.Fatalf("blob opened under another stream ID: err = %v", err)
	}
}

func TestSeal_PreviousKeyStillOpens(t *testing.T) {
	t.Parallel()
	oldKey, newKey := testSealKey(t), testSealKey(t)
	sealedOld := newTestSealer(t, oldKey).Seal("stream-1", testHeader)

	rotated := newTestSealer(t, newKey, oldKey)
	if got, err := rotated.Unseal("stream-1", sealedOld); err != nil || got != testHeader {
		t.Fatalf("previous-key blob: Unseal = %q, %v", got, err)
	}
	sealedNew := rotated.Seal("stream-1", testHeader)
	if _, err := newTestSealer(t, oldKey).Unseal("stream-1", sealedNew); !errors.Is(err, ErrUnseal) {
		t.Errorf("new seal did not use the current key: err = %v", err)
	}
	if _, err := newTestSealer(t, newKey).Unseal("stream-1", sealedOld); !errors.Is(err, ErrUnseal) {
		t.Errorf("blob opened after its key left the ring: err = %v", err)
	}
}

func TestSeal_TamperAndTruncationFail(t *testing.T) {
	t.Parallel()
	s := newTestSealer(t, testSealKey(t))
	sealed := s.Seal("stream-1", testHeader)
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 0x01
	for name, blob := range map[string][]byte{
		"tampered":  tampered,
		"truncated": sealed[:8],
		"empty":     nil,
	} {
		if _, err := s.Unseal("stream-1", blob); !errors.Is(err, ErrUnseal) {
			t.Errorf("%s: err = %v, want ErrUnseal", name, err)
		}
	}
}

func TestSeal_RejectsBadKeyLength(t *testing.T) {
	t.Parallel()
	if _, err := NewSealer(make([]byte, 16)); !errors.Is(err, ErrSealKey) {
		t.Errorf("16-byte current key: err = %v", err)
	}
	if _, err := NewSealer(testSealKey(t), make([]byte, 31)); !errors.Is(err, ErrSealKey) {
		t.Errorf("31-byte previous key: err = %v", err)
	}
	if _, err := NewSealer(nil); !errors.Is(err, ErrSealKey) {
		t.Errorf("nil key: err = %v", err)
	}
}

package op

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func hmacLabel(label string, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	return h.Sum(nil)
}

func TestKeyDerivationMatchesHMACOfLabel(t *testing.T) {
	t.Parallel()
	cur := bytes.Repeat([]byte{1}, 32)
	prev := bytes.Repeat([]byte{2}, 32)
	rings := []struct {
		label string
		one   func([]byte) []byte
		ring  func([][]byte) ([]byte, [][]byte)
	}{
		{csrfDerivationLabel, deriveCSRFKey, deriveCSRFSigningKeys},
		{stateRefDerivationLabel, deriveStateRefKey, deriveStateRefSigningKeys},
		{ssfSealDerivationLabel, deriveSSFSealKey, deriveSSFSealKeys},
	}
	for _, r := range rings {
		if !bytes.Equal(r.one(cur), hmacLabel(r.label, cur)) {
			t.Errorf("%s: single-key derivation diverges", r.label)
		}
		c, p := r.ring([][]byte{cur, prev})
		if !bytes.Equal(c, hmacLabel(r.label, cur)) || len(p) != 1 || !bytes.Equal(p[0], hmacLabel(r.label, prev)) {
			t.Errorf("%s: ring derivation diverges", r.label)
		}
		if c, p := r.ring(nil); c != nil || p != nil {
			t.Errorf("%s: empty ring must derive nothing", r.label)
		}
		if _, p := r.ring([][]byte{cur}); p == nil || len(p) != 0 {
			t.Errorf("%s: single-key ring must yield an empty non-nil previous slice", r.label)
		}
	}
	if !bytes.Equal(deriveCompletionKey(cur), hmacLabel(completionDerivationLabel, cur)) {
		t.Error("completion key derivation diverges")
	}
}

package emailotp

import "testing"

func TestCodeModulusMatchesCodeDigits(t *testing.T) {
	t.Parallel()
	want := uint64(1)
	for range codeDigits {
		want *= 10
	}
	if codeModulus != want {
		t.Fatalf("codeModulus = %d, want 10^%d = %d", codeModulus, codeDigits, want)
	}
}

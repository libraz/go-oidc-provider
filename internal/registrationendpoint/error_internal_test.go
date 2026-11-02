package registrationendpoint

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeDescription_TruncatesOnRuneBoundary(t *testing.T) {
	t.Parallel()

	// 199 ASCII bytes then a 3-byte rune straddles the 200-byte ceiling.
	in := strings.Repeat("a", maxDescriptionBytes-1) + "あ" + "tail"
	got := sanitizeDescription(in)
	if !utf8.ValidString(got) {
		t.Fatalf("truncated description is not valid UTF-8: %q", got)
	}
	if len(got) > maxDescriptionBytes {
		t.Fatalf("len=%d exceeds %d", len(got), maxDescriptionBytes)
	}
	if want := strings.Repeat("a", maxDescriptionBytes-1); got != want {
		t.Errorf("got %d bytes, want the %d-byte ASCII prefix", len(got), len(want))
	}
}

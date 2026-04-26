package recovery_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
)

func TestGenerateBatch_ReturnsTenCodes(t *testing.T) {
	t.Parallel()

	codes, err := recovery.GenerateBatch()
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	if len(codes) != 10 {
		t.Errorf("len(codes)=%d want 10", len(codes))
	}
}

func TestGenerateBatch_CodesAreFormatted(t *testing.T) {
	t.Parallel()

	codes, err := recovery.GenerateBatch()
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	for i, c := range codes {
		if len(c) != 11 {
			t.Errorf("codes[%d]=%q len=%d want 11 (XXXXX-XXXXX)", i, c, len(c))
		}
		if c[5] != '-' {
			t.Errorf("codes[%d]=%q hyphen not at index 5", i, c)
		}
	}
}

func TestGenerateBatch_CodesAreDistinct(t *testing.T) {
	t.Parallel()

	// 10 codes drawn from a 10-character base32 alphabet collide with
	// probability ~10^-13; this test will flake once per ~10^12 runs
	// in expectation. That's acceptable: a real failure means the
	// entropy source is broken and the assertion firing is a feature.
	codes, err := recovery.GenerateBatch()
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	seen := make(map[string]struct{}, len(codes))
	for _, c := range codes {
		if _, dup := seen[c]; dup {
			t.Errorf("duplicate code in batch: %q", c)
		}
		seen[c] = struct{}{}
	}
}

func TestGenerateBatch_AlphabetExcludesAmbiguousGlyphs(t *testing.T) {
	t.Parallel()

	// Crockford's alphabet excludes I, L, O, U to remove transcription
	// ambiguity (I/1/L, O/0). A batch of 10 codes drawn from a
	// 32-symbol alphabet of 100 characters total is virtually certain
	// to surface at least one of every legitimate symbol over a few
	// runs; the assertion below targets the absence of the forbidden
	// glyphs across many batches to keep the false-negative rate
	// negligible.
	const rounds = 50
	for _, forbidden := range []rune{'I', 'L', 'O', 'U'} {
		t.Run(string(forbidden), func(t *testing.T) {
			t.Parallel()
			for r := range rounds {
				codes, err := recovery.GenerateBatch()
				if err != nil {
					t.Fatalf("round %d: GenerateBatch: %v", r, err)
				}
				for _, c := range codes {
					if strings.ContainsRune(c, forbidden) {
						t.Fatalf("round %d code=%q contains forbidden glyph %q", r, c, forbidden)
					}
				}
			}
		})
	}
}

func TestGenerateBatch_CodesUseUppercaseAlphabet(t *testing.T) {
	t.Parallel()

	codes, err := recovery.GenerateBatch()
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	for _, c := range codes {
		for _, r := range c {
			if r == '-' {
				continue
			}
			switch {
			case r >= '0' && r <= '9':
			case r >= 'A' && r <= 'Z':
			default:
				t.Errorf("code=%q contains invalid character %q", c, r)
			}
		}
	}
}

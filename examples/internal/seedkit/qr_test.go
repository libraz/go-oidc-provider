//go:build example

package seedkit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/examples/internal/seedkit"
)

const sampleURI = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"

// TestQRTerm_Deterministic pins that QRTerm is a pure function of
// its input: encoding the same URI twice produces byte-identical
// output. Without this property the rendered QR could vary across
// runs and an operator copy-pasting the screen would never know
// whether they got the canonical form.
func TestQRTerm_Deterministic(t *testing.T) {
	t.Parallel()

	a, err := seedkit.QRTerm(sampleURI)
	if err != nil {
		t.Fatalf("QRTerm a: %v", err)
	}
	b, err := seedkit.QRTerm(sampleURI)
	if err != nil {
		t.Fatalf("QRTerm b: %v", err)
	}
	if a != b {
		t.Errorf("QRTerm not deterministic: len(a)=%d len(b)=%d", len(a), len(b))
	}
}

// TestQRTerm_NonEmpty asserts the rendered string is non-empty for
// a non-empty input, contains at least the four glyphs the renderer
// emits, and produces multiple lines (a single-line QR is impossible
// because a QR with a 4-module quiet zone is at least 9 modules tall).
func TestQRTerm_NonEmpty(t *testing.T) {
	t.Parallel()

	out, err := seedkit.QRTerm(sampleURI)
	if err != nil {
		t.Fatalf("QRTerm: %v", err)
	}
	if out == "" {
		t.Fatal("QRTerm returned empty string for non-empty input")
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 5 {
		t.Errorf("QRTerm produced %d line(s), want at least 5", len(lines))
	}
	// Every line must use only the renderer's glyph alphabet
	// (U+2580, U+2584, U+2588, and ASCII space). Stray characters
	// would point at an encoding bug.
	for _, line := range lines {
		for _, r := range line {
			switch r {
			case ' ', '▀', '▄', '█':
			default:
				t.Fatalf("unexpected glyph %q in QR rendering", r)
			}
		}
	}
}

// TestQRTerm_QuietZone pins the 4-module quiet zone the QR
// specification mandates. Under the inverted dark-terminal scheme a
// "light" QR module renders as the FULL BLOCK glyph "█" (or the
// half-block variant where a top/bottom pair of light modules
// collapses into one printed row); a "dark" module renders as space.
//
// The leading and trailing four printed rows therefore MUST be
// entirely composed of the FULL BLOCK glyph — any other glyph would
// indicate the quiet zone is missing dark cells touching the edge.
func TestQRTerm_QuietZone(t *testing.T) {
	t.Parallel()

	out, err := seedkit.QRTerm(sampleURI)
	if err != nil {
		t.Fatalf("QRTerm: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("QRTerm produced only %d lines; need at least 4 to inspect the quiet zone", len(lines))
	}
	// quietZone (4 modules) packed into 2-row glyphs produces 2
	// printed rows of all-light cells on top and 2 on the bottom.
	const quietPrintedRows = 2
	for i := range quietPrintedRows {
		if !allFullBlock(lines[i]) {
			t.Errorf("top quiet zone row %d not all-light: %q", i, lines[i])
		}
	}
	for i := len(lines) - quietPrintedRows; i < len(lines); i++ {
		if !allFullBlock(lines[i]) {
			t.Errorf("bottom quiet zone row %d not all-light: %q", i, lines[i])
		}
	}
	// And the leading/trailing 4 columns of every line must be
	// FULL BLOCKs too (left/right quiet zones).
	const quietCols = 4
	for idx, line := range lines {
		runes := []rune(line)
		if len(runes) < 2*quietCols {
			t.Fatalf("line %d shorter than 2 quiet zones: %q", idx, line)
		}
		for j := range quietCols {
			if runes[j] != '█' {
				t.Errorf("line %d left quiet col %d = %q want '█'", idx, j, runes[j])
			}
			if runes[len(runes)-1-j] != '█' {
				t.Errorf("line %d right quiet col %d = %q want '█'", idx, j, runes[len(runes)-1-j])
			}
		}
	}
}

// TestQRTerm_RejectsEmpty pins that QRTerm refuses an empty input
// rather than producing a degenerate 1x1 quiet zone the operator
// cannot scan.
func TestQRTerm_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if _, err := seedkit.QRTerm(""); !errors.Is(err, seedkit.ErrEmptyURI) {
		t.Errorf("QRTerm(\"\") err = %v, want ErrEmptyURI", err)
	}
	if _, err := seedkit.QRTerm("   "); !errors.Is(err, seedkit.ErrEmptyURI) {
		t.Errorf("QRTerm(\"   \") err = %v, want ErrEmptyURI", err)
	}
}

// TestQRTerm_DistinctPayloadsDiffer asserts that two distinct otpauth
// URIs produce distinct rendered QRs. A renderer that ignored its
// input would silently break the demo by encoding a fixed payload.
func TestQRTerm_DistinctPayloadsDiffer(t *testing.T) {
	t.Parallel()

	a, err := seedkit.QRTerm(sampleURI)
	if err != nil {
		t.Fatalf("QRTerm a: %v", err)
	}
	b, err := seedkit.QRTerm(sampleURI + "&period=60")
	if err != nil {
		t.Fatalf("QRTerm b: %v", err)
	}
	if a == b {
		t.Error("two distinct URIs produced identical QR renderings")
	}
}

// allFullBlock reports whether every rune in line is the FULL BLOCK
// glyph "█". Empty lines fail the predicate so the caller cannot
// mistakenly accept a skipped row as a valid quiet-zone row.
func allFullBlock(line string) bool {
	if line == "" {
		return false
	}
	for _, r := range line {
		if r != '█' {
			return false
		}
	}
	return true
}

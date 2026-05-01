//go:build example

package seedkit

import (
	"errors"
	"strings"

	"rsc.io/qr"
)

// ErrEmptyURI is returned by [QRTerm] when the supplied otpauth URI
// is empty after trimming whitespace. The QR encoder accepts an empty
// string but the result is meaningless for an authenticator-app
// scan, so the helper rejects the call up front.
var ErrEmptyURI = errors.New("seedkit: otpauth URI must not be empty")

// quietZone is the count of light QR modules drawn on every side of
// the encoded payload. Four modules is the minimum the QR
// specification mandates for reliable scanning; reducing it can make
// camera apps fail to lock onto the finder pattern.
const quietZone = 4

// QRTerm renders an otpauth URI as a terminal-friendly QR code using
// the Unicode upper-half-block characters U+2580 ("▀") and U+2584
// ("▄"). Each printed line covers two QR module rows so the aspect
// ratio is closer to square in a typical monospace terminal cell.
//
// The output includes a 4-module quiet zone on every side, as
// required by the QR specification for reliable phone-camera
// recognition. The colour scheme is the dark-terminal-friendly
// inverted polarity:
//
//   - A "dark" QR module is drawn as the terminal default
//     background (a space, " ");
//   - A "light" QR module is drawn as the terminal default
//     foreground (a filled block, "█" / "▀" / "▄").
//
// Phone cameras scan either polarity equally well, so this trade-off
// keeps the rendered code readable on dark-mode terminals without
// inverting colours through ANSI escape sequences. Light-terminal
// users may still scan it; the QR finder pattern is symmetric
// enough that polarity alone does not break recognition.
//
// The error-correction level is qr.M (medium, ~15% redundancy) — the
// same level rsc.io/qr's `Image` helper uses. This balances payload
// size against scan robustness for the otpauth URIs an authenticator
// app expects.
//
// QRTerm returns [ErrEmptyURI] when otpauthURI is blank, and
// surfaces any error rsc.io/qr produces during encoding (typically
// "text too long to encode as QR" for pathological inputs).
func QRTerm(otpauthURI string) (string, error) {
	if strings.TrimSpace(otpauthURI) == "" {
		return "", ErrEmptyURI
	}
	code, err := qr.Encode(otpauthURI, qr.M)
	if err != nil {
		return "", err
	}

	// Build a (size + 2*quietZone)-wide / -tall matrix of bools where
	// true means "dark module". The quiet zone is light. Iterating
	// over a fully-materialised matrix keeps the row pairing logic
	// below easy to read; the matrices are at most a few KB even for
	// the densest authenticator URI.
	side := code.Size + 2*quietZone
	dark := make([]bool, side*side)
	for y := range code.Size {
		for x := range code.Size {
			if code.Black(x, y) {
				dark[(y+quietZone)*side+(x+quietZone)] = true
			}
		}
	}

	// The half-block scheme pairs row (2k) and row (2k+1) into a
	// single line. If `side` is odd, pad an extra all-light row at
	// the bottom so the last printed line still has a defined
	// (top, bot) pair without indexing past the matrix.
	rows := side
	if rows%2 == 1 {
		rows++
	}

	var b strings.Builder
	b.Grow(rows / 2 * (side + 1))
	for y := 0; y < rows; y += 2 {
		for x := range side {
			topDark := y < side && dark[y*side+x]
			botDark := (y+1) < side && dark[(y+1)*side+x]
			b.WriteString(cellGlyph(topDark, botDark))
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// cellGlyph maps a (top, bot) module pair to the Unicode glyph that
// renders the inverted dark-terminal scheme. Truth table:
//
//	topDark  botDark  -> glyph (visible cells)
//	false    false       "█" (both halves drawn — both modules light)
//	false    true        "▀" (upper half drawn — top light, bot dark)
//	true     false       "▄" (lower half drawn — top dark, bot light)
//	true     true        " " (no halves drawn — both modules dark)
//
// The "drawn" half uses the terminal's default foreground colour,
// which on a dark-themed terminal is bright. The "not drawn" half
// is the default background, which is dark. Hence a dark QR module
// (which a scanner expects) corresponds to "not drawn".
func cellGlyph(topDark, botDark bool) string {
	switch {
	case !topDark && !botDark:
		return "█" // FULL BLOCK
	case !topDark && botDark:
		return "▀" // UPPER HALF BLOCK
	case topDark && !botDark:
		return "▄" // LOWER HALF BLOCK
	default:
		return " "
	}
}

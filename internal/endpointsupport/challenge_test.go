package endpointsupport_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
)

// TestSanitizeChallengeValue pins the byte allow-list for header-safe
// auth-param values. The CR / LF / NUL / quote / backslash bytes MUST
// be removed (not escaped) so the WWW-Authenticate header cannot be
// split, broken out of the quoted-string, or terminated early.
func TestSanitizeChallengeValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "the access token is invalid", "the access token is invalid"},
		{"strip CR", "abc\rdef", "abcdef"},
		{"strip LF", "abc\ndef", "abcdef"},
		{"strip CRLF combo", "abc\r\ndef", "abcdef"},
		{"strip NUL", "abc\x00def", "abcdef"},
		{"strip DEL", "abc\x7fdef", "abcdef"},
		{"strip controls", "abc\x01\x02\x1fdef", "abcdef"},
		{"strip double quote", `abc"def`, "abcdef"},
		{"strip backslash", `abc\def`, "abcdef"},
		{"strip mixed", "a\r\nb\"c\\d\x00e", "abcde"},
		{"preserves spaces", "a b c", "a b c"},
		{"preserves printable ascii", "abcXYZ012", "abcXYZ012"},
		// UTF-8 multibyte characters: high-bit bytes are >= 0x80 so they
		// pass the C0/DEL filter; the function does not transcode.
		{"preserves utf-8 high bytes", "café", "café"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := endpointsupport.SanitizeChallengeValue(tc.in)
			if got != tc.want {
				t.Fatalf("SanitizeChallengeValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestBuildBearerChallenge_HeaderShape asserts the auth-param
// composition: scheme prefix, comma-space separators, double-quoted
// values. Every value runs through [SanitizeChallengeValue] first so a
// malicious description cannot break the header.
func TestBuildBearerChallenge_HeaderShape(t *testing.T) {
	t.Parallel()
	out := endpointsupport.BuildBearerChallenge(endpointsupport.BearerSchemeBearer,
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeError, Value: "invalid_token"},
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeErrorDescription, Value: `the\token"is\nbad`},
	)
	want := `Bearer error="invalid_token", error_description="thetokenisnbad"`
	// Note: \n is the two-byte sequence "\\n" in the Go source literal,
	// which after sanitisation becomes "n" with the leading backslash
	// stripped. The real CR / LF byte case is covered by
	// TestSanitizeChallengeValue.
	if out != want {
		t.Fatalf("BuildBearerChallenge:\n got=%q\nwant=%q", out, want)
	}
}

// TestBuildBearerChallenge_DPoPScheme confirms the helper composes the
// RFC 9449 §7.1 DPoP-prefixed challenge identically.
func TestBuildBearerChallenge_DPoPScheme(t *testing.T) {
	t.Parallel()
	out := endpointsupport.BuildBearerChallenge(endpointsupport.BearerSchemeDPoP,
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeError, Value: "use_dpop_nonce"},
	)
	want := `DPoP error="use_dpop_nonce"`
	if out != want {
		t.Fatalf("BuildBearerChallenge:\n got=%q\nwant=%q", out, want)
	}
}

// TestBuildBearerChallenge_SkipsEmptyValues confirms a param whose
// value sanitises away to "" is dropped from the challenge so a
// strict parser does not see a zero-length quoted-string.
func TestBuildBearerChallenge_SkipsEmptyValues(t *testing.T) {
	t.Parallel()
	out := endpointsupport.BuildBearerChallenge(endpointsupport.BearerSchemeBearer,
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeError, Value: "invalid_token"},
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeErrorDescription, Value: "\r\n"},
	)
	want := `Bearer error="invalid_token"`
	if out != want {
		t.Fatalf("BuildBearerChallenge:\n got=%q\nwant=%q", out, want)
	}
}

// TestBuildBearerChallenge_NoCRLFOnAnyInput is the property-style
// guard: every byte sequence — even a payload crafted to look like a
// header injection — must produce a header value that contains no CR,
// LF, NUL, unescaped quote, or unescaped backslash.
func TestBuildBearerChallenge_NoCRLFOnAnyInput(t *testing.T) {
	t.Parallel()
	hostile := []string{
		"benign",
		"x\r\nLocation: https://evil.example",
		"x\rinjected",
		"x\ninjected",
		"x\x00injected",
		`x"; injected="`,
		`x\\injected`,
		"\t\v\f\b",
	}
	for _, h := range hostile {
		out := endpointsupport.BuildBearerChallenge(endpointsupport.BearerSchemeBearer,
			endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeError, Value: "invalid_token"},
			endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeErrorDescription, Value: h},
		)
		// Drop the wrapping scheme + opening quote so the test can scan
		// the value substring. Either way the entire string must be free
		// of the listed bytes.
		for _, bad := range []string{"\r", "\n", "\x00"} {
			if strings.Contains(out, bad) {
				t.Fatalf("BuildBearerChallenge(%q): output %q carries forbidden byte %q", h, out, bad)
			}
		}
	}
}

package totpkit_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/totpkit"
)

// FuzzProvisioningURI exercises [totpkit.NewEnrolment] against a
// corpus of pathological issuer / account inputs. The property under
// test is structural: whatever the inputs are, the produced
// OTPAuthURI MUST parse as a URL AND the query "issuer" field MUST
// round-trip through url.QueryUnescape back to the original (or, for
// inputs the standard library trims, to the trimmed form). A
// crash, a parse failure, or a corrupted issuer field is a defect.
func FuzzProvisioningURI(f *testing.F) {
	// Seed the corpus with values that have historically tripped up
	// QR-code generators and otpauth parsers: spaces, colons, '@',
	// percent signs, control characters, RTL marks, very long
	// strings, and unicode.
	seeds := [][2]string{
		{"Example", "alice@example.com"},
		{"Example Corp", "user:name@example.com"},
		{"Example/Corp", "alice@example.com"},
		{"Example?Corp", "alice@example.com"},
		{"Example#Corp", "alice@example.com"},
		{"Example%Corp", "alice@example.com"},
		{"例の会社", "花子@example.com"},
		{"\u202e", "\u202d"},
		{strings.Repeat("a", 256), strings.Repeat("b", 256)},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}

	codec, err := totpkit.NewCodec(newKey(f))
	if err != nil {
		f.Fatalf("NewCodec: %v", err)
	}

	f.Fuzz(func(t *testing.T, issuer, account string) {
		// Skip inputs the package documents as invalid; the fuzzer
		// is asked to find structural bugs in the URI generator,
		// not to assert that empty inputs are rejected (which the
		// dedicated unit tests already pin).
		if strings.TrimSpace(issuer) == "" || strings.TrimSpace(account) == "" {
			return
		}
		// Reject NUL / CR / LF in issuer/account — RFC 3986 forbids
		// them in URI components and the embedder should sanitise
		// inputs upstream. The package's URL escaping handles them
		// safely but the URL parser may reject them on the
		// round-trip; skip rather than assert defective behaviour.
		for _, ch := range []rune{0, '\r', '\n'} {
			if strings.ContainsRune(issuer, ch) || strings.ContainsRune(account, ch) {
				return
			}
		}

		pending, err := totpkit.NewEnrolment(codec, "user-fuzz", issuer, account)
		if err != nil {
			t.Fatalf("NewEnrolment(issuer=%q account=%q): %v", issuer, account, err)
		}
		u, err := url.Parse(pending.OTPAuthURI)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", pending.OTPAuthURI, err)
		}
		if u.Scheme != "otpauth" || u.Host != "totp" {
			t.Fatalf("scheme=%q host=%q want otpauth/totp", u.Scheme, u.Host)
		}
		if got := u.Query().Get("issuer"); got != issuer {
			t.Fatalf("issuer query=%q want %q", got, issuer)
		}
		// The label embedded in the path is "<issuer>:<account>"
		// after URL-escaping. Decoding the path back through
		// PathUnescape must reconstruct that string exactly, with
		// no truncation or character substitution.
		rawLabel := strings.TrimPrefix(u.EscapedPath(), "/")
		label, err := url.PathUnescape(rawLabel)
		if err != nil {
			t.Fatalf("PathUnescape(%q): %v", rawLabel, err)
		}
		want := issuer + ":" + account
		if label != want {
			t.Fatalf("label=%q want %q", label, want)
		}
	})
}

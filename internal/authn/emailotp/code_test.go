package emailotp_test

import (
	"strings"
	"testing"
	"unicode"

	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
)

func TestGenerateCodeShape(t *testing.T) {
	t.Parallel()
	for range 200 {
		c, err := emailotp.GenerateCode()
		if err != nil {
			t.Fatalf("GenerateCode: %v", err)
		}
		if len(c) != emailotp.CodeDigits {
			t.Fatalf("GenerateCode = %q (len %d); want length %d", c, len(c), emailotp.CodeDigits)
		}
		for _, r := range c {
			if !unicode.IsDigit(r) {
				t.Fatalf("GenerateCode = %q; non-digit %q", c, r)
			}
		}
	}
}

func TestGenerateSaltShape(t *testing.T) {
	t.Parallel()
	a, err := emailotp.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	b, err := emailotp.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(a) != emailotp.SaltLength || len(b) != emailotp.SaltLength {
		t.Fatalf("GenerateSalt lengths = %d, %d; want %d", len(a), len(b), emailotp.SaltLength)
	}
	if string(a) == string(b) {
		t.Fatalf("two GenerateSalt draws collided: %x", a)
	}
}

func TestHashCodeStableAndBoundsToInputs(t *testing.T) {
	t.Parallel()

	salt := []byte("0123456789abcdef")
	h1 := emailotp.HashCode(salt, "user-1", "123456")
	h2 := emailotp.HashCode(salt, "user-1", "123456")
	if string(h1) != string(h2) {
		t.Fatalf("HashCode not deterministic: %x vs %x", h1, h2)
	}
	if string(h1) == string(emailotp.HashCode(salt, "user-1", "654321")) {
		t.Fatalf("HashCode collides on different code")
	}
	if string(h1) == string(emailotp.HashCode(salt, "user-2", "123456")) {
		t.Fatalf("HashCode collides on different subject")
	}
	if string(h1) == string(emailotp.HashCode([]byte("fedcba9876543210"), "user-1", "123456")) {
		t.Fatalf("HashCode collides on different salt")
	}
}

func TestConstantTimeEqualHashes(t *testing.T) {
	t.Parallel()
	a := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	c := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab")
	if !emailotp.ConstantTimeEqualHashes(a, b) {
		t.Errorf("equal hashes reported unequal")
	}
	if emailotp.ConstantTimeEqualHashes(a, c) {
		t.Errorf("unequal hashes reported equal")
	}
}

func TestConstantTimeEqualEmailsCaseInsensitive(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want bool
	}{
		{"alice@example.com", "alice@example.com", true},
		{"Alice@Example.COM", "alice@example.com", true},
		{"alice@example.com", "bob@example.com", false},
		{"alice@example.com", "alice@example.org", false},
		{"alice@example.com", "", false},
	}
	for _, tc := range cases {
		got := emailotp.ConstantTimeEqualEmails(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("ConstantTimeEqualEmails(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestMaskEmail(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"alice@example.com", "a***@e***"},
		{"a@b.c", "a***@b***"},
		{"élise@example.com", "é***@e***"},
		{"@example.com", "***"},
		{"alice@", "***"},
		{"no-at-sign", "***"},
		{"", "***"},
	}
	for _, tc := range cases {
		got := emailotp.MaskEmail(tc.in)
		if got != tc.want {
			t.Errorf("MaskEmail(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if !strings.Contains(got, "***") {
			t.Errorf("MaskEmail(%q) = %q; missing redaction marker", tc.in, got)
		}
	}
}

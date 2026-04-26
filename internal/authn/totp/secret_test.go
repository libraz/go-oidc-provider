package totp_test

import (
	"bytes"
	"encoding/base32"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn/totp"
)

func TestGenerateSecret_Length(t *testing.T) {
	t.Parallel()

	s, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if len(s) != 20 {
		t.Errorf("len(secret)=%d want 20", len(s))
	}
}

func TestGenerateSecret_Distinct(t *testing.T) {
	t.Parallel()

	a, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret a: %v", err)
	}
	b, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("two GenerateSecret calls produced identical bytes")
	}
}

func TestEncodeBase32_RoundTrip(t *testing.T) {
	t.Parallel()

	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	encoded := totp.EncodeBase32(secret)
	if strings.Contains(encoded, "=") {
		t.Errorf("EncodeBase32 produced padding: %q", encoded)
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		t.Fatalf("base32 decode: %v", err)
	}
	if !bytes.Equal(decoded, secret) {
		t.Errorf("decoded=%x want %x", decoded, secret)
	}
}

func TestProvisioningURI_StandardFormat(t *testing.T) {
	t.Parallel()

	secret := []byte("12345678901234567890")
	uri := totp.ProvisioningURI("ExampleCorp", "alice@example.com", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("uri=%q missing scheme/host", uri)
	}

	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	q := parsed.Query()
	if got, want := q.Get("algorithm"), "SHA1"; got != want {
		t.Errorf("algorithm=%q want %q", got, want)
	}
	if got, want := q.Get("digits"), "6"; got != want {
		t.Errorf("digits=%q want %q", got, want)
	}
	if got, want := q.Get("period"), "30"; got != want {
		t.Errorf("period=%q want %q", got, want)
	}
	if got, want := q.Get("issuer"), "ExampleCorp"; got != want {
		t.Errorf("issuer=%q want %q", got, want)
	}
	if q.Get("secret") != totp.EncodeBase32(secret) {
		t.Errorf("secret param=%q want %q", q.Get("secret"), totp.EncodeBase32(secret))
	}
}

func TestProvisioningURI_EscapesSpecialCharacters(t *testing.T) {
	t.Parallel()

	// Issuer with a space and account with a colon must be percent-
	// encoded into the path so the otpauth label survives parsing.
	uri := totp.ProvisioningURI("Example Corp", "user:name@example.com", []byte("secretsecretsecret12"))

	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	// The path includes the leading "/" and the escaped label.
	wantLabel := url.PathEscape("Example Corp:user:name@example.com")
	gotLabel := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if gotLabel != wantLabel {
		t.Errorf("label=%q want %q", gotLabel, wantLabel)
	}
	// The decoded query should still report the raw issuer name.
	if got, want := parsed.Query().Get("issuer"), "Example Corp"; got != want {
		t.Errorf("issuer=%q want %q", got, want)
	}
}

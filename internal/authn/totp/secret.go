package totp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
)

// secretLen is the byte length of a freshly minted TOTP shared secret.
// RFC 6238 §5.1 recommends "at least the same size as the HMAC output";
// SHA-1 produces 160 bits, hence 20 bytes. Authenticator apps render
// 20-byte secrets as 32 base32 characters which fits comfortably in a
// QR code at error-correction level M.
const secretLen = 20

// GenerateSecret returns a fresh 160-bit shared secret read from
// [crypto/rand]. The caller is expected to seal the bytes through
// [Codec.Seal] before persisting and to discard the plaintext as soon as
// the otpauth URI / QR code has been displayed.
//
// The returned slice is a fresh allocation; callers may zero it after use.
func GenerateSecret() ([]byte, error) {
	b := make([]byte, secretLen)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("totp: read entropy: %w", err)
	}
	return b, nil
}

// EncodeBase32 returns the RFC 4648 base32 encoding of secret without
// padding. Authenticator apps consume this form in the otpauth URI
// "secret" parameter; padding ("=" characters) is omitted because the
// otpauth de-facto convention drops it and several popular apps reject
// padded values outright.
func EncodeBase32(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// ProvisioningURI returns the otpauth URI an authenticator app consumes
// when it scans the enrolment QR code. The format is the de-facto
// standard documented at
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format and
// matches what every major authenticator app (Google Authenticator,
// 1Password, Authy, Microsoft Authenticator) accepts:
//
//	otpauth://totp/{issuer}:{account}?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
//
// Both issuer and account are URL-escaped so values containing spaces,
// colons, or non-ASCII characters round-trip safely. The function does
// not validate the inputs beyond escaping; callers SHOULD pass an issuer
// derived from the OP's configured Issuer URL hostname and an account
// label that uniquely identifies the user (typically email or
// preferred_username).
func ProvisioningURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", EncodeBase32(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

//go:build browserverify

package browserverify

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates HMAC-SHA-1 for authenticator interop.
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"
)

// totpSecretRE matches the "base32 seed : <SECRET>" line the MFA examples
// print in their startup enrolment banner. The secret is unpadded base32
// (RFC 4648 alphabet), exactly as op/totpkit emits it.
var totpSecretRE = regexp.MustCompile(`base32 seed\s*:\s*([A-Z2-7]+)`)

// scrapeTOTPSecret reads the example's captured startup log and returns the
// base32 TOTP secret from its enrolment banner. The banner is printed
// before the OP listener comes up, so by the time readiness passes it is
// already on disk; a short retry covers the rare flush lag.
func scrapeTOTPSecret(t *testing.T, logPath string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(logPath)
		if err == nil {
			if m := totpSecretRE.FindSubmatch(data); m != nil {
				return string(m[1])
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("TOTP secret not found in example log %s:\n%s", logPath, data)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// totpCode computes the 6-digit RFC 6238 code for a base32 secret at time
// t. It mirrors internal/authn/totp (HMAC-SHA-1, 30s step, 6 digits,
// T0 = epoch); that package is internal and cannot be imported here, so
// the few lines of RFC 4226 §5.3 dynamic truncation are reproduced.
func totpCode(secretBase32 string, t time.Time) (string, error) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretBase32)
	if err != nil {
		return "", fmt.Errorf("decode base32 secret: %w", err)
	}
	counter := uint64(t.Unix() / 30)

	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(ctr[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", binCode%1_000_000), nil
}

package emailotp

import "time"

// CodeDigits exposes the package's OTP-length constant for whitebox
// tests in the _test package.
const CodeDigits = codeDigits

// SaltLength exposes the per-record salt length for whitebox tests.
const SaltLength = saltLength

// LockThresholdShort / LockThresholdLong / LockDurationShort /
// LockDurationLong / CounterWindow expose the brute-force counter
// thresholds so tests can reference them without re-declaring the
// numeric values (which would silently desync if the production
// constants were tuned).
const (
	LockThresholdShort = lockThresholdShort
	LockThresholdLong  = lockThresholdLong
	LockDurationShort  = lockDurationShort
	LockDurationLong   = lockDurationLong
	CounterWindow      = counterWindow
)

// ScratchVerify exposes the verify-step Scratch sentinel so adapter
// tests can construct ContinueInput values that route into the
// verify branch.
var ScratchVerify = scratchVerify

// GenerateCode / GenerateSalt / HashCode / ConstantTimeEqualHashes /
// ConstantTimeEqualEmails / MaskEmail expose the package-internal
// helpers so the whitebox tests can exercise them without relaxing
// the production identifier visibility.
func GenerateCode() (string, error) { return generateCode() }
func GenerateSalt() ([]byte, error) { return generateSalt() }
func HashCode(salt []byte, sub, code string) []byte {
	return hashCode(salt, sub, code)
}

func ConstantTimeEqualHashes(a, b []byte) bool { return constantTimeEqualHashes(a, b) }
func ConstantTimeEqualEmails(a, b string) bool { return constantTimeEqualEmails(a, b) }
func MaskEmail(addr string) string             { return maskEmail(addr) }

// FakeClock is a deterministic [timex.Clock] implementation. The
// adapter package shape lives in its own helper so tests can construct
// one without re-declaring the type per file.
type FakeClock struct{ T time.Time }

// Now implements [timex.Clock].
func (c *FakeClock) Now() time.Time { return c.T }

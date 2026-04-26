package recovery

// Test-only re-exports of unexported helpers so the black-box hash tests
// can exercise the encoding directly without polluting the package's
// public API.

var (
	HashCodeForTest   = hashCode
	VerifyCodeForTest = verifyCode
)

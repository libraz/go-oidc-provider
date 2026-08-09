package recovery

import (
	"context"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Test-only re-exports of unexported helpers so the black-box hash tests
// can exercise the encoding directly without polluting the package's
// public API.

var HashCodeForTest = hashCode

// VerifyCodeForTest checks presented against a single stored encoding by
// driving the production [Verifier.Verify] path with a one-slot batch.
// Routing through Verify rather than a private single-hash helper keeps
// the encoding tests on exactly the code the login flow runs, including
// the [verifyPolicy] fence.
func VerifyCodeForTest(presented, encoded string) error {
	_, err := (&Verifier{}).Verify(context.Background(), &store.RecoveryBatch{
		Subject: "verify-code-for-test",
		Codes:   []store.RecoveryCode{{Hash: encoded}},
	}, presented)
	return err
}

// HashBatchForTest mints the stored encodings for a whole batch under one
// shared salt, so tests can build batches of an arbitrary size without
// reimplementing the layout the verifier requires.
func HashBatchForTest(plain []string) ([]string, error) { return hashCodes(plain) }

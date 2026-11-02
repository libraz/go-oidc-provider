package authn

import (
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// A pattern compiles once and is reused across submissions; one that does
// not compile keeps failing closed.
func TestCheckFieldPattern_ReusesCompiledPattern(t *testing.T) {
	t.Parallel()
	good := interaction.FieldSpec{Pattern: `[0-9]{6}-cache-test`}
	bad := interaction.FieldSpec{Pattern: `([unclosed-cache-test`}
	first := fieldPattern(good.Pattern)
	if first == nil {
		t.Fatal("valid pattern did not compile")
	}
	for range 3 {
		if fieldPattern(good.Pattern) != first {
			t.Fatal("pattern recompiled on a later submission")
		}
		if err := checkFieldPattern(good, "123456-cache-test"); err != nil {
			t.Fatalf("matching value rejected: %v", err)
		}
		if err := checkFieldPattern(good, "x123456-cache-test"); !errors.Is(err, ErrSubmissionRejected) {
			t.Fatalf("non-matching value: err = %v", err)
		}
		if err := checkFieldPattern(bad, "anything"); !errors.Is(err, ErrSubmissionRejected) {
			t.Fatalf("uncompilable pattern: err = %v", err)
		}
	}
}

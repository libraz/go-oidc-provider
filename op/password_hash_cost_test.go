package op_test

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/libraz/go-oidc-provider/op"
)

func TestBcryptHashScheme_RefusesOutOfPolicyCost(t *testing.T) {
	t.Parallel()

	scheme := op.BcryptHashScheme()
	start := time.Now()
	ok, err := scheme.Verify(context.Background(), []byte("$2b$31$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"), "pw")
	if err != nil || ok {
		t.Fatalf("Verify = %v, %v; want false, nil", ok, err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("out-of-policy cost ran bcrypt (%s)", time.Since(start))
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := scheme.Verify(context.Background(), hash, "pw"); err != nil || !ok {
		t.Fatalf("in-policy hash: %v, %v", ok, err)
	}
}

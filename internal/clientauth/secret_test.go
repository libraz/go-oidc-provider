package clientauth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
)

func TestArgon2id_HashRoundTrip(t *testing.T) {
	t.Parallel()

	v := &clientauth.Argon2id{}
	hash, err := v.Hash("secret-1")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash prefix: %q", hash)
	}
	if err := v.Verify("secret-1", hash); err != nil {
		t.Errorf("Verify(correct): %v", err)
	}
	if err := v.Verify("secret-2", hash); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Errorf("Verify(wrong)=%v want ErrCredentialsInvalid", err)
	}
}

func TestArgon2id_VerifyRejectsMalformed(t *testing.T) {
	t.Parallel()

	v := &clientauth.Argon2id{}
	cases := map[string]string{
		"empty":         "",
		"wrong-prefix":  "$bcrypt$v=19$m=65536,t=3,p=1$abc$def",
		"missing-parts": "$argon2id$v=19$m=65536,t=3,p=1$abc",
		"bad-version":   "$argon2id$v=99$m=65536,t=3,p=1$YWFhYQ$YWFhYQ",
		"bad-base64":    "$argon2id$v=19$m=65536,t=3,p=1$@@@$@@@",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := v.Verify("secret", encoded); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
				t.Errorf("err=%v want ErrCredentialsInvalid", err)
			}
		})
	}
}

func TestArgon2id_CustomParamsRoundTrip(t *testing.T) {
	t.Parallel()

	// Use the smallest parameter set still at or above the OWASP floor
	// the verifier enforces; anything weaker is rejected by Verify.
	v := &clientauth.Argon2id{Params: clientauth.Argon2idParams{
		Memory:      clientauth.Argon2idMinMemory,
		Iterations:  clientauth.Argon2idMinIterations,
		Parallelism: 1,
		SaltLength:  8,
		KeyLength:   16,
	}}
	hash, err := v.Hash("hello")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := v.Verify("hello", hash); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// TestArgon2id_VerifyRejectsWeakParams pins the OWASP 2024 floor: a
// stored hash whose Argon2id m= parameter falls below
// [Argon2idMinMemory] or whose t= parameter falls below
// [Argon2idMinIterations] MUST be rejected as if the secret did not
// match. The defence catches database leaks made worse by a legacy
// hashing configuration the verifier no longer trusts.
func TestArgon2id_VerifyRejectsWeakParams(t *testing.T) {
	t.Parallel()

	// Hash with deliberately weak parameters; the encoded string is
	// well-formed, so only the floor check should reject Verify.
	weakMemory := &clientauth.Argon2id{Params: clientauth.Argon2idParams{
		Memory:      clientauth.Argon2idMinMemory - 1024,
		Iterations:  clientauth.Argon2idMinIterations,
		Parallelism: 1,
		SaltLength:  8,
		KeyLength:   16,
	}}
	weakHash, err := weakMemory.Hash("hello")
	if err != nil {
		t.Fatalf("Hash (weak memory): %v", err)
	}
	verifier := &clientauth.Argon2id{}
	if err := verifier.Verify("hello", weakHash); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Errorf("weak memory Verify=%v want ErrCredentialsInvalid", err)
	}

	weakIter := &clientauth.Argon2id{Params: clientauth.Argon2idParams{
		Memory:      clientauth.Argon2idMinMemory,
		Iterations:  clientauth.Argon2idMinIterations - 1,
		Parallelism: 1,
		SaltLength:  8,
		KeyLength:   16,
	}}
	if weakIter.Params.Iterations == 0 {
		// guard: cannot construct a sub-floor iteration count when the
		// floor is already 1; skip the iter half of the test in that case.
		return
	}
	weakIterHash, err := weakIter.Hash("hello")
	if err != nil {
		t.Fatalf("Hash (weak iter): %v", err)
	}
	if err := verifier.Verify("hello", weakIterHash); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Errorf("weak iterations Verify=%v want ErrCredentialsInvalid", err)
	}
}

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

// TestArgon2id_HashRejectsWeakParams pins the OWASP 2024 floor on the
// write path: the reference hasher must not emit a PHC string its verifier
// would later reject as too weak.
func TestArgon2id_HashRejectsWeakParams(t *testing.T) {
	t.Parallel()

	weakMemory := &clientauth.Argon2id{Params: clientauth.Argon2idParams{
		Memory:      clientauth.Argon2idMinMemory - 1024,
		Iterations:  clientauth.Argon2idMinIterations,
		Parallelism: 1,
		SaltLength:  8,
		KeyLength:   16,
	}}
	if _, err := weakMemory.Hash("hello"); !errors.Is(err, clientauth.ErrInsecureParams) {
		t.Fatalf("weak memory Hash err=%v want ErrInsecureParams", err)
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
	if _, err := weakIter.Hash("hello"); !errors.Is(err, clientauth.ErrInsecureParams) {
		t.Fatalf("weak iterations Hash err=%v want ErrInsecureParams", err)
	}
}

// TestArgon2id_VerifyRejectsDuplicateParameter pins the parser
// invariant the audit-2026-05-07 review (S-03) flagged: a stored
// PHC that re-declares m / t / p MUST be refused outright. Pre-audit
// the parsers (one per credential surface) all walked the
// "m=64,m=128,..." segment with last-value-wins semantics; the
// shared internal/argon2id parser now rejects the duplicate so an
// audit log cannot disagree with the actual derivation.
func TestArgon2id_VerifyRejectsDuplicateParameter(t *testing.T) {
	t.Parallel()

	v := &clientauth.Argon2id{}
	good, err := v.Hash("dup-test")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	bogus := strings.Replace(good, "m=65536", "m=65536,m=131072", 1)
	if err := v.Verify("dup-test", bogus); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Fatalf("Verify(duplicate-m) err=%v want ErrCredentialsInvalid", err)
	}
}

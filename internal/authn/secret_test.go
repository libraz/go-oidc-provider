package authn_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
)

func TestArgon2id_HashRoundTrip(t *testing.T) {
	t.Parallel()

	v := &authn.Argon2id{}
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
	if err := v.Verify("secret-2", hash); !errors.Is(err, authn.ErrCredentialsInvalid) {
		t.Errorf("Verify(wrong)=%v want ErrCredentialsInvalid", err)
	}
}

func TestArgon2id_VerifyRejectsMalformed(t *testing.T) {
	t.Parallel()

	v := &authn.Argon2id{}
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
			if err := v.Verify("secret", encoded); !errors.Is(err, authn.ErrCredentialsInvalid) {
				t.Errorf("err=%v want ErrCredentialsInvalid", err)
			}
		})
	}
}

func TestArgon2id_CustomParamsRoundTrip(t *testing.T) {
	t.Parallel()

	// Use a small parameter set so the test is fast but still hits every
	// branch of resolved/parameter handling.
	v := &authn.Argon2id{Params: authn.Argon2idParams{
		Memory:      16 * 1024,
		Iterations:  1,
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

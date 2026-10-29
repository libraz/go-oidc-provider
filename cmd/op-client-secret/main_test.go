package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
)

// field returns the value printed after label on its own line.
func field(t *testing.T, out, label string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, label+": "); ok {
			return v
		}
	}
	t.Fatalf("no %q line in output %q", label, out)
	return ""
}

func TestOpClientSecret_New(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run(nil, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	secret := field(t, stdout.String(), "secret")
	hash := field(t, stdout.String(), "hash")
	if err := (clientauth.HighEntropy{}).Verify(secret, hash); err != nil {
		t.Errorf("printed hash does not verify the printed secret: %v", err)
	}
	if err := (clientauth.HighEntropy{}).Verify(secret+"x", hash); err == nil {
		t.Error("hash verified a different secret")
	}
}

func TestOpClientSecret_Argon2id(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"-argon2id"}, strings.NewReader("s3cret-value\n"), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	hash := field(t, stdout.String(), "hash")
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash %q is not an argon2id encoding", hash)
	}
	if !op.VerifyPassword([]byte(hash), "s3cret-value") {
		t.Error("hash does not verify the plaintext read from stdin")
	}
}

func TestOpClientSecret_EmptyStdinRejected(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "\n", "\r\n"} {
		var stdout, stderr bytes.Buffer
		if err := run([]string{"-argon2id"}, strings.NewReader(in), &stdout, &stderr); err == nil {
			t.Errorf("stdin %q: expected an error", in)
		}
		if stdout.Len() != 0 {
			t.Errorf("stdin %q: nothing may be printed, got %q", in, stdout.String())
		}
	}
}

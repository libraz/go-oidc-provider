package op_test

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/libraz/go-oidc-provider/op"
)

func bcryptFixture(t *testing.T, pw string) []byte {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	return h
}

func TestBcryptHashScheme_Recognizes(t *testing.T) {
	t.Parallel()
	s := op.BcryptHashScheme()
	tail := "$04$abcdefghijklmnopqrstuuOpaqueOpaqueOpaqueOpaqueOpaque."
	for _, tc := range []struct {
		name string
		enc  string
		want bool
	}{
		{"2a", "$2a" + tail, true},
		{"2b", "$2b" + tail, true},
		{"2y", "$2y" + tail, true},
		{"2x", "$2x" + tail, false},
		{"argon2id", "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$a2V5", false},
		{"empty", "", false},
		{"plain", "hunter2", false},
	} {
		if got := s.Recognizes([]byte(tc.enc)); got != tc.want {
			t.Errorf("%s: Recognizes = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestBcryptHashScheme_Verify(t *testing.T) {
	t.Parallel()
	s := op.BcryptHashScheme()
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		stored string
		try    string
		want   bool
	}{
		{"match", "correct horse", "correct horse", true},
		{"mismatch", "correct horse", "wrong horse", false},
		{"zero bytes match", "", "", true},
		{"zero bytes mismatch", "secret", "", false},
		{"non-ASCII match", "パスワード-é", "パスワード-é", true},
		{"non-ASCII mismatch", "パスワード-é", "パスワード-e", false},
		{"exactly 72 bytes", strings.Repeat("a", 72), strings.Repeat("a", 72), true},
	} {
		got, err := s.Verify(ctx, bcryptFixture(t, tc.stored), tc.try)
		if err != nil {
			t.Fatalf("%s: Verify error: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: Verify = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestBcryptHashScheme_Verify_Over72BytesIsMismatch(t *testing.T) {
	t.Parallel()
	s := op.BcryptHashScheme()
	// The stored hash is of the 72-byte prefix; a longer candidate that
	// shares that prefix must not match.
	prefix := strings.Repeat("a", 72)
	got, err := s.Verify(context.Background(), bcryptFixture(t, prefix), prefix+"b")
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if got {
		t.Fatal("password over 72 bytes matched a truncated hash")
	}
}

func TestBcryptHashScheme_Verify_MalformedHashIsMismatch(t *testing.T) {
	t.Parallel()
	got, err := op.BcryptHashScheme().Verify(context.Background(), []byte("$2a$garbage"), "pw")
	if err != nil || got {
		t.Fatalf("Verify = (%v, %v), want (false, nil)", got, err)
	}
}

//go:build example

package main

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestMembersEmailPinsBinaryCollation is the schema half of the identity
// rule. MySQL 8.4 defaults utf8mb4 to utf8mb4_0900_ai_ci, which folds
// accents as well as case: under it "cafe@example.com" and
// "café@example.com" are one row, so the unique key refuses the second
// signup and a lookup by either address resolves whichever row exists.
// The column states its own collation so the comparison is by bytes.
//
// This asserts the DDL the application ships. What MySQL then does with
// it is measured against a live engine on the library's own schema; this
// module has no database and does not add one.
func TestMembersEmailPinsBinaryCollation(t *testing.T) {
	t.Parallel()

	const want = "COLLATE utf8mb4_bin"
	emailColumn := ""
	for _, line := range strings.Split(membersDDL, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "email ") {
			emailColumn = line
		}
	}
	if emailColumn == "" {
		t.Fatalf("the members DDL declares no email column:\n%s", membersDDL)
	}
	if !strings.Contains(emailColumn, want) {
		t.Errorf("email column %q does not carry %q, so the schema's default collation "+
			"decides which addresses are the same person", strings.TrimSpace(emailColumn), want)
	}
}

// TestNormaliseEmailFoldsCaseButNotAccents pins the Go half of the same
// rule: case and surrounding space are one address, and anything else —
// an accent above all — is a different one. Under the binary collation
// above, two values this function leaves distinct are two rows.
func TestNormaliseEmailFoldsCaseButNotAccents(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"case is folded", "Member@Example.COM", "member@example.com"},
		{"surrounding space is trimmed", "  member@example.com\t", "member@example.com"},
		{"an accented address keeps its accent", " CAFÉ@example.com ", "café@example.com"},
	} {
		if got := normaliseEmail(tc.raw); got != tc.want {
			t.Errorf("%s: normaliseEmail(%q) = %q, want %q", tc.name, tc.raw, got, tc.want)
		}
	}

	// The two normalise to different byte strings, which is what the
	// binary collation preserves: signing up for the second address must
	// not collide with the first, and signing in with it must not
	// resolve the first member's row.
	if accented, plain := normaliseEmail("café@example.com"), normaliseEmail("cafe@example.com"); accented == plain {
		t.Errorf("normaliseEmail folds %q onto %q", accented, plain)
	}
}

// TestVerifyPasswordAgainstAStoredEncoding pins the pair the account
// pages rest on: signUp and changePassword write op.HashPassword's
// encoding into password_phc, and verifyPassword reads that column back
// through op.VerifyPassword before either page replaces a credential.
// The fake member store the page tests run against holds plaintext, so
// this is where the two halves meet a hash the library produced.
func TestVerifyPasswordAgainstAStoredEncoding(t *testing.T) {
	t.Parallel()

	stored, err := op.HashPassword("correct-horse")
	if err != nil {
		t.Fatalf("op.HashPassword: %v", err)
	}
	if !op.VerifyPassword(stored, "correct-horse") {
		t.Error("the stored member's own password does not verify")
	}
	for _, tc := range []struct {
		name     string
		password string
		stored   []byte
	}{
		{"wrong password", "correct-hors", stored},
		{"column never written", "correct-horse", nil},
		{"column truncated by a narrower type", "correct-horse", stored[:len(stored)-4]},
	} {
		if op.VerifyPassword(tc.stored, tc.password) {
			t.Errorf("%s: verified", tc.name)
		}
	}
}

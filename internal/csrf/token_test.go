package csrf_test

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/csrf"
)

// newKey returns a fresh 32-byte HMAC key for tests.
func newKey(tb testing.TB) []byte {
	tb.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		tb.Fatalf("rand: %v", err)
	}
	return k
}

func TestNewSigner_RejectsBadKey(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		"empty":     nil,
		"too_short": make([]byte, 16),
		"too_long":  make([]byte, 64),
	}
	for name, k := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := csrf.NewSigner(k); !errors.Is(err, csrf.ErrInvalidKey) {
				t.Errorf("err=%v want ErrInvalidKey", err)
			}
		})
	}
}

func TestSigner_RoundTrip(t *testing.T) {
	t.Parallel()

	s, err := csrf.NewSigner(newKey(t))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	tok, err := s.Issue("session-A", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Verify(tok, "session-A", now.Add(5*time.Minute), time.Hour); err != nil {
		t.Errorf("Verify within window: %v", err)
	}
}

func TestSigner_Verify_RejectsWrongSession(t *testing.T) {
	t.Parallel()

	s, err := csrf.NewSigner(newKey(t))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	now := time.Now()
	tok, _ := s.Issue("session-A", now)
	if err := s.Verify(tok, "session-B", now, time.Hour); !errors.Is(err, csrf.ErrTokenInvalid) {
		t.Errorf("err=%v want ErrTokenInvalid (session mismatch)", err)
	}
}

func TestSigner_Verify_RejectsExpired(t *testing.T) {
	t.Parallel()

	s, err := csrf.NewSigner(newKey(t))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	issued := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	tok, _ := s.Issue("session", issued)

	later := issued.Add(2 * time.Hour)
	if err := s.Verify(tok, "session", later, time.Hour); !errors.Is(err, csrf.ErrTokenInvalid) {
		t.Errorf("err=%v want ErrTokenInvalid (expired)", err)
	}
}

func TestSigner_Verify_AcceptsZeroMaxAge(t *testing.T) {
	t.Parallel()

	s, err := csrf.NewSigner(newKey(t))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tok, _ := s.Issue("session", issued)
	// Five years later — must still verify when maxAge is disabled.
	later := issued.Add(5 * 365 * 24 * time.Hour)
	if err := s.Verify(tok, "session", later, 0); err != nil {
		t.Errorf("Verify with maxAge=0 rejected: %v", err)
	}
}

func TestSigner_Verify_RejectsTamperedToken(t *testing.T) {
	t.Parallel()

	s, err := csrf.NewSigner(newKey(t))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, _ := s.Issue("session", time.Now())
	parts := strings.SplitN(tok, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("issued token shape unexpected: %q", tok)
	}
	// Mutate the timestamp segment — HMAC must fail.
	tampered := parts[0] + ".9999999999." + parts[2]
	if err := s.Verify(tampered, "session", time.Now(), time.Hour); !errors.Is(err, csrf.ErrTokenInvalid) {
		t.Errorf("err=%v want ErrTokenInvalid", err)
	}
}

func TestSigner_Verify_RejectsMalformedToken(t *testing.T) {
	t.Parallel()

	s, err := csrf.NewSigner(newKey(t))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	cases := map[string]string{
		"empty":     "",
		"two_parts": "a.b",
		"bad_b64":   "!!!.123.???",
		"bad_iat":   "AA.notanumber.AA",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := s.Verify(tok, "s", time.Now(), time.Hour); !errors.Is(err, csrf.ErrTokenInvalid) {
				t.Errorf("err=%v want ErrTokenInvalid", err)
			}
		})
	}
}

func TestSigner_DistinctTokensPerIssue(t *testing.T) {
	t.Parallel()

	s, err := csrf.NewSigner(newKey(t))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	now := time.Now()
	a, _ := s.Issue("session", now)
	b, _ := s.Issue("session", now)
	if a == b {
		t.Error("Issue produced identical tokens for the same input (nonce reuse)")
	}
}

func TestSigner_Verify_RejectsKeyMismatch(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewSigner(newKey(t))
	b, _ := csrf.NewSigner(newKey(t))

	tok, _ := a.Issue("session", time.Now())
	if err := b.Verify(tok, "session", time.Now(), time.Hour); !errors.Is(err, csrf.ErrTokenInvalid) {
		t.Errorf("Verify with different key: err=%v want ErrTokenInvalid", err)
	}
}

func TestSigner_LengthPrefix_PreventsBoundaryShift(t *testing.T) {
	t.Parallel()

	// With length-prefixed framing, distinct splits of the input that
	// share the same concatenated bytes must produce distinct MACs.
	// The token issued for (sessionID="ab", scope="cd") and the
	// verification for (sessionID="abc", scope="d") happen to share the
	// concatenation "abcd" but the length prefixes (2,2) versus (3,1)
	// disagree, so the MAC tag must NOT match.
	s, err := csrf.NewSigner(newKey(t))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	tokAB, err := s.IssueScoped("ab", "cd", now)
	if err != nil {
		t.Fatalf("IssueScoped: %v", err)
	}
	if err := s.VerifyScoped(tokAB, "abc", "d", now, time.Hour); !errors.Is(err, csrf.ErrTokenInvalid) {
		t.Errorf("err=%v want ErrTokenInvalid (boundary collision)", err)
	}

	// Same boundary-shift exercise without scope confusion: pure
	// sessionID variants that would have collided under the old "|"
	// separator if a sessionID ever contained a pipe.
	tokA, err := s.Issue("a|b", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Verify(tokA, "a", now, time.Hour); !errors.Is(err, csrf.ErrTokenInvalid) {
		t.Errorf("err=%v want ErrTokenInvalid (sessionID boundary)", err)
	}
}

func TestSigner_IssueScoped_BindsScope(t *testing.T) {
	t.Parallel()

	s, err := csrf.NewSigner(newKey(t))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	tok, err := s.IssueScoped("session", "form-A", now)
	if err != nil {
		t.Fatalf("IssueScoped: %v", err)
	}
	if err := s.VerifyScoped(tok, "session", "form-A", now, time.Hour); err != nil {
		t.Errorf("VerifyScoped same scope: %v", err)
	}
	if err := s.VerifyScoped(tok, "session", "form-B", now, time.Hour); !errors.Is(err, csrf.ErrTokenInvalid) {
		t.Errorf("err=%v want ErrTokenInvalid (different scope)", err)
	}
	// And the un-scoped Verify must also reject.
	if err := s.Verify(tok, "session", now, time.Hour); !errors.Is(err, csrf.ErrTokenInvalid) {
		t.Errorf("err=%v want ErrTokenInvalid (un-scoped Verify on scoped token)", err)
	}
}

func TestSigner_Issue_BackwardCompatibleWithVerifyScopedEmpty(t *testing.T) {
	t.Parallel()

	s, err := csrf.NewSigner(newKey(t))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	tok, err := s.Issue("session", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// VerifyScoped("") must accept tokens minted by Issue.
	if err := s.VerifyScoped(tok, "session", "", now, time.Hour); err != nil {
		t.Errorf("VerifyScoped empty scope rejected Issue token: %v", err)
	}
}

func TestConstantTimeEqual(t *testing.T) {
	t.Parallel()

	if !csrf.ConstantTimeEqual("abc", "abc") {
		t.Error("equal strings reported not equal")
	}
	if csrf.ConstantTimeEqual("abc", "abd") {
		t.Error("different strings reported equal")
	}
	if csrf.ConstantTimeEqual("abc", "abcd") {
		t.Error("length mismatch reported equal")
	}
}

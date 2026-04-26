package pkce_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/pkce"
)

// challengeFor returns the canonical S256 challenge for verifier. It mirrors
// the transformation a well-behaved RP would perform, so tests can build
// matching pairs without re-implementing the math at every call site.
func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestVerify_RoundTrip(t *testing.T) {
	t.Parallel()

	// A verifier exactly at the minimum length (43) — exercises the
	// boundary that pkce.VerifierMinLength is enforcing.
	verifier := strings.Repeat("a", 43)
	challenge := challengeFor(verifier)

	if err := pkce.Verify(challenge, pkce.Method, verifier); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerify_RejectsMismatch(t *testing.T) {
	t.Parallel()

	verifier := strings.Repeat("a", 43)
	challenge := challengeFor(strings.Repeat("b", 43))
	err := pkce.Verify(challenge, pkce.Method, verifier)
	if !errors.Is(err, pkce.ErrVerifierMismatch) {
		t.Errorf("err=%v want ErrVerifierMismatch", err)
	}
}

func TestVerify_RejectsPlainMethod(t *testing.T) {
	t.Parallel()

	verifier := strings.Repeat("a", 43)
	err := pkce.Verify(verifier, "plain", verifier)
	if !errors.Is(err, pkce.ErrChallengeMethodUnsupported) {
		t.Errorf("err=%v want ErrChallengeMethodUnsupported", err)
	}
}

func TestVerify_RejectsBadVerifier(t *testing.T) {
	t.Parallel()

	verifier := strings.Repeat("a", 43)
	challenge := challengeFor(verifier)

	cases := map[string]string{
		"too_short":      strings.Repeat("a", 42),
		"too_long":       strings.Repeat("a", 129),
		"reserved_char":  strings.Repeat("a", 42) + "!",
		"space":          strings.Repeat("a", 42) + " ",
		"non_ascii":      strings.Repeat("a", 42) + "é",
		"plus_not_unres": strings.Repeat("a", 42) + "+",
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := pkce.Verify(challenge, pkce.Method, bad)
			if !errors.Is(err, pkce.ErrVerifierFormat) {
				t.Errorf("err=%v want ErrVerifierFormat", err)
			}
		})
	}
}

func TestValidateChallenge_AcceptsCanonical(t *testing.T) {
	t.Parallel()

	verifier := strings.Repeat("a", 64)
	challenge := challengeFor(verifier)
	if err := pkce.ValidateChallenge(challenge, pkce.Method); err != nil {
		t.Errorf("ValidateChallenge: %v", err)
	}
}

func TestValidateChallenge_RequiresFields(t *testing.T) {
	t.Parallel()

	good := challengeFor(strings.Repeat("a", 64))

	if err := pkce.ValidateChallenge("", pkce.Method); !errors.Is(err, pkce.ErrChallengeRequired) {
		t.Errorf("missing challenge: err=%v want ErrChallengeRequired", err)
	}
	if err := pkce.ValidateChallenge(good, ""); !errors.Is(err, pkce.ErrChallengeRequired) {
		t.Errorf("missing method: err=%v want ErrChallengeRequired", err)
	}
}

func TestValidateChallenge_RejectsPlain(t *testing.T) {
	t.Parallel()

	good := challengeFor(strings.Repeat("a", 64))
	err := pkce.ValidateChallenge(good, "plain")
	if !errors.Is(err, pkce.ErrChallengeMethodUnsupported) {
		t.Errorf("err=%v want ErrChallengeMethodUnsupported", err)
	}
}

func TestValidateChallenge_RejectsMalformed(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"too_short":  strings.Repeat("a", 42),
		"too_long":   strings.Repeat("a", 44),
		"with_pad":   strings.Repeat("a", 42) + "=",
		"non_b64url": strings.Repeat("a", 42) + "+",
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := pkce.ValidateChallenge(bad, pkce.Method)
			if !errors.Is(err, pkce.ErrChallengeFormat) {
				t.Errorf("err=%v want ErrChallengeFormat", err)
			}
		})
	}
}

package dpop_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// constNonceVerifier is a tiny [dpop.NonceVerifier] that accepts any
// nonce in its allow-set. Tests pin both "stale" and "fresh" values to
// exercise the rotation gate around the jti mark in [dpop.Verifier.Verify].
type constNonceVerifier struct {
	allowed map[string]struct{}
}

func newNonceVerifier(values ...string) *constNonceVerifier {
	m := make(map[string]struct{}, len(values))
	for _, v := range values {
		m[v] = struct{}{}
	}
	return &constNonceVerifier{allowed: m}
}

func (c *constNonceVerifier) Validate(nonce string) bool {
	_, ok := c.allowed[nonce]
	return ok
}

// newNonceVerifierProvider wires a fresh in-memory replay store + clock
// + Verifier with the supplied [dpop.NonceVerifier]. The helper mirrors
// [newVerifier] but threads the nonce gate.
func newVerifierWithNonces(t testing.TB, now time.Time, nv dpop.NonceVerifier) *dpop.Verifier {
	t.Helper()
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:   newMemJTIStore(),
		Clock:  fixedClock{now: now},
		Nonces: nv,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// TestVerify_MarksJTIAfterNonceCheck closes the M-FAPI-1 vector: a
// proof that fails the nonce gate MUST NOT consume its jti slot, and
// the same jti MUST be rejected as a replay only after a nonce-passing
// proof actually marks it. Without the property, an attacker who
// observes a proof whose nonce went stale (legitimate retry path) can
// resubmit the same jti with a fresh nonce and have it accepted.
func TestVerify_MarksJTIAfterNonceCheck(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	// Verifier accepts only "fresh"; "stale" must fail.
	v := newVerifierWithNonces(t, now, newNonceVerifier("fresh"))

	staleClaims := goodClaims(now)
	staleClaims["nonce"] = "stale"
	staleProof := signProof(t, key, staleClaims, "")
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: staleProof,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); !errors.Is(err, dpop.ErrProofNonceInvalid) {
		t.Fatalf("stale nonce: err=%v want ErrProofNonceInvalid", err)
	}

	// The legitimate retry mints a fresh proof with the SAME jti but a
	// fresh nonce. It MUST succeed because the failing nonce path did
	// not consume the jti slot.
	freshClaims := goodClaims(now)
	freshClaims["nonce"] = "fresh"
	freshProof := signProof(t, key, freshClaims, "")
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: freshProof,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("fresh nonce after stale: %v", err)
	}

	// A second submission with the same jti — even with a fresh nonce
	// — MUST be rejected because the previous fresh-nonce proof marked
	// the jti.
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: freshProof,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); !errors.Is(err, dpop.ErrProofReplayed) {
		t.Fatalf("replay after fresh: err=%v want ErrProofReplayed", err)
	}
}

// TestVerify_HTMStrictCase pins the RFC 9449 §4.3 byte-equal rule on
// the default verifier: a proof carrying "post" against a "POST"
// request fails ErrProofHTMMismatch.
func TestVerify_HTMStrictCase(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["htm"] = "post"
	raw := signProof(t, key, claims, "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofHTMMismatch) {
		t.Fatalf("err=%v want ErrProofHTMMismatch (default verifier MUST be byte-equal)", err)
	}
}

// TestVerify_HTMLooseCaseOptIn covers the AllowLooseMethodCase opt-in:
// when the embedder sets the flag, the proof's "htm" matches the
// request method under ASCII case folding.
func TestVerify_HTMLooseCaseOptIn(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["htm"] = "post"
	raw := signProof(t, key, claims, "")
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:                 newMemJTIStore(),
		Clock:                fixedClock{now: now},
		AllowLooseMethodCase: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("loose method case: %v", err)
	}
}

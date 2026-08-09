package dpop_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// nonceFn is a tiny [dpop.NonceVerifier] adapter so each test can
// supply its acceptance rule inline. The atomic counter records call
// count so tests can assert the verifier is consulted exactly when
// expected — important because the nonce check sits at a specific
// position in the verify pipeline (after ath, before replay mark).
type nonceFn struct {
	calls atomic.Int64
	allow func(string) bool
}

func (n *nonceFn) Validate(s string) bool {
	n.calls.Add(1)
	return n.allow(s)
}

// newVerifierWithNonce mirrors the package-local newVerifier helper
// but threads a [dpop.NonceVerifier] through. Defined here so the
// nonce-suite tests do not need to fork the larger helper.
func newVerifierWithNonce(t testing.TB, now time.Time, nonces dpop.NonceVerifier) *dpop.Verifier {
	t.Helper()
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:   newMemJTIStore(),
		Clock:  fixedClock{now: now},
		Nonces: nonces,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// TestVerify_NonceAccepted: when the verifier is wired with a
// NonceVerifier and the proof carries an acceptable nonce, the verify
// pipeline runs to completion and consults the nonce check exactly
// once.
func TestVerify_NonceAccepted(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["nonce"] = "current-server-nonce"
	raw := signProof(t, key, claims, "")
	nonces := &nonceFn{allow: func(s string) bool { return s == "current-server-nonce" }}
	v := newVerifierWithNonce(t, now, nonces)
	res, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.JKT == "" {
		t.Errorf("VerifyResult.JKT should be populated on success")
	}
	if got := nonces.calls.Load(); got != 1 {
		t.Errorf("Validate calls = %d, want 1", got)
	}
}

// TestVerify_NonceMissing: when the verifier is wired but the proof
// has no nonce claim, the pipeline returns ErrProofNonceMissing
// without consulting the validator (the verifier short-circuits on
// empty input — Validate("") is the implementer's concern, not the
// verifier's).
func TestVerify_NonceMissing(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "") // no nonce claim
	nonces := &nonceFn{allow: func(string) bool { return true }}
	v := newVerifierWithNonce(t, now, nonces)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofNonceMissing) {
		t.Fatalf("err = %v, want ErrProofNonceMissing", err)
	}
	if got := nonces.calls.Load(); got != 0 {
		t.Errorf("Validate calls = %d, want 0 (verifier should short-circuit on empty)", got)
	}
}

// TestVerify_NonceRejected: when the proof carries a nonce but the
// validator rejects it, the pipeline returns ErrProofNonceInvalid.
// Distinct sentinel from ErrProofNonceMissing so audit logs can tell
// "stale" apart from "absent" even though the wire response is the
// same RFC 9449 §8 challenge.
func TestVerify_NonceRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["nonce"] = "stale-nonce"
	raw := signProof(t, key, claims, "")
	nonces := &nonceFn{allow: func(s string) bool { return s == "current-server-nonce" }}
	v := newVerifierWithNonce(t, now, nonces)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofNonceInvalid) {
		t.Fatalf("err = %v, want ErrProofNonceInvalid", err)
	}
	if got := nonces.calls.Load(); got != 1 {
		t.Errorf("Validate calls = %d, want 1", got)
	}
}

// TestVerify_NoNonceVerifier: when the embedder did not configure a
// NonceVerifier (the default), proofs are accepted regardless of the
// nonce claim — present, absent, or empty all pass through. Confirms
// the nonce gate is opt-in and does not implicitly tighten a
// deployment that never asked for it.
func TestVerify_NoNonceVerifier(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		nonce string
	}{
		{"absent", ""},
		{"present", "anything-the-server-does-not-track"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := newES256Key(t)
			claims := goodClaims(now)
			if tc.nonce != "" {
				claims["nonce"] = tc.nonce
			}
			raw := signProof(t, key, claims, "")
			v := newVerifier(t, now) // no Nonces in VerifierConfig
			if _, err := v.Verify(context.Background(), dpop.VerifyInput{
				ProofHeader: raw,
				Method:      "POST",
				URL:         mustParseURL(t, "https://op.example/oidc/token"),
				TLS:         true,
			}); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// TestVerify_NonceCheckedBeforeReplay: a stale-nonce proof must NOT
// burn a jti slot. RFC 9449 §8 expects the client to retry with a
// fresh proof carrying a regenerated jti, but a paranoid replay
// store could reject the retry if the verifier consumed the failed
// jti first. This test pins the ordering: nonce errors leave the
// jti unmarked.
func TestVerify_NonceCheckedBeforeReplay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["jti"] = "should-not-be-consumed"
	claims["nonce"] = "stale"
	raw := signProof(t, key, claims, "")
	nonces := &nonceFn{allow: func(string) bool { return false }}
	v := newVerifierWithNonce(t, now, nonces)
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); !errors.Is(err, dpop.ErrProofNonceInvalid) {
		t.Fatalf("first verify err = %v, want ErrProofNonceInvalid", err)
	}
	// Now retry with the same jti but an acceptable nonce. If the
	// first attempt had marked the jti, this would fail with
	// ErrProofReplayed; the contract pinned by this test is that it
	// instead succeeds.
	claims["nonce"] = "good"
	nonces.allow = func(s string) bool { return s == "good" }
	raw = signProof(t, key, claims, "")
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("retry verify: %v", err)
	}
}

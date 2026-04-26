package dpop_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// The dpop_test package shares helpers with proof_test.go (signKey,
// newVerifier, fixedClock, mustParseURL, etc.). The cases in this file
// focus on the high-level Verify entry point: HTM/HTU mismatch, iat
// window enforcement, replay detection, and the optional ath binding
// (RFC 9449 §4.3).

func TestVerify_HTMMismatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "GET",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofHTMMismatch) {
		t.Fatalf("err=%v want ErrProofHTMMismatch", err)
	}
}

func TestVerify_HTUMismatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/userinfo"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofHTUMismatch) {
		t.Fatalf("err=%v want ErrProofHTUMismatch", err)
	}
}

func TestVerify_IatTooOld(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-2 * time.Minute)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(stale), "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofIatWindow) {
		t.Fatalf("err=%v want ErrProofIatWindow", err)
	}
}

func TestVerify_IatTooFuture(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	future := now.Add(5 * time.Minute)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(future), "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofIatWindow) {
		t.Fatalf("err=%v want ErrProofIatWindow", err)
	}
}

func TestVerify_Replay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "")
	v := newVerifier(t, now)

	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("first Verify: %v", err)
	}

	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofReplayed) {
		t.Fatalf("err=%v want ErrProofReplayed", err)
	}
}

func TestVerify_ATHRequired(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
		AccessToken: "opaque-access-token",
	})
	if !errors.Is(err, dpop.ErrProofATHMismatch) {
		t.Fatalf("err=%v want ErrProofATHMismatch", err)
	}
}

func TestVerify_ATHMismatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["ath"] = base64.RawURLEncoding.EncodeToString(sha256.New().Sum([]byte("wrong")))
	raw := signProof(t, key, claims, "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
		AccessToken: "opaque-access-token",
	})
	if !errors.Is(err, dpop.ErrProofATHMismatch) {
		t.Fatalf("err=%v want ErrProofATHMismatch", err)
	}
}

func TestVerify_ATHHappyPath(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	const accessToken = "opaque-access-token"
	claims := goodClaims(now)
	claims["ath"] = dpop.AccessTokenHash(accessToken)
	raw := signProof(t, key, claims, "")
	v := newVerifier(t, now)
	out, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
		AccessToken: accessToken,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.JKT == "" {
		t.Errorf("JKT must be populated on ath success")
	}
}

func TestNewVerifier_RequiresJTIs(t *testing.T) {
	t.Parallel()
	if _, err := dpop.NewVerifier(dpop.VerifierConfig{}); err == nil {
		t.Fatal("NewVerifier without JTIs must error")
	}
}

func TestAccessTokenHash_Stable(t *testing.T) {
	t.Parallel()
	a := dpop.AccessTokenHash("abc")
	b := dpop.AccessTokenHash("abc")
	if a != b {
		t.Errorf("hash diverged: %q vs %q", a, b)
	}
	if dpop.AccessTokenHash("abc") == dpop.AccessTokenHash("abd") {
		t.Errorf("collision on tiny input")
	}
}

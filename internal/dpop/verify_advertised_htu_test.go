package dpop_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// TestVerify_AdvertisedHTU pins the OP-endpoint comparison: with
// AdvertisedHTU set, the proof must name one of the advertised URLs
// (canonicalised as for the request-derived path), whatever URL the
// request itself reconstructs to. A proxy that rewrote neither scheme nor
// host therefore no longer decides the outcome.
func TestVerify_AdvertisedHTU(t *testing.T) {
	t.Parallel()

	const (
		advertised = "https://op.example.com/oidc/token"
		alias      = "https://mtls.op.example.com/oidc/token"
		internal   = "http://10.0.0.7:8080/oidc/token"
	)
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	cases := []struct {
		name string
		htu  string
		want error
	}{
		{"advertised URL", advertised, nil},
		{"advertised URL with default port", "https://op.example.com:443/oidc/token", nil},
		{"advertised URL with upper-case host", "https://OP.EXAMPLE.COM/oidc/token", nil},
		{"mtls alias", alias, nil},
		{"request-derived internal URL", internal, dpop.ErrProofHTUMismatch},
		{"other endpoint on the advertised host", "https://op.example.com/oidc/par", dpop.ErrProofHTUMismatch},
		{"advertised path on another host", "https://attacker.example/oidc/token", dpop.ErrProofHTUMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := goodClaims(now)
			claims["htu"] = tc.htu
			raw := signProof(t, key, claims, "")
			_, err := newVerifier(t, now).Check(context.Background(), dpop.VerifyInput{
				ProofHeader:   raw,
				Method:        "POST",
				URL:           mustParseURL(t, internal),
				AdvertisedHTU: []string{advertised, alias},
			})
			if !errors.Is(err, tc.want) {
				t.Errorf("htu=%q: err=%v, want %v", tc.htu, err, tc.want)
			}
		})
	}
}

// TestVerify_RequestDerivedHTUWithoutAdvertised confirms the resource-
// server posture is unchanged: with no advertised set, the request URL is
// what the proof must name.
func TestVerify_RequestDerivedHTUWithoutAdvertised(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["htu"] = "https://rs.example.com/api/orders"
	raw := signProof(t, key, claims, "")
	v := newVerifier(t, now)
	if _, err := v.Check(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://rs.example.com/api/orders"),
	}); err != nil {
		t.Errorf("request-derived match refused: %v", err)
	}
	if _, err := v.Check(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://rs.example.com/api/other"),
	}); !errors.Is(err, dpop.ErrProofHTUMismatch) {
		t.Errorf("request-derived mismatch: err=%v, want ErrProofHTUMismatch", err)
	}
}

// TestGate_HTUReachesVerifier pins that [dpop.Gate.HTU] is what the
// HTTP entry point compares against.
func TestGate_HTUReachesVerifier(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	claims["htu"] = "https://op.example.com/oidc/token"
	gate := dpop.Gate{Verifier: newVerifier(t, now), HTU: []string{"https://op.example.com/oidc/token"}}

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://10.0.0.7:8080/oidc/token", nil)
	r.Header.Set("DPoP", signProof(t, key, claims, ""))
	if _, ok := gate.Check(context.Background(), httptest.NewRecorder(), r); !ok {
		t.Fatal("gate refused a proof naming the advertised URL")
	}

	gate.HTU = []string{"https://op.example.com/oidc/par"}
	claims["jti"] = "advertised-gate-second"
	r.Header.Set("DPoP", signProof(t, key, claims, ""))
	if _, ok := gate.Check(context.Background(), httptest.NewRecorder(), r); ok {
		t.Error("gate admitted a proof naming a URL outside its advertised set")
	}
}

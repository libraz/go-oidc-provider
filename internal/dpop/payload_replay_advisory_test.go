package dpop_test

import (
	"context"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// TestVerify_RejectsNonObjectPayloads pins that a correctly signed proof
// whose payload is not a JSON object is rejected: a malformed-proof error
// for non-objects, and the missing-jti error for JSON null (which decodes to
// an empty claim bag).
//
// Tracks: CVE-2026-107723 (fast-jwt — claim validation silently skipped when
// the payload was a JSON array)
func TestVerify_RejectsNonObjectPayloads(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)

	for name, tc := range map[string]struct {
		payload string
		want    error
	}{
		"array":  {`[]`, dpop.ErrProofMalformed},
		"null":   {`null`, dpop.ErrProofMissingJTI},
		"string": {`"s"`, dpop.ErrProofMalformed},
		"number": {`1`, dpop.ErrProofMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw := signProofRawPayload(t, key, []byte(tc.payload))
			res, err := newVerifier(t, now).Verify(context.Background(), dpop.VerifyInput{
				ProofHeader: raw,
				Method:      "POST",
				URL:         mustParseURL(t, "https://op.example/oidc/token"),
				TLS:         true,
			})
			if err == nil || res != nil {
				t.Fatalf("accepted payload %s: res=%+v err=%v", name, res, err)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
		})
	}
}

// TestVerify_ReplayKeysOnJTINotRawProof pins that replay detection follows
// the parsed jti: two proofs with the same claims but distinct serialisations
// (fresh ECDSA signature each time) are the same proof to the replay gate.
//
// Tracks: CVE-2026-102269 (PyJWT — non-canonical signature segments gave one
// token several string forms, bypassing a raw-token revocation list)
func TestVerify_ReplayKeysOnJTINotRawProof(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	first := signProof(t, key, goodClaims(now), "")
	second := signProof(t, key, goodClaims(now), "")
	if first == second {
		t.Fatal("expected distinct serialisations for the same claims")
	}

	v := newVerifier(t, now)
	in := func(raw string) dpop.VerifyInput {
		return dpop.VerifyInput{
			ProofHeader: raw,
			Method:      "POST",
			URL:         mustParseURL(t, "https://op.example/oidc/token"),
			TLS:         true,
		}
	}
	if _, err := v.Verify(context.Background(), in(first)); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if _, err := v.Verify(context.Background(), in(second)); !errors.Is(err, dpop.ErrProofReplayed) {
		t.Fatalf("re-signed proof err=%v want ErrProofReplayed", err)
	}
}

// signProofRawPayload signs payload verbatim as a dpop+jwt proof.
func signProofRawPayload(tb testing.TB, key signKey, payload []byte) string {
	tb.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: key.alg, Key: key.priv},
		(&josev4.SignerOptions{}).
			WithType("dpop+jwt").
			WithHeader("jwk", josev4.JSONWebKey{Key: key.priv.Public()}),
	)
	if err != nil {
		tb.Fatalf("NewSigner: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		tb.Fatalf("Sign: %v", err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		tb.Fatalf("CompactSerialize: %v", err)
	}
	return raw
}

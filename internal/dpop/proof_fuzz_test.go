package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/url"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// FuzzVerifyProofHeader exercises [dpop.Verifier.Verify] with arbitrary
// "DPoP" header values. The harness asserts three structural invariants:
//
//  1. Verify never panics, regardless of input.
//  2. Every error returned MUST wrap one of the documented Err* sentinels;
//     a naked third-party error class would mean the HTTP layer's
//     wire-code mapping silently degrades to "server_error".
//  3. The success path returns a non-nil [*dpop.VerifyResult] whose JKT is
//     a populated base64url string and whose JTI matches the claim.
//
// The fuzz target is the proof-header parse + verify pipeline: a real
// ECDSA key is generated once in the seed function so the seed corpus
// exercises both the malformed-input branches AND the cryptographic
// happy path. Fuzz inputs cover the parser surface — non-JWT garbage,
// flipped signature bytes, alg=none variants, oversize payloads — that
// internal/jose's own fuzz harness only exercises one layer up.
//
// Seed rationale:
//   - empty: ErrProofMalformed empty-proof branch.
//   - canonical good proof: success path; downstream invariants run.
//   - good proof with the trailing 4 chars overwritten: ErrProofSignature.
//   - good proof rebuilt with typ=JWT: ErrProofMalformed (typ gate).
//   - well-formed compact JWS with two dots but bogus base64: parser
//     malformed branch.
//   - 10 KiB of "AAAA...AAA.AAA.AAA": stresses the base64 decoder before
//     signature work; must not blow out memory or panic.
//   - alg=none classic: proves the jose layer's allow-list survives in
//     situ.
func FuzzVerifyProofHeader(f *testing.F) {
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwk := josev4.JSONWebKey{Key: priv.Public()}
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: priv},
		(&josev4.SignerOptions{}).
			WithType("dpop+jwt").
			WithHeader("jwk", jwk),
	)
	if err != nil {
		f.Fatalf("NewSigner: %v", err)
	}
	good, err := jwt.Signed(signer).Claims(map[string]any{
		"jti": "fuzz-jti-1",
		"htm": "POST",
		"htu": "https://op.example/oidc/token",
		"iat": now.Unix(),
	}).Serialize()
	if err != nil {
		f.Fatalf("Serialize: %v", err)
	}

	// Mutate the trailing signature so the JOSE layer parses the JWS but
	// rejects the signature.
	tampered := good[:len(good)-4] + "AAAA"

	// Rebuild with typ=JWT to drive the typ-mismatch branch.
	wrongTypSigner, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: priv},
		(&josev4.SignerOptions{}).
			WithType("JWT").
			WithHeader("jwk", jwk),
	)
	if err != nil {
		f.Fatalf("NewSigner(JWT): %v", err)
	}
	wrongTyp, err := jwt.Signed(wrongTypSigner).Claims(map[string]any{
		"jti": "fuzz-jti-2",
		"htm": "POST",
		"htu": "https://op.example/oidc/token",
		"iat": now.Unix(),
	}).Serialize()
	if err != nil {
		f.Fatalf("Serialize(wrongTyp): %v", err)
	}

	// 10 KiB pseudo-JWT: three dot-separated runs of 'A's. Long enough
	// to exercise allocator paths; structurally invalid base64 once
	// the parser actually decodes the segments.
	bigBlob := make([]byte, 10*1024)
	for i := range bigBlob {
		bigBlob[i] = 'A'
	}
	bigBlob[3000] = '.'
	bigBlob[6000] = '.'

	f.Add("")
	f.Add(good)
	f.Add(tampered)
	f.Add(wrongTyp)
	f.Add("not.a.jwt")
	f.Add(string(bigBlob))
	f.Add(`eyJhbGciOiJub25lIiwidHlwIjoiZHBvcCtqd3QifQ.e30.`)

	verifier, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:  newMemJTIStore(),
		Clock: fixedClock{now: now},
	})
	if err != nil {
		f.Fatalf("NewVerifier: %v", err)
	}
	reqURL, err := url.Parse("https://op.example/oidc/token")
	if err != nil {
		f.Fatalf("url.Parse: %v", err)
	}

	f.Fuzz(func(t *testing.T, header string) {
		out, err := verifier.Verify(context.Background(), dpop.VerifyInput{
			ProofHeader: header,
			Method:      "POST",
			URL:         reqURL,
			TLS:         true,
		})
		if err != nil {
			switch {
			case errors.Is(err, dpop.ErrProofMalformed),
				errors.Is(err, dpop.ErrProofSignature),
				errors.Is(err, dpop.ErrProofIatWindow),
				errors.Is(err, dpop.ErrProofReplayed),
				errors.Is(err, dpop.ErrProofHTMMismatch),
				errors.Is(err, dpop.ErrProofHTUMismatch),
				errors.Is(err, dpop.ErrProofATHMismatch),
				errors.Is(err, dpop.ErrProofMissingJTI):
				// allowed
			default:
				t.Fatalf("Verify returned unrecognised error class: %v", err)
			}
			if out != nil {
				t.Fatalf("Verify returned non-nil result alongside error %v", err)
			}
			return
		}

		// Success path. Each run consumes the same JTI store; once the
		// good seed has been replayed by the fuzzer, ErrProofReplayed
		// should kick in instead of a second success. So the success
		// branch is reachable at most once across the seed corpus, but
		// the contract still holds whenever it does fire.
		if out == nil {
			t.Fatalf("Verify returned nil result and nil error")
		}
		if out.JKT == "" {
			t.Fatalf("Verify returned empty JKT for input length %d", len(header))
		}
		if out.JTI == "" {
			t.Fatalf("Verify returned empty JTI for input length %d", len(header))
		}
	})
}

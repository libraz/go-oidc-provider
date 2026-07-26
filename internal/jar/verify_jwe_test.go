package jar_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/jose"
)

// staticEncryptionResolver is a tiny [jar.EncryptionResolver] used by
// the verifier-side JWE tests. It owns a single (kid, *rsa.PrivateKey)
// pair so a test can stand a JWE round trip up without bringing in
// the full op-level keyset machinery.
type staticEncryptionResolver struct {
	kid  string
	priv *rsa.PrivateKey
}

func (r *staticEncryptionResolver) Resolve(kid string) (any, bool) {
	if kid != r.kid {
		return nil, false
	}
	return r.priv, true
}

func (r *staticEncryptionResolver) All() []any {
	return []any{r.priv}
}

// newJWEVerifier wires a verifier with the JWE seam plugged in. It
// shares the rest of the configuration with [newTestVerifier] (frozen
// clock, allow-missing-nbf/jti) so tests focus on the encryption-
// specific behaviour.
func newJWEVerifier(
	t *testing.T,
	now time.Time,
	keys *josev4.JSONWebKeySet,
	dec jar.EncryptionResolver,
) *jar.Verifier {
	t.Helper()
	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:             testIssuer,
		Resolver:           &staticResolver{keys: keys},
		Clock:              fakeClock{now: now},
		AllowMissingNbf:    true,
		AllowMissingJTI:    true,
		EncryptionResolver: dec,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// mustEncryptToJWE wraps an inner JWS in a JWE addressed to pub. The
// helper centralises the recipient-shape construction so individual
// tests stay focused on the assertion under test.
func mustEncryptToJWE(t *testing.T, inner string, pub *rsa.PublicKey, kid string) string {
	t.Helper()
	out, err := jose.EncryptNestedJWT(inner, jose.EncryptionRecipient{
		Alg:   jose.JWEAlgRSAOAEP256,
		Enc:   jose.JWEEncA256GCM,
		KeyID: kid,
		Key:   pub,
	})
	if err != nil {
		t.Fatalf("EncryptNestedJWT: %v", err)
	}
	return out
}

// mustRSAKey is a per-test fixture key. The 2048-bit floor matches
// the OP allow-list so the encryption resolver accepts the kid.
func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

// TestVerify_DecryptsJWERequestObject pins the happy path: a JWE
// wrapping a valid JWS round-trips through [Verifier.Verify] and the
// returned [Object] carries the decrypted claim bag.
func TestVerify_DecryptsJWERequestObject(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	inner, jwks := makeRequestObject(t, happyClaims(now))
	priv := mustRSAKey(t)
	jwe := mustEncryptToJWE(t, inner, &priv.PublicKey, "enc-1")

	v := newJWEVerifier(t, now, jwks, &staticEncryptionResolver{kid: "enc-1", priv: priv})
	obj, err := v.Verify(context.Background(), jwe, testClientID, newClient())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if obj.Claims["client_id"] != testClientID {
		t.Fatalf("claims did not survive JWE unwrap: %v", obj.Claims)
	}
}

// TestVerify_RejectsJWEWithoutResolver pins the wire-error envelope for
// the "OP has no encryption keyset" case: a JWE-shaped raw with a nil
// resolver MUST surface [ErrEncryptionUnsupported] so the wire layer
// emits invalid_request_object.
func TestVerify_RejectsJWEWithoutResolver(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	inner, jwks := makeRequestObject(t, happyClaims(now))
	priv := mustRSAKey(t)
	jwe := mustEncryptToJWE(t, inner, &priv.PublicKey, "enc-1")

	v := newTestVerifier(t, now, jwks)
	_, err := v.Verify(context.Background(), jwe, testClientID, newClient())
	if !errors.Is(err, jar.ErrEncryptionUnsupported) {
		t.Fatalf("err=%v want ErrEncryptionUnsupported", err)
	}
}

// TestVerify_RejectsJWEWithUnknownKID pins the kid-resolver leg: a
// JWE whose kid is not on the resolver MUST surface
// [ErrDecryptFailed] so an attacker probing for OP keysets via wire
// codes learns nothing. The class-collapsing mirrors (kid-oracle
// defence).
func TestVerify_RejectsJWEWithUnknownKID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	inner, jwks := makeRequestObject(t, happyClaims(now))
	priv := mustRSAKey(t)
	jwe := mustEncryptToJWE(t, inner, &priv.PublicKey, "enc-stranger")

	v := newJWEVerifier(t, now, jwks, &staticEncryptionResolver{kid: "enc-1", priv: priv})
	_, err := v.Verify(context.Background(), jwe, testClientID, newClient())
	if !errors.Is(err, jar.ErrDecryptFailed) {
		t.Fatalf("err=%v want ErrDecryptFailed", err)
	}
}

// TestVerify_RejectsJWEWithWrongKey pins the decrypt-failure leg: a
// JWE addressed to a different public key fails uniformly. The
// uniformity guarantee matters because an attacker who could
// distinguish "wrong key" from "kid unknown" would learn whether a kid
// is registered.
func TestVerify_RejectsJWEWithWrongKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	inner, jwks := makeRequestObject(t, happyClaims(now))
	wrongPriv := mustRSAKey(t) // recipient pub key for the JWE
	opPriv := mustRSAKey(t)    // OP's actual private key (does not match)
	jwe := mustEncryptToJWE(t, inner, &wrongPriv.PublicKey, "enc-1")

	v := newJWEVerifier(t, now, jwks, &staticEncryptionResolver{kid: "enc-1", priv: opPriv})
	_, err := v.Verify(context.Background(), jwe, testClientID, newClient())
	if !errors.Is(err, jar.ErrDecryptFailed) {
		t.Fatalf("err=%v want ErrDecryptFailed", err)
	}
}

// TestVerify_RejectsJWEWithDisallowedAlg pins the allow-list gate. A
// crafted JWE whose protected header advertises an alg outside the
// project allow-list MUST surface [ErrEncryptionAlgNotAllowed] without
// any crypto running. The fixture is hand-built because go-jose v4
// will refuse to mint such a JWE for us.
func TestVerify_RejectsJWEWithDisallowedAlg(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	inner, jwks := makeRequestObject(t, happyClaims(now))
	priv := mustRSAKey(t)
	jwe := mustEncryptToJWE(t, inner, &priv.PublicKey, "enc-1")
	tampered := tamperJWEAlg(t, jwe, "RSA1_5")

	v := newJWEVerifier(t, now, jwks, &staticEncryptionResolver{kid: "enc-1", priv: priv})
	_, err := v.Verify(context.Background(), tampered, testClientID, newClient())
	if !errors.Is(err, jar.ErrEncryptionAlgNotAllowed) {
		t.Fatalf("err=%v want ErrEncryptionAlgNotAllowed", err)
	}
}

// TestVerify_PassesThroughBareJWS pins that the JWE seam does not
// disturb the existing JWS path: a 3-segment compact JWS continues to
// flow through [Parse] / signature verification unchanged when the
// resolver is plumbed in.
func TestVerify_PassesThroughBareJWS(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	inner, jwks := makeRequestObject(t, happyClaims(now))
	priv := mustRSAKey(t)

	v := newJWEVerifier(t, now, jwks, &staticEncryptionResolver{kid: "enc-1", priv: priv})
	if _, err := v.Verify(context.Background(), inner, testClientID, newClient()); err != nil {
		t.Fatalf("Verify (bare JWS): %v", err)
	}
}

// TestVerify_RejectsJWEWrappedUnsignedJWT pins that decrypting a JWE
// never launders an unsigned inner token into an authenticated request.
// A JWE whose plaintext is an "alg":"none" JWT (empty signature) MUST be
// rejected: decryption confers confidentiality, never authentication, so
// the inner token still has to clear the JWS allow-list before any claim
// is trusted.
//
// Tracks: CVE-2026-29000 (pac4j-jwt) — a JWE whose decrypted payload was
// an unsigned / plain inner JWT was accepted as authenticated, letting an
// attacker holding only the recipient's public encryption key forge a
// request. The structural property is that every decrypted plaintext is
// routed through [Parse] -> [internal/jose.ParseSigned], whose closed
// signing-alg allow-list rejects "none" before the claim bag is read.
func TestVerify_RejectsJWEWrappedUnsignedJWT(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, jwks := makeRequestObject(t, happyClaims(now))
	priv := mustRSAKey(t)

	// An unsigned "alg":"none" JWT: header {"alg":"none"}, payload {},
	// empty signature segment. This is the primitive the pac4j bypass
	// smuggled inside a JWE and had accepted as an authenticated request.
	const noneJWT = "eyJhbGciOiJub25lIn0.e30."
	jwe := mustEncryptToJWE(t, noneJWT, &priv.PublicKey, "enc-1")

	v := newJWEVerifier(t, now, jwks, &staticEncryptionResolver{kid: "enc-1", priv: priv})
	_, err := v.Verify(context.Background(), jwe, testClientID, newClient())
	if !errors.Is(err, jar.ErrParse) {
		t.Fatalf("err=%v want ErrParse (JWE-wrapped alg=none inner must be rejected)", err)
	}
}

// tamperJWEAlg rewrites the protected header's `alg` value to the
// supplied (possibly disallowed) string and returns the re-serialised
// compact JWE. The helper exists because go-jose v4 will not produce
// a JWE with a banned alg from happy paths; we have to construct the
// hostile fixture by hand.
func tamperJWEAlg(t *testing.T, jwe, badAlg string) string {
	t.Helper()
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		t.Fatalf("not a compact JWE: %d parts", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("base64 decode protected header: %v", err)
	}
	tampered := strings.Replace(string(header), `"alg":"RSA-OAEP-256"`, `"alg":"`+badAlg+`"`, 1)
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(tampered))
	return strings.Join(parts, ".")
}

// TestVerify_RejectsDeeplyNestedJWE pins the JAR-level mapping for
// [jose.ErrJWENestingTooDeep]. The verifier reserves one of the
// [jose.MaxJOSENestingDepth] slots for the inner JWS Parse, so the
// JWE budget is MaxJOSENestingDepth-1. A chain of MaxJOSENestingDepth
// JWE wrappers (one over the budget) MUST surface [jar.ErrParse] —
// the wire layer then emits invalid_request_object, which is the
// appropriate envelope for a malformed request object regardless of
// where in the chain the depth ceiling fired (collapsing the failure
// class is a deliberate defence against an attacker probing for the
// cap value via wire-code variation).
func TestVerify_RejectsDeeplyNestedJWE(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	inner, jwks := makeRequestObject(t, happyClaims(now))
	priv := mustRSAKey(t)

	// Wrap the JWS in MaxJOSENestingDepth JWE layers — one over the
	// JWE budget the verifier passes to DecryptChain. The first
	// MaxJOSENestingDepth-1 wrappers are within budget; the
	// MaxJOSENestingDepth-th is the one that trips the cap.
	payload := mustEncryptToJWE(t, inner, &priv.PublicKey, "enc-1")
	for range jose.MaxJOSENestingDepth - 1 {
		payload = mustEncryptToJWE(t, payload, &priv.PublicKey, "enc-1")
	}

	v := newJWEVerifier(t, now, jwks, &staticEncryptionResolver{kid: "enc-1", priv: priv})
	_, err := v.Verify(context.Background(), payload, testClientID, newClient())
	if !errors.Is(err, jar.ErrParse) {
		t.Fatalf("err=%v want ErrParse (mapped from ErrJWENestingTooDeep)", err)
	}
}

// TestVerify_AcceptsJWEAtBoundary confirms the boundary opposite to
// [TestVerify_RejectsDeeplyNestedJWE]: a chain of (MaxJOSENestingDepth-1)
// JWE layers wrapping a JWS sits exactly at the budget and MUST verify
// successfully. The pair pins both sides of the inequality so a
// regression flipping ">" to ">=" surfaces immediately.
func TestVerify_AcceptsJWEAtBoundary(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	inner, jwks := makeRequestObject(t, happyClaims(now))
	priv := mustRSAKey(t)

	// (MaxJOSENestingDepth-1) total JWE layers + 1 JWS = MaxJOSENestingDepth.
	payload := mustEncryptToJWE(t, inner, &priv.PublicKey, "enc-1")
	for range jose.MaxJOSENestingDepth - 2 {
		payload = mustEncryptToJWE(t, payload, &priv.PublicKey, "enc-1")
	}

	v := newJWEVerifier(t, now, jwks, &staticEncryptionResolver{kid: "enc-1", priv: priv})
	if _, err := v.Verify(context.Background(), payload, testClientID, newClient()); err != nil {
		t.Fatalf("Verify at depth boundary: %v", err)
	}
}

// Compile-time assertion so the test file fails at build time if the
// public [jar.EncryptionResolver] contract drifts.
var _ jar.EncryptionResolver = (*staticEncryptionResolver)(nil)

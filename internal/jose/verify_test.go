package jose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/keys"
)

// mintJWS is the verification-path counterpart of [signWithCrit] in
// jose_test.go: produce a compact JWS with a controllable "kid"
// header. signer is an ECDSA P-256 private key (the only shape
// [keys.NewSet] accepts).
func mintJWS(t testing.TB, priv *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	opts := (&josev4.SignerOptions{}).WithHeader("kid", kid)
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: priv},
		opts,
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return tok
}

func mustECDSAKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return priv
}

func TestVerify_AcceptsValidSignature(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "active", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	tok := mintJWS(t, priv, "active", map[string]any{"sub": "u-1"})

	jws, _, err := jose.ParseSigned(tok)
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	payload, err := jose.Verify(jws, set)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(payload) == 0 {
		t.Fatal("Verify returned empty payload")
	}
}

func TestVerify_RejectsMissingKID(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "active", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	// Mint a JWS with no "kid" header.
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: priv},
		&josev4.SignerOptions{},
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(map[string]any{"sub": "u-1"}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	jws, _, err := jose.ParseSigned(tok)
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	_, err = jose.Verify(jws, set)
	if !errors.Is(err, jose.ErrMissingKeyID) {
		t.Fatalf("Verify err = %v; want ErrMissingKeyID", err)
	}
}

func TestVerify_RejectsUnknownKID(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "active", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	tok := mintJWS(t, priv, "stranger", map[string]any{"sub": "u-1"})

	jws, _, err := jose.ParseSigned(tok)
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	_, err = jose.Verify(jws, set)
	if !errors.Is(err, jose.ErrUnknownKeyID) {
		t.Fatalf("Verify err = %v; want ErrUnknownKeyID", err)
	}
}

// TestVerify_DoesNotTrialDecodeAcrossKeys pins the structural property
// that Verify resolves the key strictly through the JWS "kid" and
// never iterates the set. The token below is signed with priv2 but
// names kid "k1" (whose key is priv1). A naive verifier that fell
// back to trying every key in the set would succeed; jose.Verify must
// fail.
func TestVerify_DoesNotTrialDecodeAcrossKeys(t *testing.T) {
	t.Parallel()

	priv1 := mustECDSAKey(t)
	priv2 := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{
		{KeyID: "k1", Signer: priv1},
		{KeyID: "k2", Signer: priv2},
	})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	// Sign with priv2 but advertise kid "k1".
	tok := mintJWS(t, priv2, "k1", map[string]any{"sub": "u-1"})

	jws, _, err := jose.ParseSigned(tok)
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	_, err = jose.Verify(jws, set)
	if err == nil {
		t.Fatal("Verify succeeded; expected failure (kid k1 must not be re-resolved)")
	}
	// The exact failure is wrapped ErrMalformed (signature mismatch
	// surfaces from go-jose). The contract is "no trial-decode" — the
	// test passes if Verify returns any non-nil error here.
}

func TestVerify_RejectsNilInputs(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "k", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	if _, err := jose.Verify(nil, set); !errors.Is(err, jose.ErrMalformed) {
		t.Errorf("Verify(nil jws) err = %v; want ErrMalformed", err)
	}

	tok := mintJWS(t, priv, "k", map[string]any{"sub": "u-1"})
	jws, _, err := jose.ParseSigned(tok)
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	if _, err := jose.Verify(jws, nil); !errors.Is(err, jose.ErrMalformed) {
		t.Errorf("Verify(nil set) err = %v; want ErrMalformed", err)
	}
}

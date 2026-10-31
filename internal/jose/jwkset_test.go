package jose_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// JWK members used by the decoder tests. ecSigJWK is a well-formed P-256
// verification key; the rest are members the JOSE layer cannot turn into a
// key — an OKP curve outside the Ed25519 it implements (the shape an RP
// publishes for ECDH-ES key agreement) and an entirely unknown "kty".
const (
	ecSigJWK      = `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sig","kid":"sig-1","alg":"ES256"}`
	x25519JWK     = `{"kty":"OKP","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo","use":"enc","kid":"enc-1"}`
	ed448JWK      = `{"kty":"OKP","crv":"Ed448","x":"AAAA","use":"sig","kid":"sig-2"}`
	unknownKtyJWK = `{"kty":"XYZZY","kid":"other-1"}`
	// zeroExponentRSAJWK decodes, but its exponent of 0 fails Valid and
	// once panicked RFC 7638 thumbprint computation in the JOSE layer.
	octJWK             = `{"kty":"oct","k":"c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0","alg":"HS256","use":"sig","kid":"oct-1"}`
	zeroExponentRSAJWK = `{"kty":"RSA","kid":"rsa-e0","e":"AA","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw"}`
)

// TestDecodeJWKSet covers the RFC 7517 §5 rule that a JWK Set member whose
// key type is not understood must be ignored rather than taken as grounds
// to reject the whole document: an RP that publishes an X25519 encryption
// key next to its ES256 signing key would otherwise lose every JWKS-backed
// path (private_key_jwt, request objects, registration) at once. The
// declared count covers members that were dropped so callers can keep
// bounding cardinality on the wire shape.
func TestDecodeJWKSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		doc          string
		wantKIDs     []string
		wantDeclared int
		wantErr      error
		wantOtherErr bool
	}{
		{
			name:         "unsupported member dropped, supported key kept",
			doc:          `{"keys":[` + x25519JWK + `,` + ecSigJWK + `]}`,
			wantKIDs:     []string{"sig-1"},
			wantDeclared: 2,
		},
		{
			name:         "several unsupported members dropped",
			doc:          `{"keys":[` + ed448JWK + `,` + unknownKtyJWK + `,` + ecSigJWK + `]}`,
			wantKIDs:     []string{"sig-1"},
			wantDeclared: 3,
		},
		{
			name:         "supported key first",
			doc:          `{"keys":[` + ecSigJWK + `,` + x25519JWK + `]}`,
			wantKIDs:     []string{"sig-1"},
			wantDeclared: 2,
		},
		{
			name:         "member missing kty dropped",
			doc:          `{"keys":[{"kid":"no-kty"},` + ecSigJWK + `]}`,
			wantKIDs:     []string{"sig-1"},
			wantDeclared: 2,
		},
		{
			// Tracks: GHSA-r39w-98wm-9pp6
			name:         "degenerate RSA key (exponent 0) dropped",
			doc:          `{"keys":[` + zeroExponentRSAJWK + `,` + ecSigJWK + `]}`,
			wantKIDs:     []string{"sig-1"},
			wantDeclared: 2,
		},
		{
			name:         "every member unsupported",
			doc:          `{"keys":[` + x25519JWK + `,` + unknownKtyJWK + `]}`,
			wantDeclared: 2,
			wantErr:      jose.ErrNoUsableJWK,
		},
		{
			name:         "empty key array",
			doc:          `{"keys":[]}`,
			wantDeclared: 0,
		},
		{
			name:         "absent keys member",
			doc:          `{}`,
			wantDeclared: 0,
		},
		{
			name:         "malformed document",
			doc:          `{"keys":[`,
			wantOtherErr: true,
		},
		{
			name:         "document is not an object",
			doc:          `["not-a-jwks"]`,
			wantOtherErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set, declared, err := jose.DecodeJWKSet([]byte(tc.doc))
			if declared != tc.wantDeclared {
				t.Errorf("declared=%d want %d", declared, tc.wantDeclared)
			}
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v want %v", err, tc.wantErr)
				}
				return
			case tc.wantOtherErr:
				if err == nil {
					t.Fatal("expected a decode error, got nil")
				}
				if errors.Is(err, jose.ErrNoUsableJWK) {
					t.Fatal("a malformed document must not surface as ErrNoUsableJWK")
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeJWKSet: %v", err)
			}
			got := make([]string, 0, len(set.Keys))
			for i := range set.Keys {
				got = append(got, set.Keys[i].KeyID)
			}
			if !slices.Equal(got, tc.wantKIDs) {
				t.Errorf("kids=%v want %v", got, tc.wantKIDs)
			}
		})
	}
}

// TestParseJWKSet_IgnoresUnsupportedMember pins that the key-shape parser
// inherits the member-wise tolerance, so a client registering a mixed
// keyset still yields its usable verification keys.
func TestParseJWKSet_IgnoresUnsupportedMember(t *testing.T) {
	t.Parallel()

	keys, err := jose.ParseJWKSet([]byte(`{"keys":[` + x25519JWK + `,` + ecSigJWK + `]}`))
	if err != nil {
		t.Fatalf("ParseJWKSet: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys)=%d want 1", len(keys))
	}
	if keys[0].Algorithm != "ES256" {
		t.Errorf("alg=%q want ES256", keys[0].Algorithm)
	}
}

// TestParseJWKSet_AllMembersUnsupported confirms a set with nothing usable
// left is an error rather than an empty success, so callers do not have to
// tell "no keys" from "no keys we understand".
func TestParseJWKSet_AllMembersUnsupported(t *testing.T) {
	t.Parallel()

	if _, err := jose.ParseJWKSet([]byte(`{"keys":[` + x25519JWK + `]}`)); !errors.Is(err, jose.ErrNoUsableJWK) {
		t.Fatalf("err=%v want ErrNoUsableJWK", err)
	}
}

// TestParseJWKSet_RejectsPrivateKey pins that a JWKS advertised for
// signature verification is admitted only when it carries public keys.
// crypto.PublicKey is an alias for `any`, so the naive type assertion the
// parser used never failed and would have stored a client-registered
// private key as a verification key. The public-key control proves the
// tighter gate does not regress the conforming path.
func TestParseJWKSet_RejectsPrivateKey(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pubSet, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig",
	}}})
	if err != nil {
		t.Fatalf("marshal public set: %v", err)
	}
	if _, err := jose.ParseJWKSet(pubSet); err != nil {
		t.Fatalf("public JWKS rejected: %v", err)
	}

	privSet, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: priv, KeyID: "k1", Algorithm: "RS256", Use: "sig",
	}}})
	if err != nil {
		t.Fatalf("marshal private set: %v", err)
	}
	if _, err := jose.ParseJWKSet(privSet); !errors.Is(err, jose.ErrUnsupportedKeyShape) {
		t.Fatalf("private JWKS: err=%v want ErrUnsupportedKeyShape", err)
	}
}

// FuzzDecodeJWKSet pins the no-panic contract on the JWK Set entry point
// every inbound client key set goes through, and that the declared count
// never undercounts the survivors.
//
// Tracks: GHSA-vvm8-gf78-28g4 (go-jose) — panics in JSON parsing reached
// through JWK and JWK Set decoding.
func FuzzDecodeJWKSet(f *testing.F) {
	for _, member := range []string{ecSigJWK, x25519JWK, ed448JWK, unknownKtyJWK, zeroExponentRSAJWK, octJWK} {
		f.Add([]byte(`{"keys":[` + member + `]}`))
	}
	f.Add([]byte(`{"keys":[{"kty":"RSA","n":null,"e":null}]}`))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"","y":""}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		set, declared, err := jose.DecodeJWKSet(raw)
		if err != nil {
			return
		}
		if declared < len(set.Keys) {
			t.Fatalf("declared=%d < decoded=%d", declared, len(set.Keys))
		}
	})
}

// TestParseJWKSet_RejectsSymmetricKey pins that an inbound JWK Set never
// yields an oct key, empty or not, so no client-supplied JWK can key an
// HMAC verification.
//
// Tracks: GHSA-pxh4-856f-4h89 (PyJWT) — an oct JWK with an empty "k"
// produced a zero-length HMAC key that verified any forged token.
func TestParseJWKSet_RejectsSymmetricKey(t *testing.T) {
	t.Parallel()

	for name, member := range map[string]string{
		"empty k":     `{"kty":"oct","k":"","alg":"HS256","use":"sig","kid":"oct-empty"}`,
		"non-empty k": octJWK,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			keys, err := jose.ParseJWKSet([]byte(`{"keys":[` + member + `]}`))
			if err == nil {
				t.Fatalf("ParseJWKSet accepted a symmetric key: %+v", keys)
			}
			if !errors.Is(err, jose.ErrUnsupportedKeyShape) && !errors.Is(err, jose.ErrNoUsableJWK) {
				t.Fatalf("err=%v want ErrUnsupportedKeyShape or ErrNoUsableJWK", err)
			}
		})
	}
}

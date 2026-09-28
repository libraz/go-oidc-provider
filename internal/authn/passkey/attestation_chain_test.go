package passkey_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/testutil/softkey"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// coseES256 is the COSE algorithm identifier for ECDSA P-256 / SHA-256.
const coseES256 = -7

// oidFIDOGenCeAAGUID is the attestation-certificate extension carrying
// the authenticator model's AAGUID.
var oidFIDOGenCeAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// testCA is a certificate authority minted in-process: a vendor root,
// an intermediate, or an attacker's own root.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func newSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return n
}

// newTestRoot mints a self-signed root valid around now.
func newTestRoot(t *testing.T, name string, now time.Time) *testCA {
	t.Helper()
	key := newTestKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// intermediate mints a CA certificate signed by ca.
func (ca *testCA) intermediate(t *testing.T, now time.Time) *testCA {
	t.Helper()
	key := newTestKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: "Attestation Intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// attestationLeaf mints a packed attestation certificate (W3C WebAuthn
// §8.2.1) naming aaguid in id-fido-gen-ce-aaguid, signed by ca.
func (ca *testCA) attestationLeaf(t *testing.T, aaguid []byte, now time.Time) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	ext, err := asn1.Marshal(aaguid)
	if err != nil {
		t.Fatalf("marshal AAGUID extension: %v", err)
	}
	key := newTestKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(t),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Example Vendor"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			CommonName:         "Example Authenticator",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtraExtensions:       []pkix.Extension{{Id: oidFIDOGenCeAAGUID, Value: ext}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create attestation leaf: %v", err)
	}
	return der, key
}

// packedCreate builds the registration response a browser posts for a
// "packed" attestation. With x5c the statement is signed by attKey;
// without it the statement is self attestation, signed by the new
// credential key.
func packedCreate(t *testing.T, challenge, aaguid []byte, x5c [][]byte, attKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString

	credKey := newTestKey(t)
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("credential id: %v", err)
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	credKey.X.FillBytes(x)
	credKey.Y.FillBytes(y)
	coseKey, err := cbor.Marshal(map[int]any{1: 2, 3: coseES256, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatalf("encode COSE key: %v", err)
	}

	rpIDHash := sha256.Sum256([]byte(roundTripRPID))
	authData := append([]byte(nil), rpIDHash[:]...)
	authData = append(authData, 0x41) // UP | AT
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, aaguid...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credID))) //nolint:gosec // credID is 32 bytes.
	authData = append(authData, credID...)
	authData = append(authData, coseKey...)

	clientData, err := json.Marshal(map[string]any{
		"type":        "webauthn.create",
		"challenge":   b64(challenge),
		"origin":      roundTripOrigin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("encode client data: %v", err)
	}
	clientDataHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), clientDataHash[:]...))

	signer := credKey
	if x5c != nil {
		signer = attKey
	}
	sig, err := ecdsa.SignASN1(rand.Reader, signer, digest[:])
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	stmt := map[string]any{"alg": coseES256, "sig": sig}
	if x5c != nil {
		stmt["x5c"] = x5c
	}
	attestation, err := cbor.Marshal(map[string]any{"fmt": "packed", "attStmt": stmt, "authData": authData})
	if err != nil {
		t.Fatalf("encode attestation object: %v", err)
	}
	out, err := json.Marshal(map[string]any{
		"id":    b64(credID),
		"rawId": b64(credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(attestation),
		},
		"clientExtensionResults": map[string]any{},
	})
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	return out
}

// testAttestationRoots returns one freshly minted root, for tests that
// need an allowlist to be configurable but never run a registration.
func testAttestationRoots(t *testing.T) []*x509.Certificate {
	t.Helper()
	return []*x509.Certificate{newTestRoot(t, "Vendor Attestation Root", time.Now()).cert}
}

// newAllowlistVerifier builds a verifier that admits allowedAAGUIDStr
// under the given roots, with its clock pinned to now.
func newAllowlistVerifier(t *testing.T, now time.Time, roots ...*x509.Certificate) *passkey.Verifier {
	t.Helper()
	v, err := passkey.New(passkey.Config{
		RPID:                  roundTripRPID,
		RPDisplayName:         "Example Identity",
		RPOrigins:             []string{roundTripOrigin},
		AttestationPreference: protocol.PreferDirectAttestation,
		AAGUIDAllowlist:       []string{allowedAAGUIDStr},
		AttestationRoots:      roots,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.Clock = timex.ClockFunc(func() time.Time { return now })
	return v
}

// finishWith runs one registration ceremony, letting build produce the
// response from the issued challenge.
func finishWith(t *testing.T, v *passkey.Verifier, build func(challenge []byte) []byte) (*passkey.Credential, error) {
	t.Helper()
	ctx := context.Background()
	opts, session, err := v.BeginRegistration(ctx, roundTripSubject, roundTripName, "Alice", nil)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	challenge, err := softkey.ChallengeFromOptions(opts.PublicKey)
	if err != nil {
		t.Fatalf("ChallengeFromOptions: %v", err)
	}
	return v.FinishRegistration(ctx, newEmptyPasskeyStore(t), session, roundTripSubject, roundTripName, "Alice", nil, build(challenge))
}

// TestAAGUIDAllowlistRequiresATrustedAttestationChain pins that the
// allowlist decides only on an AAGUID whose attestation certificate
// chains to a configured root. The attestation type alone proves
// nothing: anyone can mint a CA and a leaf naming a certified model's
// AAGUID, and the library reports that chain as "basic_full" exactly
// as it would a vendor's.
//
// Tracks: GHSA-6hxq-p678-4hr2 — an AAGUID allowlist was applied to an
// attestation whose certificate chain was never checked against a
// trust anchor, the same shape as CVE-2026-6856: an unauthenticated
// AAGUID claim let any authenticator assert a certified model's
// identity.
func TestAAGUIDAllowlistRequiresATrustedAttestationChain(t *testing.T) {
	t.Parallel()

	now := time.Now()
	vendor := newTestRoot(t, "Vendor Attestation Root", now)

	t.Run("a chain to a self-made root is refused", func(t *testing.T) {
		t.Parallel()
		attacker := newTestRoot(t, "Attacker Root", now)
		leaf, key := attacker.attestationLeaf(t, allowedAAGUIDBytes, now)
		v := newAllowlistVerifier(t, now, vendor.cert)
		_, err := finishWith(t, v, func(c []byte) []byte {
			return packedCreate(t, c, allowedAAGUIDBytes, [][]byte{leaf}, key)
		})
		if !errors.Is(err, passkey.ErrAttestationInvalid) {
			t.Fatalf("forged chain naming an allowlisted AAGUID: err=%v, want ErrAttestationInvalid", err)
		}
	})

	t.Run("a chain to a configured root with an allowlisted AAGUID is accepted", func(t *testing.T) {
		t.Parallel()
		leaf, key := vendor.attestationLeaf(t, allowedAAGUIDBytes, now)
		v := newAllowlistVerifier(t, now, vendor.cert)
		cred, err := finishWith(t, v, func(c []byte) []byte {
			return packedCreate(t, c, allowedAAGUIDBytes, [][]byte{leaf}, key)
		})
		if err != nil {
			t.Fatalf("FinishRegistration: %v", err)
		}
		if cred.AttestationType != "basic_full" {
			t.Errorf("AttestationType=%q want basic_full", cred.AttestationType)
		}
	})

	t.Run("a chain through an intermediate to a configured root is accepted", func(t *testing.T) {
		t.Parallel()
		inter := vendor.intermediate(t, now)
		leaf, key := inter.attestationLeaf(t, allowedAAGUIDBytes, now)
		v := newAllowlistVerifier(t, now, vendor.cert)
		if _, err := finishWith(t, v, func(c []byte) []byte {
			return packedCreate(t, c, allowedAAGUIDBytes, [][]byte{leaf, inter.cert.Raw}, key)
		}); err != nil {
			t.Fatalf("FinishRegistration: %v", err)
		}
	})

	t.Run("a chain to a configured root with a non-allowlisted AAGUID is refused", func(t *testing.T) {
		t.Parallel()
		leaf, key := vendor.attestationLeaf(t, disallowedAAGUIDBytes, now)
		v := newAllowlistVerifier(t, now, vendor.cert)
		_, err := finishWith(t, v, func(c []byte) []byte {
			return packedCreate(t, c, disallowedAAGUIDBytes, [][]byte{leaf}, key)
		})
		if !errors.Is(err, passkey.ErrAttestationInvalid) {
			t.Fatalf("trusted chain, AAGUID outside the allowlist: err=%v, want ErrAttestationInvalid", err)
		}
	})

	t.Run("a leaf naming another AAGUID than the authenticator data is refused", func(t *testing.T) {
		t.Parallel()
		leaf, key := vendor.attestationLeaf(t, disallowedAAGUIDBytes, now)
		v := newAllowlistVerifier(t, now, vendor.cert)
		_, err := finishWith(t, v, func(c []byte) []byte {
			return packedCreate(t, c, allowedAAGUIDBytes, [][]byte{leaf}, key)
		})
		if !errors.Is(err, passkey.ErrAttestationInvalid) {
			t.Fatalf("certificate AAGUID differs from authenticator data: err=%v, want ErrAttestationInvalid", err)
		}
	})

	t.Run("the chain is judged at the OP clock", func(t *testing.T) {
		t.Parallel()
		leaf, key := vendor.attestationLeaf(t, allowedAAGUIDBytes, now)
		v := newAllowlistVerifier(t, now.Add(48*time.Hour), vendor.cert)
		_, err := finishWith(t, v, func(c []byte) []byte {
			return packedCreate(t, c, allowedAAGUIDBytes, [][]byte{leaf}, key)
		})
		if !errors.Is(err, passkey.ErrAttestationInvalid) {
			t.Fatalf("chain expired at the OP clock: err=%v, want ErrAttestationInvalid", err)
		}
	})

	t.Run("self attestation is refused", func(t *testing.T) {
		t.Parallel()
		v := newAllowlistVerifier(t, now, vendor.cert)
		_, err := finishWith(t, v, func(c []byte) []byte {
			return packedCreate(t, c, allowedAAGUIDBytes, nil, nil)
		})
		if !errors.Is(err, passkey.ErrAttestationInvalid) {
			t.Fatalf("self attestation: err=%v, want ErrAttestationInvalid", err)
		}
	})

	t.Run("no attestation is refused", func(t *testing.T) {
		t.Parallel()
		key, err := softkey.New()
		if err != nil {
			t.Fatalf("softkey.New: %v", err)
		}
		key.SetAAGUID([16]byte(allowedAAGUIDBytes))
		v := newAllowlistVerifier(t, now, vendor.cert)
		_, err = finishWith(t, v, func(c []byte) []byte {
			out, cerr := key.Create(roundTripRPID, roundTripOrigin, c)
			if cerr != nil {
				t.Fatalf("Create: %v", cerr)
			}
			return out
		})
		if !errors.Is(err, passkey.ErrAttestationInvalid) {
			t.Fatalf("none attestation: err=%v, want ErrAttestationInvalid", err)
		}
	})
}

// TestNew_AAGUIDAllowlistRequiresAttestationRoots pins the construction
// half: an allowlist without trust anchors, or with a nil one, is a
// configuration error rather than a policy that admits any chain.
func TestNew_AAGUIDAllowlistRequiresAttestationRoots(t *testing.T) {
	t.Parallel()

	base := passkey.Config{
		RPID:                  roundTripRPID,
		RPDisplayName:         "Example Identity",
		RPOrigins:             []string{roundTripOrigin},
		AttestationPreference: protocol.PreferDirectAttestation,
		AAGUIDAllowlist:       []string{allowedAAGUIDStr},
	}
	if _, err := passkey.New(base); !errors.Is(err, passkey.ErrInvalidConfig) {
		t.Errorf("allowlist without roots: err=%v, want ErrInvalidConfig", err)
	}

	withNil := base
	withNil.AttestationRoots = []*x509.Certificate{nil}
	if _, err := passkey.New(withNil); !errors.Is(err, passkey.ErrInvalidConfig) {
		t.Errorf("nil root: err=%v, want ErrInvalidConfig", err)
	}
}

// Package softkey is an in-process WebAuthn authenticator for tests.
//
// A registration or assertion ceremony cannot be exercised end to end
// without something that holds a key and signs with it. Browsers ship a
// virtual authenticator for exactly this reason; softkey is the Go
// equivalent, so a test can drive [github.com/libraz/go-oidc-provider/op/passkeykit]
// enrolment and [github.com/libraz/go-oidc-provider/op.PrimaryPasskey]
// login against real signatures rather than against a stub that agrees
// with whatever the verifier asks.
//
// It is not a mock of the verifier: every byte it emits is the wire
// format a browser emits, and the library's own parser and signature
// check are what decide whether a test passes.
//
// The authenticator holds one ES256 credential, reports "none"
// attestation, and increments its signature counter on every assertion.
// Scope is deliberately narrow — no CTAP transport, no PIN, no resident
// key management, no attestation statement formats beyond "none".
package softkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator-data flag bits (W3C WebAuthn Level 3 §6.1).
const (
	flagUserPresent    = 0x01
	flagUserVerified   = 0x04
	flagBackupEligible = 0x08
	flagBackupState    = 0x10
	flagAttestedData   = 0x40
)

// coseES256 is the COSE algorithm identifier for ECDSA over P-256 with
// SHA-256. It is the only algorithm this authenticator offers.
const coseES256 = -7

// credentialIDLen is the length of the generated credential identifier.
// Any length works; 32 bytes matches what platform authenticators
// typically emit for a non-resident credential.
const credentialIDLen = 32

// Key is one soft authenticator holding one credential.
//
// The exported policy fields are read at ceremony time, so a test can
// flip them between calls to model an authenticator whose user
// verification or backup state changed. Zero values give the common
// case: user present, not verified, not backed up.
type Key struct {
	// UserVerified sets the UV flag. Turn it on for a flow that
	// requires user verification.
	UserVerified bool

	// BackupEligible sets the BE flag. It is fixed at credential
	// creation for a real authenticator, and the verifier rejects an
	// assertion that flips it — set it before [Key.Create] and leave
	// it alone afterwards.
	BackupEligible bool

	// BackupState sets the BS flag. Unlike BE this may legitimately
	// change once the credential has been synced.
	BackupState bool

	aaguid       [16]byte
	credentialID []byte
	priv         *ecdsa.PrivateKey
	signCount    uint32
}

// New builds an authenticator with a fresh ES256 key, a random
// credential ID, and an all-zero AAGUID (the value a platform
// authenticator reports when it declines to identify its model).
func New() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("softkey: generate key: %w", err)
	}
	id := make([]byte, credentialIDLen)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("softkey: generate credential id: %w", err)
	}
	return &Key{credentialID: id, priv: priv}, nil
}

// CredentialID returns the identifier this authenticator reports.
func (k *Key) CredentialID() []byte { return append([]byte(nil), k.credentialID...) }

// SetAAGUID makes the authenticator claim a specific model. Tests that
// exercise an AAGUID allowlist use it to stand in for a certified
// device; note that an allowlist is only enforced against an
// attestation that vouches for the model, which "none" does not.
func (k *Key) SetAAGUID(aaguid [16]byte) { k.aaguid = aaguid }

// SignCount reports the counter the next assertion will carry.
func (k *Key) SignCount() uint32 { return k.signCount }

// SetSignCount rewinds or advances the counter. A counter that fails to
// increase is what the verifier reads as a cloned authenticator, so
// this is how a test produces that signal.
func (k *Key) SetSignCount(n uint32) { k.signCount = n }

// Create produces the JSON a browser posts after
// navigator.credentials.create() — the value
// [passkeykit.Registrar.Finish] consumes.
//
// challenge is the raw challenge bytes from the creation options;
// origin is the page origin the ceremony ran on, which must be one the
// Relying Party accepts.
func (k *Key) Create(rpID, origin string, challenge []byte) ([]byte, error) {
	clientData, err := clientDataJSON("webauthn.create", origin, challenge)
	if err != nil {
		return nil, err
	}

	coseKey, err := k.coseKey()
	if err != nil {
		return nil, err
	}

	// Attested credential data: AAGUID, then the credential ID with a
	// two-byte big-endian length prefix, then the COSE public key.
	attested := make([]byte, 0, len(k.aaguid)+2+len(k.credentialID)+len(coseKey))
	attested = append(attested, k.aaguid[:]...)
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(k.credentialID))) //nolint:gosec // credentialIDLen is a 32-byte constant.
	attested = append(attested, k.credentialID...)
	attested = append(attested, coseKey...)

	authData := k.authenticatorData(rpID, flagAttestedData, attested)

	attestation, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		return nil, fmt.Errorf("softkey: encode attestation object: %w", err)
	}

	return json.Marshal(map[string]any{
		"id":    b64(k.credentialID),
		"rawId": b64(k.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(attestation),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults": map[string]any{},
	})
}

// Assert produces the JSON a browser posts after
// navigator.credentials.get(). The signature counter is incremented
// first, so consecutive calls produce the strictly increasing sequence
// a genuine authenticator would; drive [Key.SetSignCount] to break that
// on purpose.
//
// userHandle is echoed back as the credential's user handle. Pass the
// subject bytes the credential was registered under, or nil for a
// non-discoverable credential.
func (k *Key) Assert(rpID, origin string, challenge, userHandle []byte) ([]byte, error) {
	clientData, err := clientDataJSON("webauthn.get", origin, challenge)
	if err != nil {
		return nil, err
	}

	k.signCount++
	authData := k.authenticatorData(rpID, 0, nil)

	// The signature covers the authenticator data concatenated with the
	// SHA-256 of the client data — the binding that stops a signature
	// captured on one page being replayed on another.
	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte(nil), authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("softkey: sign assertion: %w", err)
	}

	response := map[string]any{
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
	}
	if len(userHandle) > 0 {
		response["userHandle"] = b64(userHandle)
	}

	return json.Marshal(map[string]any{
		"id":                     b64(k.credentialID),
		"rawId":                  b64(k.credentialID),
		"type":                   "public-key",
		"response":               response,
		"clientExtensionResults": map[string]any{},
	})
}

// authenticatorData assembles the fixed-layout structure both ceremonies
// sign over: the RP ID hash, one flags byte, the big-endian signature
// counter, and — for registration — the attested credential data.
func (k *Key) authenticatorData(rpID string, extraFlags byte, attested []byte) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))

	flags := byte(flagUserPresent) | extraFlags
	if k.UserVerified {
		flags |= flagUserVerified
	}
	if k.BackupEligible {
		flags |= flagBackupEligible
	}
	if k.BackupState {
		flags |= flagBackupState
	}

	out := make([]byte, 0, sha256.Size+1+4+len(attested))
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, k.signCount)
	out = append(out, attested...)
	return out
}

// coseKey encodes the public key as a COSE_Key map. The integer labels
// are the ones RFC 8152 assigns: 1 kty, 3 alg, -1 crv, -2 x, -3 y. The
// coordinates are fixed-width because a leading zero byte is
// significant to the verifier's decoder.
func (k *Key) coseKey() ([]byte, error) {
	const coordLen = 32
	const (
		ktyEC2  = 2 // key type: two-coordinate elliptic curve
		crvP256 = 1 // curve: NIST P-256
	)
	x := make([]byte, coordLen)
	y := make([]byte, coordLen)
	k.priv.X.FillBytes(x)
	k.priv.Y.FillBytes(y)

	out, err := cbor.Marshal(map[int]any{
		1:  ktyEC2,
		3:  coseES256,
		-1: crvP256,
		-2: x,
		-3: y,
	})
	if err != nil {
		return nil, fmt.Errorf("softkey: encode COSE key: %w", err)
	}
	return out, nil
}

// clientDataJSON builds the CollectedClientData the browser would
// produce. crossOrigin is always false: this authenticator only models
// a ceremony run from the Relying Party's own page.
func clientDataJSON(ceremony, origin string, challenge []byte) ([]byte, error) {
	out, err := json.Marshal(map[string]any{
		"type":        ceremony,
		"challenge":   b64(challenge),
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		return nil, fmt.Errorf("softkey: encode client data: %w", err)
	}
	return out, nil
}

// b64 renders bytes the way every WebAuthn wire field does: base64url
// without padding.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ChallengeFromOptions extracts the raw challenge from a serialised
// PublicKeyCredentialCreationOptions / RequestOptions object, so a test
// can feed the ceremony's own challenge straight back to [Key.Create] /
// [Key.Assert] instead of re-deriving it.
func ChallengeFromOptions(options []byte) ([]byte, error) {
	var doc struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(options, &doc); err != nil {
		return nil, fmt.Errorf("softkey: parse options: %w", err)
	}
	if doc.Challenge == "" {
		return nil, fmt.Errorf("softkey: options carry no challenge: %s", options)
	}
	raw, err := base64.RawURLEncoding.DecodeString(doc.Challenge)
	if err != nil {
		return nil, fmt.Errorf("softkey: decode challenge: %w", err)
	}
	return raw, nil
}

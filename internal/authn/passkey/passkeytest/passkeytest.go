// Package passkeytest is a software WebAuthn authenticator for tests that
// drive the passkey factor through its orchestrator-facing surface.
//
// It wraps one ES256 credential: [Authenticator.Record] is the row a test
// seeds into a [store.PasskeyStore] as if registration had happened, and
// [Authenticator.Assert] is the JSON an SPA submits in the passkey
// prompt's response field. Signatures are real, so the library's parser
// and verifier decide whether a test passes.
package passkeytest

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/libraz/go-oidc-provider/internal/testutil/softkey"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Authenticator holds one P-256 credential and its signature counter.
// The counter starts at 0 and increases on every [Authenticator.Assert].
type Authenticator struct {
	key       *softkey.Key
	rpID      string
	publicKey []byte
}

// New builds an authenticator whose credential is scoped to rpID, with a
// fresh key and a random credential ID.
func New(t testing.TB, rpID string) *Authenticator {
	t.Helper()
	key, err := softkey.New()
	if err != nil {
		t.Fatalf("passkeytest: %v", err)
	}
	return &Authenticator{key: key, rpID: rpID, publicKey: coseKey(t, key, rpID)}
}

// Record returns the credential record a completed registration would
// have stored for subject: the credential ID and COSE public key of this
// authenticator, "none" attestation, a zero AAGUID and sign counter 0.
func (a *Authenticator) Record(subject string) store.PasskeyRecord {
	return store.PasskeyRecord{
		CredentialID:    a.key.CredentialID(),
		Subject:         subject,
		PublicKey:       append([]byte(nil), a.publicKey...),
		AAGUID:          make([]byte, 16),
		AttestationType: "none",
		Transports:      []string{"internal"},
		UserPresent:     true,
		UserVerified:    true,
	}
}

// Assert returns the PublicKeyCredential JSON a browser produces for
// navigator.credentials.get(): id / rawId, type, and a response holding
// clientDataJSON, authenticatorData (rpIdHash, UP, UV when uv is true,
// the incremented counter), the signature over
// authenticatorData || SHA-256(clientDataJSON), and userHandle when
// non-empty. Binary fields are base64url without padding.
func (a *Authenticator) Assert(t testing.TB, challenge []byte, origin string, userHandle []byte, uv bool) []byte {
	t.Helper()
	a.key.UserVerified = uv
	out, err := a.key.Assert(a.rpID, origin, challenge, userHandle)
	if err != nil {
		t.Fatalf("passkeytest: %v", err)
	}
	return out
}

// coseKey extracts the COSE public key from the attested credential data
// of a registration response: rpIdHash (32), flags (1), counter (4),
// AAGUID (16), credential ID length (2), credential ID, then the key.
func coseKey(t testing.TB, key *softkey.Key, rpID string) []byte {
	t.Helper()
	raw, err := key.Create(rpID, "https://"+rpID, make([]byte, 32))
	if err != nil {
		t.Fatalf("passkeytest: %v", err)
	}
	var created struct {
		Response struct {
			AttestationObject string `json:"attestationObject"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("passkeytest: parse registration response: %v", err)
	}
	attestation, err := base64.RawURLEncoding.DecodeString(created.Response.AttestationObject)
	if err != nil {
		t.Fatalf("passkeytest: decode attestation object: %v", err)
	}
	var obj struct {
		AuthData []byte `cbor:"authData"`
	}
	if err := cbor.Unmarshal(attestation, &obj); err != nil {
		t.Fatalf("passkeytest: decode attestation object: %v", err)
	}
	const idLenOffset = 32 + 1 + 4 + 16
	if len(obj.AuthData) < idLenOffset+2 {
		t.Fatalf("passkeytest: authenticator data too short")
	}
	start := idLenOffset + 2 + int(binary.BigEndian.Uint16(obj.AuthData[idLenOffset:]))
	if len(obj.AuthData) <= start {
		t.Fatalf("passkeytest: authenticator data carries no public key")
	}
	return append([]byte(nil), obj.AuthData[start:]...)
}

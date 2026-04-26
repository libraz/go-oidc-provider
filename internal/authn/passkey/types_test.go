package passkey_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
)

func sampleWebauthnCredential() webauthn.Credential {
	return webauthn.Credential{
		ID:              []byte{0x01, 0x02, 0x03, 0x04},
		PublicKey:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		AttestationType: "none",
		Transport: []protocol.AuthenticatorTransport{
			protocol.USB,
			protocol.Internal,
		},
		Flags: webauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: true,
			BackupState:    false,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00},
			SignCount:    42,
			CloneWarning: false,
			Attachment:   protocol.Platform,
		},
	}
}

func TestCredential_RoundTripPreservesEveryField(t *testing.T) {
	t.Parallel()

	original := sampleWebauthnCredential()
	c := passkey.FromWebauthnCredentialForTest(original)

	if !bytes.Equal(c.ID, original.ID) {
		t.Errorf("ID mismatch: got %x want %x", c.ID, original.ID)
	}
	if !bytes.Equal(c.PublicKey, original.PublicKey) {
		t.Errorf("PublicKey mismatch: got %x want %x", c.PublicKey, original.PublicKey)
	}
	if c.AttestationType != original.AttestationType {
		t.Errorf("AttestationType=%q want %q", c.AttestationType, original.AttestationType)
	}
	wantTransports := []string{string(protocol.USB), string(protocol.Internal)}
	if !reflect.DeepEqual(c.Transports, wantTransports) {
		t.Errorf("Transports=%v want %v", c.Transports, wantTransports)
	}
	if c.Flags.UserPresent != original.Flags.UserPresent {
		t.Errorf("Flags.UserPresent=%v want %v", c.Flags.UserPresent, original.Flags.UserPresent)
	}
	if c.Flags.UserVerified != original.Flags.UserVerified {
		t.Errorf("Flags.UserVerified=%v want %v", c.Flags.UserVerified, original.Flags.UserVerified)
	}
	if c.Flags.BackupEligible != original.Flags.BackupEligible {
		t.Errorf("Flags.BackupEligible=%v want %v", c.Flags.BackupEligible, original.Flags.BackupEligible)
	}
	if c.Flags.BackupState != original.Flags.BackupState {
		t.Errorf("Flags.BackupState=%v want %v", c.Flags.BackupState, original.Flags.BackupState)
	}
	if !bytes.Equal(c.Authenticator.AAGUID, original.Authenticator.AAGUID) {
		t.Errorf("Authenticator.AAGUID mismatch: got %x want %x", c.Authenticator.AAGUID, original.Authenticator.AAGUID)
	}
	if c.Authenticator.SignCount != original.Authenticator.SignCount {
		t.Errorf("Authenticator.SignCount=%d want %d", c.Authenticator.SignCount, original.Authenticator.SignCount)
	}
	if c.Authenticator.CloneWarning != original.Authenticator.CloneWarning {
		t.Errorf("Authenticator.CloneWarning=%v want %v", c.Authenticator.CloneWarning, original.Authenticator.CloneWarning)
	}
	if c.Authenticator.Attachment != string(original.Authenticator.Attachment) {
		t.Errorf("Authenticator.Attachment=%q want %q", c.Authenticator.Attachment, original.Authenticator.Attachment)
	}

	// Round-trip back: every field should survive.
	round := passkey.ToWebauthnCredentialForTest(c)

	if !bytes.Equal(round.ID, original.ID) {
		t.Errorf("round-trip ID mismatch")
	}
	if !bytes.Equal(round.PublicKey, original.PublicKey) {
		t.Errorf("round-trip PublicKey mismatch")
	}
	if round.AttestationType != original.AttestationType {
		t.Errorf("round-trip AttestationType mismatch")
	}
	if !reflect.DeepEqual(round.Transport, original.Transport) {
		t.Errorf("round-trip Transport mismatch: got %v want %v", round.Transport, original.Transport)
	}
	if round.Flags.UserPresent != original.Flags.UserPresent ||
		round.Flags.UserVerified != original.Flags.UserVerified ||
		round.Flags.BackupEligible != original.Flags.BackupEligible ||
		round.Flags.BackupState != original.Flags.BackupState {
		t.Errorf("round-trip Flags mismatch: got %+v want %+v", round.Flags, original.Flags)
	}
	if !bytes.Equal(round.Authenticator.AAGUID, original.Authenticator.AAGUID) {
		t.Errorf("round-trip AAGUID mismatch")
	}
	if round.Authenticator.SignCount != original.Authenticator.SignCount {
		t.Errorf("round-trip SignCount mismatch")
	}
	if round.Authenticator.CloneWarning != original.Authenticator.CloneWarning {
		t.Errorf("round-trip CloneWarning mismatch")
	}
	if round.Authenticator.Attachment != original.Authenticator.Attachment {
		t.Errorf("round-trip Attachment mismatch")
	}
}

func TestCredential_ConversionDefensivelyCopiesByteSlices(t *testing.T) {
	t.Parallel()

	original := sampleWebauthnCredential()
	c := passkey.FromWebauthnCredentialForTest(original)
	// Mutate the original after conversion — the project struct must
	// own its own backing arrays.
	original.ID[0] ^= 0xff
	original.PublicKey[0] ^= 0xff
	original.Authenticator.AAGUID[0] ^= 0xff

	if c.ID[0] == original.ID[0] {
		t.Errorf("ID shared backing array with source")
	}
	if c.PublicKey[0] == original.PublicKey[0] {
		t.Errorf("PublicKey shared backing array with source")
	}
	if c.Authenticator.AAGUID[0] == original.Authenticator.AAGUID[0] {
		t.Errorf("AAGUID shared backing array with source")
	}
}

func TestCredential_EmptyTransportsRoundTrip(t *testing.T) {
	t.Parallel()

	original := sampleWebauthnCredential()
	original.Transport = nil

	c := passkey.FromWebauthnCredentialForTest(original)
	if len(c.Transports) != 0 {
		t.Errorf("len(Transports)=%d want 0", len(c.Transports))
	}
	round := passkey.ToWebauthnCredentialForTest(c)
	if len(round.Transport) != 0 {
		t.Errorf("len(round.Transport)=%d want 0", len(round.Transport))
	}
}

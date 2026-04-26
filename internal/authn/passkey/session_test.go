package passkey_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
)

func sampleSessionData() webauthn.SessionData {
	return webauthn.SessionData{
		Challenge:            "Y2hhbGxlbmdlLWJ5dGVz",
		RelyingPartyID:       "id.example.com",
		UserID:               []byte("user-alice"),
		AllowedCredentialIDs: [][]byte{{0x01}, {0x02, 0x03}},
		Expires:              time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		UserVerification:     protocol.VerificationPreferred,
	}
}

func TestSession_EncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	src := sampleSessionData()
	s := passkey.EncodeSessionForTest(src)

	if s.Challenge != src.Challenge {
		t.Errorf("Challenge=%q want %q", s.Challenge, src.Challenge)
	}
	if !bytes.Equal(s.UserID, src.UserID) {
		t.Errorf("UserID mismatch")
	}
	if !reflect.DeepEqual(s.AllowedCredentialIDs, src.AllowedCredentialIDs) {
		t.Errorf("AllowedCredentialIDs mismatch: got %v want %v", s.AllowedCredentialIDs, src.AllowedCredentialIDs)
	}
	if !s.Expires.Equal(src.Expires) {
		t.Errorf("Expires=%v want %v", s.Expires, src.Expires)
	}
	if s.UserVerification != string(src.UserVerification) {
		t.Errorf("UserVerification=%q want %q", s.UserVerification, src.UserVerification)
	}

	round := passkey.DecodeSessionForTest(s)
	if round.Challenge != src.Challenge {
		t.Errorf("round Challenge mismatch")
	}
	if !bytes.Equal(round.UserID, src.UserID) {
		t.Errorf("round UserID mismatch")
	}
	if !reflect.DeepEqual(round.AllowedCredentialIDs, src.AllowedCredentialIDs) {
		t.Errorf("round AllowedCredentialIDs mismatch")
	}
	if !round.Expires.Equal(src.Expires) {
		t.Errorf("round Expires=%v want %v", round.Expires, src.Expires)
	}
	if round.UserVerification != src.UserVerification {
		t.Errorf("round UserVerification=%q want %q", round.UserVerification, src.UserVerification)
	}
}

func TestSession_DefensivelyClonesByteSlices(t *testing.T) {
	t.Parallel()

	src := sampleSessionData()
	s := passkey.EncodeSessionForTest(src)
	// Mutate the original UserID and AllowedCredentialIDs; the
	// session value must own its own backing arrays.
	src.UserID[0] ^= 0xff
	src.AllowedCredentialIDs[0][0] ^= 0xff

	if s.UserID[0] == src.UserID[0] {
		t.Errorf("UserID shared backing array with source")
	}
	if s.AllowedCredentialIDs[0][0] == src.AllowedCredentialIDs[0][0] {
		t.Errorf("AllowedCredentialIDs shared backing array with source")
	}
}

func TestSession_JSONRoundTripPreservesEveryField(t *testing.T) {
	t.Parallel()

	original := passkey.Session{
		Challenge:            "Y2hhbGxlbmdlLWJ5dGVz",
		UserID:               []byte("user-alice"),
		AllowedCredentialIDs: [][]byte{{0x01, 0x02}, {0x03, 0x04, 0x05}},
		Expires:              time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
		UserVerification:     "preferred",
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var round passkey.Session
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if round.Challenge != original.Challenge {
		t.Errorf("Challenge=%q want %q", round.Challenge, original.Challenge)
	}
	if !bytes.Equal(round.UserID, original.UserID) {
		t.Errorf("UserID mismatch")
	}
	if !reflect.DeepEqual(round.AllowedCredentialIDs, original.AllowedCredentialIDs) {
		t.Errorf("AllowedCredentialIDs mismatch: got %v want %v", round.AllowedCredentialIDs, original.AllowedCredentialIDs)
	}
	if !round.Expires.Equal(original.Expires) {
		t.Errorf("Expires=%v want %v", round.Expires, original.Expires)
	}
	// Expires MUST be in UTC after the round-trip.
	if loc := round.Expires.Location(); loc != time.UTC {
		t.Errorf("Expires.Location=%v want UTC", loc)
	}
	if round.UserVerification != original.UserVerification {
		t.Errorf("UserVerification=%q want %q", round.UserVerification, original.UserVerification)
	}
}

func TestSession_JSONRoundTripNormalisesTimezone(t *testing.T) {
	t.Parallel()

	jst, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skipf("Asia/Tokyo unavailable: %v", err)
	}
	original := passkey.Session{
		Challenge: "abc",
		Expires:   time.Date(2026, 4, 26, 21, 0, 0, 0, jst),
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var round passkey.Session
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if round.Expires.Location() != time.UTC {
		t.Errorf("Expires.Location=%v want UTC", round.Expires.Location())
	}
	if !round.Expires.Equal(original.Expires) {
		t.Errorf("Expires instant changed across round-trip: got %v want %v", round.Expires, original.Expires)
	}
}

func TestSession_JSONRoundTripEmptyOptionalFields(t *testing.T) {
	t.Parallel()

	// A registration session has no AllowedCredentialIDs and may
	// have empty UserVerification.
	original := passkey.Session{
		Challenge: "Y2hhbGxlbmdl",
		UserID:    []byte("user"),
		Expires:   time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var round passkey.Session
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(round.AllowedCredentialIDs) != 0 {
		t.Errorf("AllowedCredentialIDs=%v want empty", round.AllowedCredentialIDs)
	}
	if round.UserVerification != "" {
		t.Errorf("UserVerification=%q want empty", round.UserVerification)
	}
}

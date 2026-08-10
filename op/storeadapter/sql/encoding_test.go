//nolint:testpackage // tests reference unexported encodeObjectArray / decodeObjectArray.
package oidcsql

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
)

// TestObjectArray_RoundTrip_NumberFidelity pins that the
// authorization_details column round-trips a large integer through
// encode/decode without the lossy float64 widening encoding/json applies
// by default. decodeObjectArray uses json.Decoder+UseNumber so a payment
// amount that exceeds the float64 integer-exact range (2^53) comes back as
// a json.Number carrying the exact decimal string rather than "1e17".
func TestObjectArray_RoundTrip_NumberFidelity(t *testing.T) {
	t.Parallel()

	const bigAmount = "100000000000000001" // > 2^53, not float64-exact.
	in := []map[string]any{
		{"type": "payment_initiation", "amount": json.Number(bigAmount)},
	}

	encoded, err := encodeObjectArray(in)
	if err != nil {
		t.Fatalf("encodeObjectArray: %v", err)
	}
	out, err := decodeObjectArray(encoded)
	if err != nil {
		t.Fatalf("decodeObjectArray: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("decoded length=%d want 1", len(out))
	}
	amount, ok := out[0]["amount"].(json.Number)
	if !ok {
		t.Fatalf("amount type=%T want json.Number (default float64 decode loses precision)", out[0]["amount"])
	}
	if amount.String() != bigAmount {
		t.Errorf("amount=%q want %q", amount.String(), bigAmount)
	}
}

// TestObjectArray_RoundTrip_Nil pins that a nil slice survives the
// round-trip as nil (the "no authorization_details" shape), mirroring the
// inmem reference.
func TestObjectArray_RoundTrip_Nil(t *testing.T) {
	t.Parallel()

	encoded, err := encodeObjectArray(nil)
	if err != nil {
		t.Fatalf("encodeObjectArray(nil): %v", err)
	}
	out, err := decodeObjectArray(encoded)
	if err != nil {
		t.Fatalf("decodeObjectArray: %v", err)
	}
	if out != nil {
		t.Errorf("decoded=%v want nil", out)
	}
}

func TestJSONEncoders_RejectNonJSONValues(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		fn   func() error
	}{
		{"map function", func() error { _, err := encodeMap(map[string]any{"bad": func() {}}); return err }},
		{"map NaN", func() error { _, err := encodeMap(map[string]any{"bad": math.NaN()}); return err }},
		{"object array channel", func() error { _, err := encodeObjectArray([]map[string]any{{"bad": make(chan int)}}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.fn(); !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("encoder error=%v, want ErrInvalidJSON", err)
			}
		})
	}
}

// TestMap_RoundTrip_NumberFidelity pins the same guarantee for the
// claim-map columns (user claims, grant claims, refresh-token extras).
// These feed ID tokens and /userinfo directly, so a value widened to
// float64 here is a wrong number delivered to the relying party — and
// because the rounding is deterministic, every read agrees with every
// other read and nothing downstream can notice.
func TestMap_RoundTrip_NumberFidelity(t *testing.T) {
	t.Parallel()

	const bigID = "9007199254740993" // 2^53 + 1: the smallest integer float64 cannot hold.
	in := map[string]any{"account_id": json.Number(bigID)}

	encoded, err := encodeMap(in)
	if err != nil {
		t.Fatalf("encodeMap: %v", err)
	}
	out, err := decodeMap(encoded)
	if err != nil {
		t.Fatalf("decodeMap: %v", err)
	}
	got, ok := out["account_id"].(json.Number)
	if !ok {
		t.Fatalf("account_id type=%T want json.Number (default float64 decode loses precision)", out["account_id"])
	}
	if got.String() != bigID {
		t.Errorf("account_id=%q want %q", got.String(), bigID)
	}

	// The wire form is what the RP actually receives, so assert on it
	// too: a json.Number that re-marshals to scientific notation would
	// satisfy the check above and still change the claim.
	reencoded, err := encodeMap(out)
	if err != nil {
		t.Fatalf("re-encodeMap: %v", err)
	}
	if want := `{"account_id":` + bigID + `}`; string(reencoded) != want {
		t.Errorf("re-encoded=%s want %s", reencoded, want)
	}
}

// TestMap_RoundTrip_Nil pins that a nil map survives as nil (the "no
// claims" shape), mirroring the inmem reference.
func TestMap_RoundTrip_Nil(t *testing.T) {
	t.Parallel()

	encoded, err := encodeMap(nil)
	if err != nil {
		t.Fatalf("encodeMap(nil): %v", err)
	}
	out, err := decodeMap(encoded)
	if err != nil {
		t.Fatalf("decodeMap: %v", err)
	}
	if out != nil {
		t.Errorf("decoded=%v want nil", out)
	}
}

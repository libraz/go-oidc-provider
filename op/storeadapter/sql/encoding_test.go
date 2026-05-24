//nolint:testpackage // tests reference unexported encodeObjectArray / decodeObjectArray.
package oidcsql

import (
	"encoding/json"
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

	encoded := encodeObjectArray(in)
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

	out, err := decodeObjectArray(encodeObjectArray(nil))
	if err != nil {
		t.Fatalf("decodeObjectArray: %v", err)
	}
	if out != nil {
		t.Errorf("decoded=%v want nil", out)
	}
}

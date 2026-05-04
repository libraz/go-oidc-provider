package op_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// TestWithDeviceCodeGrant_AcceptsValidConfig confirms the dedicated
// opt-in option constructs without error against the inmem reference
// store (which ships a non-nil [store.DeviceCodeStore]).
func TestWithDeviceCodeGrant_AcceptsValidConfig(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithDeviceCodeGrant(),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
}

// TestWithDeviceCodeGrant_RejectsMissingSubstore pins the
// substore-presence gate. stubStore intentionally returns nil from
// DeviceCodes so an embedder who forgets to wire the substore sees
// the construction error rather than a runtime nil panic on the
// first /device_authorization POST.
func TestWithDeviceCodeGrant_RejectsMissingSubstore(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithDeviceCodeGrant(),
	)...)
	if err == nil {
		t.Fatal("expected error when DeviceCodes substore is nil")
	}
	if !strings.Contains(err.Error(), "DeviceCodes") {
		t.Errorf("err = %v, want it to mention DeviceCodes", err)
	}
}

// TestWithGrants_DeviceCode_RejectsMissingSubstore mirrors
// [TestWithDeviceCodeGrant_RejectsMissingSubstore] for the alternative
// entry point: an embedder that activates the device_code grant via
// [op.WithGrants] (rather than the dedicated [op.WithDeviceCodeGrant]
// option) must still see the construction error when the configured
// Store does not provide a DeviceCodes substore. Prior to the fix
// this path bypassed the gate and the runtime reached a nil-substore
// Save on the first /device_authorization POST.
func TestWithGrants_DeviceCode_RejectsMissingSubstore(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithGrants(grant.DeviceCode),
	)...)
	if err == nil {
		t.Fatal("expected error when DeviceCodes substore is nil under WithGrants(grant.DeviceCode)")
	}
	if !strings.Contains(err.Error(), "DeviceCodes") {
		t.Errorf("err = %v, want it to mention DeviceCodes", err)
	}
}

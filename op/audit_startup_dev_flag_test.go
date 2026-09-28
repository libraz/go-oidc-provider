package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestStartupProfile_RecordsInsecureBackchannelLogoutForDev pins that
// the dev-only back-channel relaxation is visible on the audit stream,
// not only on the operational logger, and reads false when unset.
func TestStartupProfile_RecordsInsecureBackchannelLogoutForDev(t *testing.T) {
	t.Parallel()

	const key = "insecure_backchannel_logout_for_dev"

	on := captureStartupProfile(t, op.WithAllowInsecureBackchannelLogoutForDev())
	if got, ok := on.Extras[key]; !ok || got != true {
		t.Fatalf("%s = %v (present=%v) with the option set, want true", key, got, ok)
	}

	off := captureStartupProfile(t)
	if got, ok := off.Extras[key]; !ok || got != false {
		t.Fatalf("%s = %v (present=%v) without the option, want false", key, got, ok)
	}
}

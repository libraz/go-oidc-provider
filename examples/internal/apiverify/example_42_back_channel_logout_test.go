//go:build apiverify

package apiverify

import "testing"

// 42 boots an OP plus an RP stub that receives logout tokens; the
// discovery probe confirms the OP came up (the logout delivery itself needs
// a seeded session, out of scope for a boot smoke).
func TestExample42BackChannelLogout(t *testing.T) {
	runDiscovery(t, "../../42-back-channel-logout", "http://127.0.0.1:8080")
}

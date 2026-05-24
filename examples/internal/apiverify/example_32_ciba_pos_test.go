//go:build apiverify

package apiverify

import "testing"

// 32 runs a complete CIBA backchannel round-trip (bc-authorize → device
// approval → token poll → id_token decode) in-process and exits 0; a
// non-zero exit means the round-trip broke.
func TestExample32CIBAPOS(t *testing.T) {
	runExitZero(t, "../../32-ciba-pos")
}

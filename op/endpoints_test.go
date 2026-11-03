package op_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestEndpoints_RejectsOverrideOccupyingConcatenatedDiscoveryPath pins that an
// endpoint override may not take the path a relying party derives by appending
// the well-known suffix to a path-carrying issuer. Serving the OP's own
// endpoints from that URL would leave conformant discovery unreachable, so the
// configuration is refused at construction time.
func TestEndpoints_RejectsOverrideOccupyingConcatenatedDiscoveryPath(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithIssuer(validIssuer+"/tenant"),
		op.WithMountPrefix("/"),
		op.WithEndpoints(op.Endpoints{
			UserInfo: "/.well-known/openid-configuration",
		}),
	)...)
	if err == nil {
		t.Fatal("op.New accepted an endpoint override occupying the concatenated discovery path")
	}
	if !strings.Contains(err.Error(), "/tenant/.well-known/openid-configuration") {
		t.Errorf("error %q does not name the contested path", err)
	}
}

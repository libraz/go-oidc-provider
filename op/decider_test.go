package op_test

import "github.com/libraz/go-oidc-provider/op"

// Compile-time confirmation that every concrete [op.Decision]
// satisfies the sealed interface. The orchestrator's switch-on-type
// evaluation relies on the four cases being total; if a future change
// accidently breaks the marker method, this block fails to compile.
var (
	_ op.Decision = op.Allow{}
	_ op.Decision = op.Pass{}
	_ op.Decision = op.Require{}
	_ op.Decision = op.Deny{}
)

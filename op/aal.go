package op

import "github.com/libraz/go-oidc-provider/internal/authn"

// AAL is an alias for the canonical [authn.AAL] type. See the
// authn-package documentation for the full semantics; the op package
// re-exports it so embedders write `op.AAL` without reaching into
// internal/.
//
// Stable since v1.0.
type AAL = authn.AAL

// AAL constants re-exported from the authn package. See
// [authn.AAL0] etc. for the full per-level documentation.
const (
	AAL0 = authn.AAL0
	AAL1 = authn.AAL1
	AAL2 = authn.AAL2
	AAL3 = authn.AAL3
)

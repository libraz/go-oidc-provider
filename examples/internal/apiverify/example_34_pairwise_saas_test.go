//go:build apiverify

package apiverify

import "testing"

// 34 derives pairwise subjects for two sectors and asserts cross-sector
// distinctness / same-sector stability in-process, printing "✓ self-verify"
// then exiting.
func TestExample34PairwiseSaaS(t *testing.T) {
	runSelfVerify(t, "../../34-pairwise-saas")
}

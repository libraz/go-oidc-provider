package scenarios_test

// Catalog: test/scenarios/catalog/client_id_uri.yaml (CIDU-NNN)
// Spec:
//   - RFC 7591 §3 — Client Information Response (registration_client_uri)
//   - RFC 7592 — Dynamic Client Registration Management Protocol
//   - RFC 3986 §2.1 — Percent-Encoding
//   - RFC 6749 §2.2 — client_id character set
//
// All CIDU rows are OOS for v1.0: the OP mints client_ids via
// base64.RawURLEncoding of 16 random bytes (URL-safe alphabet
// [A-Za-z0-9_-]), so no character ever needs percent-encoding and the
// "URL-form client_id" axis collapses. v1.0 also does not accept
// user-supplied client_ids and exposes no clientIdValidation knob; see
// catalog out_of_scope_reason on each row.

import "testing"

// TestScenario_CIDU_01_PercentEncodeReservedChars is OOS — see catalog
// out_of_scope_reason.
func TestScenario_CIDU_01_PercentEncodeReservedChars(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIDU-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CIDU_02_NoQueryStringAppended is OOS — see catalog
// out_of_scope_reason.
func TestScenario_CIDU_02_NoQueryStringAppended(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIDU-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CIDU_03_GetAcceptsEncodedPath is OOS — see catalog
// out_of_scope_reason.
func TestScenario_CIDU_03_GetAcceptsEncodedPath(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIDU-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CIDU_04_PutMatchesDecodedPathClientID is OOS — see
// catalog out_of_scope_reason.
func TestScenario_CIDU_04_PutMatchesDecodedPathClientID(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIDU-04 (see catalog out_of_scope_reason)")
}

// TestScenario_CIDU_05_DeleteAcceptsEncodedPath is OOS — see catalog
// out_of_scope_reason.
func TestScenario_CIDU_05_DeleteAcceptsEncodedPath(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIDU-05 (see catalog out_of_scope_reason)")
}

// TestScenario_CIDU_LC_01_FullLifecycleRoundTrip is OOS — see catalog
// out_of_scope_reason.
func TestScenario_CIDU_LC_01_FullLifecycleRoundTrip(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIDU-LC-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CIDU_LC_02_RegeneratedURIObeysEncoding is OOS — see
// catalog out_of_scope_reason.
func TestScenario_CIDU_LC_02_RegeneratedURIObeysEncoding(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIDU-LC-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CIDU_LC_03_DistinguishCIDUFromCIMD is OOS — see catalog
// out_of_scope_reason.
func TestScenario_CIDU_LC_03_DistinguishCIDUFromCIMD(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIDU-LC-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CIDU_CHR_01_ClientIDLimitedToVSCHAR is OOS — see catalog
// out_of_scope_reason.
func TestScenario_CIDU_CHR_01_ClientIDLimitedToVSCHAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIDU-CHR-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CIDU_CHR_02_ColonSlashOnlyInURLForm is OOS — see catalog
// out_of_scope_reason.
func TestScenario_CIDU_CHR_02_ColonSlashOnlyInURLForm(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIDU-CHR-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CIDU_CHR_03_LocationHeaderUsesSameEncoding is OOS — see
// catalog out_of_scope_reason.
func TestScenario_CIDU_CHR_03_LocationHeaderUsesSameEncoding(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIDU-CHR-03 (see catalog out_of_scope_reason)")
}

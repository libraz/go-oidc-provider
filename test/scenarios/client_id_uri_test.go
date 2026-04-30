package scenarios_test

// Catalog: test/scenarios/catalog/client_id_uri.yaml (CIDU-NNN)
// Spec:
//   - RFC 7591 §3 — Client Information Response (registration_client_uri)
//   - RFC 7592 — Dynamic Client Registration Management Protocol
//   - RFC 3986 §2.1 — Percent-Encoding
//   - RFC 6749 §2.2 — client_id character set

import "testing"

func TestScenario_CIDU_01_PercentEncodeReservedChars(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIDU-01")
}

func TestScenario_CIDU_02_NoQueryStringAppended(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIDU-02")
}

func TestScenario_CIDU_03_GetAcceptsEncodedPath(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIDU-03")
}

func TestScenario_CIDU_04_PutMatchesDecodedPathClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIDU-04")
}

func TestScenario_CIDU_05_DeleteAcceptsEncodedPath(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIDU-05")
}

func TestScenario_CIDU_LC_01_FullLifecycleRoundTrip(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIDU-LC-01")
}

func TestScenario_CIDU_LC_02_RegeneratedURIObeysEncoding(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIDU-LC-02")
}

func TestScenario_CIDU_LC_03_DistinguishCIDUFromCIMD(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIDU-LC-03")
}

func TestScenario_CIDU_CHR_01_ClientIDLimitedToVSCHAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIDU-CHR-01")
}

func TestScenario_CIDU_CHR_02_ColonSlashOnlyInURLForm(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIDU-CHR-02")
}

func TestScenario_CIDU_CHR_03_LocationHeaderUsesSameEncoding(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIDU-CHR-03")
}

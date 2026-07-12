package introspectendpoint

// PreferJWTForTest exposes [preferJWT] to the external _test package so
// the negotiation matrix can be exercised without standing up an HTTP
// server. The helper is test-only and never reaches the public API.
func PreferJWTForTest(accept string) bool { return preferJWT(accept) }

// CloneStringMapForTest exposes [cloneStringMap] to the external _test
// package so defensive-copy semantics can be asserted without coupling a
// handler test to access-token claim construction.
func CloneStringMapForTest(in map[string]string) map[string]string { return cloneStringMap(in) }

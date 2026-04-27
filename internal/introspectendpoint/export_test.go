package introspectendpoint

// PreferJWTForTest exposes [preferJWT] to the external _test package so
// the negotiation matrix can be exercised without standing up an HTTP
// server. The helper is test-only and never reaches the public API.
func PreferJWTForTest(accept string) bool { return preferJWT(accept) }

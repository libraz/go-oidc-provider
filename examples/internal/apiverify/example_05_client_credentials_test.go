//go:build apiverify

package apiverify

import "testing"

// 05 is a machine-to-machine OP: no end user, no browser. The grant itself
// is the deliverable, so the smoke calls the token endpoint with the
// seeded confidential client and asserts a bearer token is issued.
func TestExample05ClientCredentials(t *testing.T) {
	runClientCredentials(t, "../../05-client-credentials",
		"http://127.0.0.1:8080",
		"backend-service", "cc-demo-secret-rotate-me", "api:read")
}

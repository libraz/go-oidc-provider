//go:build browserverify

package browserverify

import (
	"strings"
	"testing"
	"time"
)

// 07-mysql-store runs the ordinary password + consent round-trip, but
// every substore behind it — durable and volatile alike — is the SQL
// adapter against a real MySQL. That makes this the only case in the
// suite that exercises the adapter's full substore set on the path a
// browser actually takes, rather than through the adapter's own
// testcontainers-go contract suite.
//
// Like the reference application, the example needs an engine, so the
// case brings up its compose stack instead of calling startExample. It
// skips without Docker unless BROWSERVERIFY_REQUIRED=1.
func TestExample07MySQLStore(t *testing.T) {
	chrome := requireChrome(t)
	compose := requireCompose(t)
	executedBrowserCases.Add(1)

	stop := startComposeStack(t, compose, "examples/07-mysql-store/compose.yaml",
		"goidc-example07-verify", "op")
	defer stop()

	// MySQL's own boot plus schema migration is comparable to the
	// DynamoDB emulator case, and the RP only listens once its discovery
	// call succeeds — so a ready RP already implies a ready OP.
	waitForReadyWithin(t, defaultRPBase+"/", 120*time.Second)

	spec := exampleSpec{
		dir:      "../../07-mysql-store",
		username: "demo",
		password: "demo",
		wantSub:  "demo-user",
	}

	// Same one-retry allowance as runRoundTrip: a dropped CDP navigation
	// event must not turn a docker-backed gate flaky.
	var body string
	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		body, err = driveLogin(chrome, spec)
		if err == nil {
			break
		}
		t.Logf("attempt %d/2 failed: %v", attempt, err)
	}
	if err != nil {
		t.Fatalf("browser round-trip: %v", err)
	}

	for _, want := range []string{
		`"iss": "` + defaultOPIssuer + `"`,
		`"sub": "` + spec.wantSub + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/me body missing %q; got:\n%s", want, body)
		}
	}
	t.Logf("round-trip OK on MySQL: /me rendered iss=%s sub=%s", defaultOPIssuer, spec.wantSub)
}

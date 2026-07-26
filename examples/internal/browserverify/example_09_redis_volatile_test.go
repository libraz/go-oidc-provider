//go:build browserverify

package browserverify

import (
	"strings"
	"testing"
	"time"
)

// 09-redis-volatile runs the ordinary password + consent round-trip
// over a split store: durable substores on a real MySQL, volatile
// substores (sessions, interactions, consumed JTIs) on a real Redis.
// That makes this the only case in the suite that proves the two
// adapters cooperate correctly across a single login on the path a
// browser actually takes — a session or interaction record that fails
// to round-trip through Redis surfaces here as a login that cannot
// complete rather than as a failing unit assertion.
//
// Like the reference application, the example needs both engines, so
// the case brings up its compose stack instead of calling startExample.
// It skips without Docker unless BROWSERVERIFY_REQUIRED=1.
func TestExample09RedisVolatile(t *testing.T) {
	chrome := requireChrome(t)
	compose := requireCompose(t)
	executedBrowserCases.Add(1)

	stop := startComposeStack(t, compose, "examples/09-redis-volatile/compose.yaml",
		"goidc-example09-verify", "op")
	defer stop()

	// Two engines (MySQL and Redis) to bring healthy before the OP even
	// starts, so this gets more budget than the single-engine cases; the
	// RP only listens once its discovery call succeeds, so a ready RP
	// already implies a ready OP.
	waitForReadyWithin(t, defaultRPBase+"/", 150*time.Second)

	spec := exampleSpec{
		dir:      "../../09-redis-volatile",
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
	t.Logf("round-trip OK on MySQL+Redis: /me rendered iss=%s sub=%s", defaultOPIssuer, spec.wantSub)
}

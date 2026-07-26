//go:build browserverify

package browserverify

import (
	"strings"
	"testing"
	"time"
)

// 17-spa-composite-store drives the same MySQL-durable + Redis-volatile
// split as 09-redis-volatile, but through the SPA interaction driver
// (op.WithSPAUI) instead of the default server-rendered forms. That
// makes this the only case in the suite that exercises the SPA prompt
// contract itself over that composite split: the interaction record the
// bundle's JSON POSTs advance has to survive the same Redis round-trip
// the server-rendered driver takes in 09, and a defect specific to that
// seam would not show up on either case alone.
//
// Like the reference application, the example needs both engines, so
// the case brings up its compose stack instead of calling startExample.
// It skips without Docker unless BROWSERVERIFY_REQUIRED=1.
func TestExample17SPACompositeStore(t *testing.T) {
	chrome := requireChrome(t)
	compose := requireCompose(t)
	executedBrowserCases.Add(1)

	stop := startComposeStack(t, compose, "examples/17-spa-composite-store/compose.yaml",
		"goidc-example17-verify", "op")
	defer stop()

	// Two engines (MySQL and Redis) to bring healthy before the OP even
	// starts, so this gets more budget than the single-engine cases; the
	// RP only listens once its discovery call succeeds, so a ready RP
	// already implies a ready OP.
	waitForReadyWithin(t, defaultRPBase+"/", 150*time.Second)

	spec := exampleSpec{
		dir:      "../../17-spa-composite-store",
		username: "demo",
		password: "demo",
		wantSub:  "demo-user",
		spa:      true,
	}

	// Same one-retry allowance as runRoundTrip: a dropped CDP navigation
	// event must not turn a docker-backed gate flaky.
	var body string
	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		body, err = driveSPALogin(chrome, spec, "", nil)
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
	t.Logf("round-trip OK on SPA over MySQL+Redis: /me rendered iss=%s sub=%s", defaultOPIssuer, spec.wantSub)
}

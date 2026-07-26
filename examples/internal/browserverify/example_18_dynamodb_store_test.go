//go:build browserverify

package browserverify

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 18-dynamodb-store runs the ordinary password + consent round-trip, but
// every substore behind it is DynamoDB. That makes this the only case in
// the suite that exercises the adapter's store.Transactional emulation
// against a real engine on the path a browser actually takes: grant
// creation and authorization-code persistence commit through one
// buffered TransactWriteItems, and a defect there surfaces as a login
// that cannot complete rather than as a failing unit assertion.
//
// Like the reference application, the example needs an engine, so the
// case brings up its compose stack instead of calling startExample. It
// skips without Docker unless BROWSERVERIFY_REQUIRED=1.
func TestExample18DynamoDBStore(t *testing.T) {
	chrome := requireChrome(t)
	compose := requireCompose(t)
	executedBrowserCases.Add(1)

	stop := startComposeStack(t, compose, "examples/18-dynamodb-store/compose.yaml",
		"goidc-example18-verify", "op")
	defer stop()

	// The emulator's JVM start plus table creation is slower than a plain
	// example boot, and the RP only listens once its discovery call
	// succeeds — so a ready RP already implies a ready OP.
	waitForReadyWithin(t, defaultRPBase+"/", 120*time.Second)

	spec := exampleSpec{
		dir:      "../../18-dynamodb-store",
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
	t.Logf("round-trip OK on DynamoDB: /me rendered iss=%s sub=%s", defaultOPIssuer, spec.wantSub)
}

// startComposeStack brings a compose project up from a repo-relative file
// and returns its teardown. The teardown removes volumes as well as
// containers so the next run starts from an empty backend, and dumps the
// named service's log when the calling test failed — a stack that came up
// but misbehaved is otherwise opaque once the containers are gone.
//
// The project name is explicit so a stack cannot adopt containers a
// developer started by hand from the same file.
func startComposeStack(t *testing.T, docker, relComposeFile, project, logService string) func() {
	t.Helper()

	composeFile := filepath.Join(repoRoot(t), filepath.FromSlash(relComposeFile))
	base := []string{"compose", "-f", composeFile, "-p", project}

	run := func(timeout time.Duration, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return exec.CommandContext(ctx, docker, append(base, args...)...).CombinedOutput()
	}

	down := func() {
		if out, err := run(2*time.Minute, "down", "-v", "--remove-orphans"); err != nil {
			t.Logf("compose down: %v\n%s", err, out)
		}
	}
	// Clear anything an interrupted run left behind before building, so the
	// new containers cannot come up onto a stale volume.
	down()

	if out, err := run(10*time.Minute, "up", "-d", "--build"); err != nil {
		down()
		t.Fatalf("compose up: %v\n%s", err, out)
	}
	return func() {
		if t.Failed() {
			if out, err := run(time.Minute, "logs", "--no-color", logService); err == nil {
				t.Logf("%s log:\n%s", logService, out)
			}
		}
		down()
	}
}

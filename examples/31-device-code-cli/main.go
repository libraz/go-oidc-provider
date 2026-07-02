//go:build example

// Example 31-device-code-cli demonstrates the RFC 8628
// device-authorization grant: an OP with [op.WithDeviceCodeGrant]
// enabled and an in-process simulated CLI client that drives the
// terminal-side ceremony — POST /device_authorization, render the
// user_code on stdout, poll /token honouring authorization_pending
// and slow_down, and decode the resulting id_token. The realistic
// use case is a TV / IoT / CLI tool that needs OAuth tokens but
// cannot host an HTTP listener for redirect-URI delivery, so the
// user authorises the device on a secondary device (phone /
// laptop) by typing a short user_code into a verification page.
//
// Run with the example build tag:
//
//	(cd examples/31-device-code-cli && go run -tags example .)
//
// The example is self-contained: a single binary stands up the OP
// on :8089, runs an in-process self-verify probe against an
// httptest server first, then drives the user-facing CLI flow
// against the listener. End-to-end runtime is under five seconds.
//
// The codebase is split by role across this directory:
//
//   - main.go   — entrypoint, package godoc, two-phase run().
//   - op.go     — OP-side wiring: buildProvider seeds the user,
//     enables [op.WithDeviceCodeGrant], and registers the public
//     CLI client. Both the probe and the CLI flow call the same
//     helper.
//   - cli.go    — terminal-side simulated CLI: device_authorization
//     POST, polling loop with §3.5 retry classification, user_code
//     panel render, id_token decode, plus the discovery readiness
//     poll the CLI uses before its first request.
//   - device.go — the authentication-device simulator: a goroutine
//     that mimics the user approving the user_code on a phone.
//   - probe.go  — self-verify probe: httptest server + happy-path
//     wire round-trip the example exits 1 on if it regresses.
//
// What the run prints, in order:
//
//  1. "self-verify: device-code round-trip OK" — the in-process
//     probe asserted POST /device_authorization → Approve →
//     POST /token (grant_type=device_code) yields an access_token.
//  2. "[op] listening on 127.0.0.1:8089" — the OP banner.
//  3. The boxed user_code panel the CLI would render on a TV
//     screen; alongside, the verification_uri_complete shortcut.
//  4. "[cli] poll #N -> authorization_pending" or
//     "[cli] poll #N -> 200 OK" — the polling loop. The first poll
//     observes the pending record while a goroutine simulates the
//     user approving the request on a second device.
//  5. "[cli] id_token sub=user-alice aud=cli-tool" — the decoded
//     claims confirming the round-trip.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Verification page: this example fakes the user's browser
//     approval by calling DeviceCodeStore.Approve directly. A real
//     deployment renders a verification page (mounted by the
//     embedder, not the library) that authenticates the user, asks
//     them to type the user_code, displays the requested scopes,
//     and calls Approve / Deny on the substore via an
//     embedder-owned handler.
//   - Brute-force lockout: the verification page is responsible
//     for IncrementUserCodeStrike + Deny("user_code_lockout") on
//     repeated mismatches; the library ships the substore method
//     but not the policy.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"
)

const (
	opAddr   = "127.0.0.1:8089"
	issuer   = "http://" + opAddr
	clientID = "cli-tool"

	// demoSubject is the OP-internal stable identifier the simulated
	// browser approval stamps on the device-code record. The id_token
	// "sub" claim mirrors this value.
	demoSubject = "user-alice"

	// deviceCodeGrantURN is the RFC 8628 §3.4 grant_type wire form.
	deviceCodeGrantURN = "urn:ietf:params:oauth:grant-type:device_code"

	// Default endpoint paths relative to the library default mount
	// prefix ("/oidc"). The CLI side uses these absolute paths to
	// build wire requests.
	deviceAuthPath = "/oidc/device_authorization"
	tokenPath      = "/oidc/token"

	// Demo cadence values. The CLI honours the OP's advertised
	// `interval` (5s by default per RFC 8628 §3.5 / ADR 0031 §Q3),
	// so the approval is scheduled to land between the first and
	// second poll and the timeout sits comfortably above one full
	// poll cycle. A real CLI MUST observe the advertised interval
	// or the OP escalates to slow_down and doubles its expectation
	// for every subsequent offence.
	demoApprovalDelay = 1500 * time.Millisecond
	demoPollTimeout   = 30 * time.Second

	// fallbackPollInterval is the cadence the CLI uses if the OP's
	// /device_authorization response carried a zero or missing
	// interval. The library default is 5s; mirroring it keeps a
	// demo that hits an unusual configuration from busy-spinning.
	fallbackPollInterval = 5 * time.Second
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("device-code example failed", slog.String("err", err.Error()))
		fmt.Fprintf(os.Stderr, "✗ %s\n", err.Error())
		os.Exit(1)
	}
}

// run owns the example's two-phase shape: a self-verify probe
// against an httptest server (so a regression in the public API
// surfaces before any listener binds) followed by the user-facing
// CLI flow against a real :8089 listener. Errors propagate to
// main() which prints a single-line "✗ <reason>" and exits 1.
func run(logger *slog.Logger) error {
	if err := selfVerify(logger); err != nil {
		return fmt.Errorf("self-verify: %w", err)
	}
	fmt.Println("✓ self-verify: device-code round-trip OK")
	return runCLIFlow(logger)
}

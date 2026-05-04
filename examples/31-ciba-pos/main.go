//go:build example

// Example 31-ciba-pos demonstrates a complete OpenID Connect Client-
// Initiated Backchannel Authentication Flow (CIBA Core 1.0) round-trip
// in poll mode: an OP with [op.WithCIBA] enabled, a [op.HintResolver]
// that maps a login_hint to a stable subject, and an in-process
// Relying Party that posts to /bc-authorize, simulates the embedder's
// authentication device approving the request, and polls /token until
// the OP issues an access_token + id_token.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/31-ciba-pos
//
// The example is self-contained: a single binary stands up the OP on
// :8080, drives the CIBA wire protocol against itself, decodes the
// resulting id_token, and exits 0. End-to-end runtime is under five
// seconds (one second between polls).
//
// The codebase is split by role across this directory:
//
//   - main.go   — entrypoint, package godoc, the high-level
//     orchestration sequence (build → listen → bc-authorize →
//     device approve → poll → decode).
//   - op.go     — OP-side wiring: buildProvider with [op.WithCIBA]
//     enabled and the demo HintResolver.
//   - rp.go     — POS-terminal-side RP: bc-authorize POST, polling
//     loop with §10.1 retry classification, id_token decode, and
//     the discovery readiness probe the RP uses before its first
//     request.
//   - device.go — authentication-device simulator: a goroutine
//     stand-in for the user's phone that calls the substore's
//     Approve method directly.
//
// What the run prints, in order:
//
//  1. "[op] listening on :8080" — the OP banner.
//  2. "[rp] POST /oidc/bc-authorize" — the relying party initiates
//     the backchannel request with login_hint=alice.
//  3. "[rp] auth_req_id=..." — the OP's response payload.
//  4. "[device] user approved auth_req_id=..." — the simulated
//     authentication device flips the record from Pending to Approved.
//     A real deployment fires this transition from a push notification
//     callback handler.
//  5. "[rp] poll #N -> 400 authorization_pending" or
//     "[rp] poll #N -> 200 OK" — the polling loop. The first poll
//     races the device approval and may land as authorization_pending;
//     the second poll observes the approved record and the OP issues
//     tokens.
//  6. "[rp] id_token sub=user-alice aud=ciba-poll-demo" — the decoded
//     id_token claims confirming the round-trip.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - HintResolver: the demo maps a single hardcoded login_hint to a
//     subject. Production resolvers query the embedder's user store
//     and MUST return [op.ErrUnknownCIBAUser] for unknown hints so the
//     OP emits unknown_user_id rather than login_required.
//   - Authentication device: the demo flips the record directly via
//     the substore's Approve method to keep the example single-binary.
//     Production embedders trigger Approve from the user's
//     authentication device callback (a push-notification handler, an
//     IVR confirmation endpoint, etc.) — never from the OP process.
//   - Client secret: high-entropy random secret rotated through the
//     embedder's secret manager in production.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

const (
	opAddr       = ":8080"
	issuer       = "http://127.0.0.1" + opAddr
	clientID     = "ciba-poll-demo"
	clientSecret = "ciba-poll-demo-secret-rotate-me"

	// loginHint is the deterministic identifier the demo RP supplies
	// at /bc-authorize. The HintResolver maps it to demoSubject; any
	// other value resolves to op.ErrUnknownCIBAUser.
	loginHint   = "alice"
	demoSubject = "user-alice"

	cibaGrantURN = "urn:openid:params:grant-type:ciba"

	bcAuthorizePath = "/oidc/bc-authorize"
	tokenPath       = "/oidc/token"

	pollInterval = 1 * time.Second
	pollTimeout  = 10 * time.Second
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("ciba example failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	provider, st, err := buildProvider()
	if err != nil {
		return fmt.Errorf("ciba example: %w", err)
	}

	srv := &http.Server{
		Addr:              opAddr,
		Handler:           provider,
		ReadHeaderTimeout: 10 * time.Second,
	}
	listenErr := make(chan error, 1)
	go func() {
		logger.Info("op listening", slog.String("addr", opAddr), slog.String("issuer", issuer))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
			return
		}
		listenErr <- nil
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
	defer cancel()
	if err := waitForIssuer(ctx, issuer); err != nil {
		return fmt.Errorf("ciba example: wait for issuer: %w", err)
	}

	authReqID, err := postBackchannelAuthorize(ctx, logger)
	if err != nil {
		return fmt.Errorf("ciba example: bc-authorize: %w", err)
	}
	logger.Info("rp received auth_req_id", slog.String("auth_req_id", authReqID))

	if err := simulateDeviceApproval(ctx, logger, st, authReqID); err != nil {
		return fmt.Errorf("ciba example: simulate device approve: %w", err)
	}

	idToken, err := pollToken(ctx, logger, authReqID)
	if err != nil {
		return fmt.Errorf("ciba example: poll: %w", err)
	}

	sub, aud, err := decodeIDTokenClaims(idToken)
	if err != nil {
		return fmt.Errorf("ciba example: decode id_token: %w", err)
	}
	logger.Info("id_token decoded", slog.String("sub", sub), slog.String("aud", aud))

	select {
	case err := <-listenErr:
		if err != nil {
			return fmt.Errorf("ciba example: op listener: %w", err)
		}
	default:
	}
	return nil
}

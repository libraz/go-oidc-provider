//go:build example

// device.go — authentication-device simulator for example
// 31-device-code-cli.
//
// In production, RFC 8628's user_code is approved on a *second*
// device — the user opens verification_uri on a phone or laptop,
// signs in, types the user_code, reviews scopes, and clicks
// "Allow". The verification page lives in the embedder's
// application (the library ships user_code-keyed helpers); the
// approval is the result of an authenticated user action.
//
// This file fakes that ceremony with a goroutine that waits a
// short delay (so the CLI's polling loop observes at least one
// authorization_pending response first) and then calls
// [devicecodekit.ApproveUserCode] with the demo subject. Production
// embedders never call approval helpers from a goroutine.

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/libraz/go-oidc-provider/op/devicecodekit"
	"github.com/libraz/go-oidc-provider/op/store"
)

// simulateBrowserApproval drives the same store seam an authentication
// device's "approve" button would: it waits for [demoApprovalDelay] so
// the polling loop observes at least one authorization_pending response
// first, then verifies and approves by user_code only. The verification
// attempt is additionally bound to a fresh opaque ceremony key rather than
// the user_code itself, so malformed and unknown entries consume one bounded
// browser-ceremony budget. Production embedders derive this key from their
// authenticated browser session or other server-side ceremony state.
func simulateBrowserApproval(ctx context.Context, st store.Store, authz *authorizationResponse, logger *slog.Logger) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(demoApprovalDelay):
	}
	deps := &devicecodekit.Deps{DeviceCodes: st.DeviceCodes()}
	ceremonyKey, err := newVerificationCeremonyKey()
	if err != nil {
		logger.Warn("create verification ceremony key failed", slog.String("err", err.Error()))
		return
	}
	matched, err := devicecodekit.VerifyUserCodeByAttemptKey(context.Background(), deps, ceremonyKey, authz.UserCode)
	if err != nil || !matched {
		if err == nil {
			err = errors.New("user_code mismatch")
		}
		logger.Warn("simulated verification failed", slog.String("err", err.Error()))
		return
	}
	if err := devicecodekit.ApproveUserCode(context.Background(), deps, authz.UserCode, demoSubject, time.Now().UTC()); err != nil { //nolint:forbidigo // demo only: production embedders stamp authTime from their authentication device's clock seam.
		logger.Warn("simulated approval failed", slog.String("err", err.Error()))
		return
	}
	fmt.Printf("[browser] user approved user_code=%s subject=%s\n", authz.UserCode, demoSubject)
}

// newVerificationCeremonyKey models server-side browser-ceremony state. It
// intentionally never uses user_code input: that short code is what the user
// types and therefore cannot be the brute-force limiter's identity.
func newVerificationCeremonyKey() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

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
// first, then verifies and approves by user_code only. Production
// embedders reach this from the user's authenticated browser session.
func simulateBrowserApproval(ctx context.Context, st store.Store, authz *authorizationResponse, logger *slog.Logger) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(demoApprovalDelay):
	}
	deps := &devicecodekit.Deps{DeviceCodes: st.DeviceCodes()}
	matched, err := devicecodekit.VerifyUserCodeByUserCode(context.Background(), deps, authz.UserCode, authz.UserCode)
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

//go:build example

// device.go — authentication-device simulator for example
// 30-device-code-cli.
//
// In production, RFC 8628's user_code is approved on a *second*
// device — the user opens verification_uri on a phone or laptop,
// signs in, types the user_code, reviews scopes, and clicks
// "Allow". The verification page lives in the embedder's
// application (the library ships only the substore method); the
// approval is the result of an authenticated user action.
//
// This file fakes that ceremony with a goroutine that waits a
// short delay (so the CLI's polling loop observes at least one
// authorization_pending response first) and then calls
// [store.DeviceCodeStore.Approve] directly with the demo subject.
// Production embedders never call Approve from a goroutine.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// simulateBrowserApproval drives the same store seam an authentication
// device's "approve" button would: it waits for [demoApprovalDelay] so
// the polling loop observes at least one authorization_pending response
// first, then calls [store.DeviceCodeStore.Approve]. Production
// embedders never call Approve from a goroutine — they reach it from
// the user's authenticated browser session.
func simulateBrowserApproval(ctx context.Context, st store.Store, authz *authorizationResponse, logger *slog.Logger) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(demoApprovalDelay):
	}
	if err := st.DeviceCodes().Approve(context.Background(), authz.DeviceCode, demoSubject); err != nil {
		logger.Warn("simulated approval failed", slog.String("err", err.Error()))
		return
	}
	fmt.Printf("[browser] user approved user_code=%s subject=%s\n", authz.UserCode, demoSubject)
}

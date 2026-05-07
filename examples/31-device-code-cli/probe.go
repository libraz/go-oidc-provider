//go:build example

// probe.go — self-verify probe for example 31-device-code-cli.
//
// Drives the full device-code round-trip against an httptest-hosted
// OP and asserts the wire shape (200 + non-empty device_code +
// non-empty user_code from /device_authorization, 200 + non-empty
// access_token from /token after Approve). Any regression in the
// public API surface fails the example with exit code 1 before the
// public listener binds.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"time"
)

// selfVerify drives an in-process round-trip against an httptest
// server. It:
//
//  1. Builds a fresh OP via [buildProvider].
//  2. POSTs /device_authorization with client_id=cli-tool.
//  3. Asserts 200 + non-empty device_code + non-empty user_code.
//  4. Calls DeviceCodeStore.Approve directly (the substore method
//     a verification page would invoke after the user clicks
//     "Allow").
//  5. POSTs /token with grant_type=device_code.
//  6. Asserts 200 + non-empty access_token.
//
// On any failure the function returns an error; main() prints
// "✗ self-verify: <reason>" and exits 1 before any listener
// binds.
func selfVerify(logger *slog.Logger) error {
	provider, st, err := buildProvider()
	if err != nil {
		return err
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authz, err := postDeviceAuthorization(ctx, srv.URL+deviceAuthPath)
	if err != nil {
		return fmt.Errorf("device_authorization: %w", err)
	}
	if authz.DeviceCode == "" || authz.UserCode == "" {
		return errors.New("device_authorization response missing device_code or user_code")
	}
	logger.Debug("self-verify authorized", slog.String("user_code", authz.UserCode))

	if err := st.DeviceCodes().Approve(ctx, authz.DeviceCode, demoSubject, time.Now().UTC()); err != nil { //nolint:forbidigo // demo only: production embedders stamp authTime from their authentication device's clock seam.
		return fmt.Errorf("approve: %w", err)
	}

	tok, err := postTokenOnce(ctx, srv.URL+tokenPath, authz.DeviceCode)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	if tok.AccessToken == "" {
		return errors.New("token response missing access_token")
	}
	return nil
}

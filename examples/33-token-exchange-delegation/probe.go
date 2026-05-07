//go:build example

// probe.go — self-verify probe for example 33-token-exchange-delegation.
//
// selfVerify is the test contract the example exits 1 on. It owns the
// three-step orchestration:
//
//  1. Drive the auth-code flow (service_a.go) to obtain the user's
//     access_token bound to service-a's audience.
//  2. Exchange that token for a service-b-audience access_token under
//     the RFC 8693 grant_type (service_a.go).
//  3. Decode the exchanged JWT and assert the act chain is correct
//     (service_b.go).
//
// Each step is implemented in its role file; this file only sequences
// them and emits the final summary line the run() banner reads.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// selfVerify drives the full round-trip: it obtains service-a's
// subject_token via the auth-code flow, exchanges it for a service-b-
// audience access_token, decodes the resulting JWT, and asserts the
// act chain. The function returns nil on success and a descriptive
// error otherwise; the caller prints the result with the canonical
// banner.
func selfVerify(logger *slog.Logger, issuer string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	subjectToken, err := obtainSubjectToken(ctx, logger, issuer)
	if err != nil {
		return fmt.Errorf("obtain subject_token: %w", err)
	}
	logger.Info("obtained subject_token", slog.Int("len", len(subjectToken)))

	exchanged, err := postTokenExchange(ctx, logger, issuer, subjectToken)
	if err != nil {
		return fmt.Errorf("token-exchange: %w", err)
	}
	logger.Info("exchanged token", slog.Int("len", len(exchanged)))

	if err := serviceBVerify(logger, issuer, exchanged); err != nil {
		return fmt.Errorf("service-b verify: %w", err)
	}
	return nil
}

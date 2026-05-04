//go:build example

// device.go — authentication-device simulator for example 31-ciba-pos.
//
// In CIBA Core 1.0, the user approves the request on a device that is
// separate from the POS terminal — typically the staff member's phone,
// reached via push notification or an out-of-band channel the embedder
// owns. The substore method [store.CIBARequestStore.Approve] flips the
// pending record to Approved.
//
// This file fakes that ceremony by calling Approve directly. Production
// embedders never call Approve from the OP process — Approve runs in
// the embedder's push-notification callback handler or IVR confirmation
// endpoint, against the same store the OP reads from.

package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func simulateDeviceApproval(ctx context.Context, logger *slog.Logger, st *inmem.Store, authReqID string) error {
	if err := st.CIBARequests().Approve(ctx, authReqID, demoSubject); err != nil {
		return err
	}
	logger.Info("device approved auth_req_id",
		slog.String("auth_req_id", authReqID),
		slog.String("subject", demoSubject))
	fmt.Printf("[device] user approved auth_req_id=%s\n", authReqID)
	return nil
}

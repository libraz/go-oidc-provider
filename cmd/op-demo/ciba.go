package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// cibaAutoApproveStore embeds *inmem.Store and overrides CIBARequests
// so the OP receives the auto-approving wrapper while every other
// substore is promoted unchanged. The wrapper exists so op-demo can
// simulate an authentication-device approval out-of-band, which is the
// shape the OFCS fapi-ciba plan expects: poll mode, first poll lands
// authorization_pending, a follow-up poll observes Approved.
//
// Production embedders MUST trigger Approve from the user's device
// callback (push-notification handler, IVR endpoint, etc.) — never
// from inside the OP process.
type cibaAutoApproveStore struct {
	*inmem.Store
	auto *autoApprovingCIBA
}

// CIBARequests overrides the embedded inmem.Store method so the
// op.Store interface receives the wrapped substore.
func (s *cibaAutoApproveStore) CIBARequests() store.CIBARequestStore {
	return s.auto
}

// autoApprovingCIBA wraps store.CIBARequestStore. Save schedules a
// goroutine that calls Approve(req.ID, req.Subject) after delay,
// simulating an authentication device approving the request. Every
// other method delegates to the inner store unchanged.
//
// The delay defaults long enough that the first /token poll lands
// authorization_pending — the shape the OFCS fapi-ciba plan asserts
// on. ctx is the parent op-demo context: when run() returns, pending
// approvals abort instead of leaking goroutines.
type autoApprovingCIBA struct {
	inner store.CIBARequestStore
	delay time.Duration
	ctx   context.Context //nolint:containedctx // dev-only binary; lifetime is bounded to run().
	log   *slog.Logger
}

// Save delegates to the inner substore and, on success, schedules
// out-of-band approval after a.delay. The goroutine aborts if the
// op-demo parent context cancels first.
func (a *autoApprovingCIBA) Save(ctx context.Context, req *store.CIBARequest) error {
	if err := a.inner.Save(ctx, req); err != nil {
		return err
	}
	authReqID := req.ID
	subject := req.Subject
	go a.approveAfterDelay(authReqID, subject)
	return nil
}

// approveAfterDelay sleeps for a.delay and calls Approve. ErrConflict
// (record already moved out of Pending) is treated as benign because
// the auth_req_id may have been Denied or expired before the timer
// fired; ErrNotFound is similarly benign for an expired record.
func (a *autoApprovingCIBA) approveAfterDelay(authReqID, subject string) {
	timer := time.NewTimer(a.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-a.ctx.Done():
		return
	}
	err := a.inner.Approve(a.ctx, authReqID, subject)
	switch {
	case err == nil:
		a.log.Info("ciba auto-approved",
			slog.String("auth_req_id_prefix", safeAuthReqIDPrefix(authReqID)),
			slog.String("subject", subject))
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
		// Benign: the record changed state (denied / expired /
		// already approved) before the auto-approve timer fired.
	default:
		a.log.Warn("ciba auto-approve failed",
			slog.String("auth_req_id_prefix", safeAuthReqIDPrefix(authReqID)),
			slog.String("err", err.Error()))
	}
}

func (a *autoApprovingCIBA) FindByAuthReqID(ctx context.Context, id string) (*store.CIBARequest, error) {
	return a.inner.FindByAuthReqID(ctx, id)
}

func (a *autoApprovingCIBA) Approve(ctx context.Context, id, subject string) error {
	return a.inner.Approve(ctx, id, subject)
}

func (a *autoApprovingCIBA) Deny(ctx context.Context, id, reason string) error {
	return a.inner.Deny(ctx, id, reason)
}

func (a *autoApprovingCIBA) RecordPoll(ctx context.Context, id string, when time.Time) error {
	return a.inner.RecordPoll(ctx, id, when)
}

func (a *autoApprovingCIBA) IncrementPollViolation(ctx context.Context, id string) (uint8, error) {
	return a.inner.IncrementPollViolation(ctx, id)
}

func (a *autoApprovingCIBA) Consume(ctx context.Context, id string) (*store.CIBARequest, error) {
	return a.inner.Consume(ctx, id)
}

// safeAuthReqIDPrefix returns the first 8 characters of an
// auth_req_id followed by an ellipsis. The full value is a bearer
// secret; logging only a prefix lets correlated lines stay readable
// without exposing the secret in the demo log.
func safeAuthReqIDPrefix(id string) string {
	const n = 8
	if len(id) <= n {
		return ""
	}
	return id[:n] + "…"
}

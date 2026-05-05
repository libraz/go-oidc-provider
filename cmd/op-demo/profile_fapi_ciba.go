// FAPI-CIBA wiring for op-demo.
//
// This file is the single reference for "what op-demo turns on for the
// fapi-ciba OFCS plan". It pairs with:
//
//   - https://go-oidc-provider.libraz.net/compliance/ofcs            — per-plan PASS/REVIEW/SKIPPED breakdown.
//   - https://go-oidc-provider.libraz.net/compliance/ofcs-reproduce  — step-by-step recipe for running the suite.
//
// CIBA differs from the fapi2-* plans in three significant ways:
//
//  1. The OFCS fapi-ciba-id1 plan inherits FAPI 1.0's hardcoded
//     tls_client_certificate_bound_access_tokens requirement and
//     exposes no sender_constrain variant; op-demo therefore wires
//     feature.MTLS instead of feature.DPoP. Both satisfy WithProfile's
//     "DPoP OR MTLS" disjunctive constraint.
//  2. CIBA clients never visit /authorize. Their seeds carry an empty
//     redirect_uri set and a narrowed grant list (CIBA URN +
//     refresh_token).
//  3. The OFCS plan drives the auth_req_id poll loop without a real
//     authentication device, so op-demo wraps the in-memory
//     CIBARequestStore with cibaAutoApproveStore. Save schedules an
//     out-of-band Approve() after cibaAutoApproveDelay so the OP can
//     simulate a device callback. Production embedders MUST trigger
//     Approve from the user's actual device callback, never from
//     inside the OP process.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	opgrant "github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// fapiCIBAOptions returns the [op.Option] additions activated when
// -profile=fapi-ciba.
//
// Wiring (everything fapi2 does in the binding-mechanism dimension,
// plus the CIBA grant):
//
//   - op.WithProfile(profile.FAPICIBA) — auto-enables the CIBA grant
//     and the FAPI alg lockdown.
//   - op.WithFeature(feature.MTLS) — sender constraint; required by
//     fapi-ciba-id1's hardcoded cert-bound check.
//   - op.WithCIBA(WithCIBAHintResolver(...), WithCIBAPollInterval(1s)) —
//     1 s poll keeps the OFCS plan moving; the auto-approve delay
//     (cfg.cibaAutoApproveDelay) is intentionally longer so the first
//     poll lands authorization_pending — the shape OFCS asserts on.
func fapiCIBAOptions(st *inmem.Store) []op.Option {
	return []op.Option{
		op.WithProfile(profile.FAPICIBA),
		op.WithFeature(feature.MTLS),
		op.WithCIBA(
			op.WithCIBAHintResolver(demoHintResolver(st)),
			op.WithCIBAPollInterval(time.Second),
		),
	}
}

// fapiCIBAClientSeeds returns CIBA-only PrivateKeyJWTClient seeds.
// Two clients are seeded so the OFCS fapi-ciba "another-client-cannot-
// poll" / "another-client-cannot-token" tests have a distinct second
// identity to drive against; each reuses the matching FAPI JWKS so
// OFCS can sign with the same private_key_jwt material.
//
// refresh_token is paired with the CIBA URN so a scope including
// offline_access yields a refresh token in the token response. The
// OFCS happy-flow asserts on that envelope; without refresh_token in
// the registered grants list the OP correctly withholds the refresh
// token but the test fails.
func fapiCIBAClientSeeds(cfg runConfig) ([]op.ClientSeed, error) {
	seeds := make([]op.ClientSeed, 0, 2)
	for _, entry := range []struct {
		id   string
		path string
	}{
		{"demo-fapi-ciba", cfg.fapiClient1JWKS},
		{"demo-fapi-ciba-2", cfg.fapiClient2JWKS},
	} {
		pub, err := op.LoadPublicJWKS(entry.path)
		if err != nil {
			return nil, fmt.Errorf("load JWKS %s: %w", entry.path, err)
		}
		seeds = append(seeds, op.PrivateKeyJWTClient{
			ID:         entry.id,
			JWKS:       pub,
			Scopes:     fapiScopeCatalog,
			GrantTypes: []string{opgrant.CIBA.String(), "refresh_token"},
		})
	}
	return seeds, nil
}

// wrapStoreForCIBA wraps the in-memory store with cibaAutoApproveStore
// so Save schedules an out-of-band approval after cfg.cibaAutoApproveDelay.
// The wrapper exists because OFCS drives the fapi-ciba plan without a
// real authentication device — the approval has to come from inside
// op-demo to make the flow progress.
func wrapStoreForCIBA(ctx context.Context, cfg runConfig, st *inmem.Store, logger *slog.Logger) store.Store {
	return &cibaAutoApproveStore{
		Store: st,
		auto: &autoApprovingCIBA{
			inner: st.CIBARequests(),
			delay: cfg.cibaAutoApproveDelay,
			ctx:   ctx,
			log:   logger,
		},
	}
}

// isCIBAProfile reports whether the profile name selects FAPI-CIBA.
// The predicate gates store wrapping in [buildOPStore] and CIBA-only
// client seeding in [buildClientSeeds].
func isCIBAProfile(name string) bool {
	return name == "fapi-ciba"
}

// demoHintResolver returns a [op.HintResolver] that maps the
// well-known login_hint "demo" (and the seed user's username) to the
// seed subject. Any other hint resolves to op.ErrUnknownCIBAUser so
// the OP returns the unknown_user_id wire code.
func demoHintResolver(_ *inmem.Store) op.HintResolver {
	return op.HintResolverFunc(func(_ context.Context, _ op.HintKind, value string) (string, error) {
		switch value {
		case demoUsername, demoSubject, "demo-user@example.com":
			return demoSubject, nil
		}
		return "", op.ErrUnknownCIBAUser
	})
}

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
	// authTime is left zero: this binary is a smoke-test fixture
	// driven by OFCS, not a production OP, and the project's
	// forbidigo gate blocks direct time.Now in cmd/. A zero AuthTime
	// omits the auth_time claim, which suits a demo that never
	// asserts the value.
	err := a.inner.Approve(a.ctx, authReqID, subject, time.Time{})
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

func (a *autoApprovingCIBA) Approve(ctx context.Context, id, subject string, authTime time.Time) error {
	return a.inner.Approve(ctx, id, subject, authTime)
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

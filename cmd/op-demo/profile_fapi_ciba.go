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
//
// OFCS-only test-mode scaffolding (the /_test/ciba-mode handler, the
// reject / slow override scheduler) lives in profile_fapi_ciba_testmode.go
// so an embedder reading this file sees only production-shaped wiring.

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
//
// The post-save scheduler is [scheduleHarness] (defined in
// profile_fapi_ciba_testmode.go) so the OFCS runner can override
// device-side outcomes per module via /_test/ciba-mode. With no
// override posted the behaviour matches [scheduleApprove] — the
// production-shaped reference an embedder would copy.
func wrapStoreForCIBA(ctx context.Context, cfg runConfig, st *inmem.Store, logger *slog.Logger) store.Store {
	return &cibaAutoApproveStore{
		Store: st,
		auto: &autoApprovingCIBA{
			inner:    st.CIBARequests(),
			delay:    cfg.cibaAutoApproveDelay,
			ctx:      ctx,
			log:      logger,
			postSave: scheduleHarness,
		},
	}
}

// isCIBAProfile reports whether the profile name selects FAPI-CIBA.
// The predicate gates store wrapping in [buildOPStore], CIBA-only
// client seeding in [buildClientSeeds], and the conditional mount of
// the OFCS test-mode handler in [main.run].
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

// autoApprovingCIBA wraps store.CIBARequestStore. Save delegates to the
// inner substore and, on success, dispatches postSave in a goroutine
// to simulate a device callback. The default postSave
// ([scheduleApprove]) waits a.delay then approves — the shape a
// production embedder would copy. op-demo installs [scheduleHarness]
// instead so OFCS can drive deny / slow outcomes; with no override
// posted scheduleHarness behaves identically to scheduleApprove.
//
// ctx is the parent op-demo context: when run() returns, pending
// approvals abort instead of leaking goroutines.
type autoApprovingCIBA struct {
	inner store.CIBARequestStore
	delay time.Duration
	ctx   context.Context //nolint:containedctx // dev-only binary; lifetime is bounded to run().
	log   *slog.Logger

	// postSave runs in a goroutine after every successful Save. nil
	// falls back to [scheduleApprove]. The OFCS harness installs
	// [scheduleHarness] (see profile_fapi_ciba_testmode.go).
	postSave func(*autoApprovingCIBA, string, string)
}

// Save delegates to the inner substore and, on success, schedules the
// configured post-save action in a goroutine.
func (a *autoApprovingCIBA) Save(ctx context.Context, req *store.CIBARequest) error {
	if err := a.inner.Save(ctx, req); err != nil {
		return err
	}
	sched := a.postSave
	if sched == nil {
		sched = scheduleApprove
	}
	go sched(a, req.ID, req.Subject)
	return nil
}

// scheduleApprove is the production-shaped post-save scheduler: wait
// a.delay, then call Approve on the inner store. Production embedders
// implement the equivalent shape on their authentication-device callback
// path; this helper simulates that callback for op-demo because there
// is no real device under the OFCS conformance harness.
func scheduleApprove(a *autoApprovingCIBA, authReqID, subject string) {
	timer := time.NewTimer(a.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-a.ctx.Done():
		return
	}
	a.runApprove(authReqID, subject)
}

// runApprove calls Approve on the inner substore and logs the outcome
// at the level matching its severity: Info on success, Warn on a real
// failure, silent on the conflict/not-found shapes that a parallel
// state change can produce. authTime is left zero: this binary is a
// smoke-test fixture, the forbidigo gate blocks direct time.Now in
// cmd/, and a zero AuthTime omits the auth_time claim — which suits a
// demo that never asserts the value.
func (a *autoApprovingCIBA) runApprove(authReqID, subject string) {
	err := a.inner.Approve(a.ctx, authReqID, subject, time.Time{})
	switch {
	case err == nil:
		a.log.Info("ciba auto-approved",
			slog.String("auth_req_id_prefix", safeAuthReqIDPrefix(authReqID)),
			slog.String("subject", subject))
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
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

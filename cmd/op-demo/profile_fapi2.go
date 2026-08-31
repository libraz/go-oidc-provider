// FAPI 2.0 (Baseline + Message Signing) wiring for op-demo.
//
// This file is the single reference for "what op-demo turns on for the
// fapi2-* OFCS plans". It pairs with:
//
//   - https://go-oidc-provider.libraz.net/compliance/ofcs            — per-plan PASS/REVIEW/SKIPPED breakdown.
//   - https://go-oidc-provider.libraz.net/compliance/ofcs-reproduce  — step-by-step recipe for running the suite.
//
// Both Baseline and Message Signing share most of the wiring (FAPI
// client seeds, FAPI TLS allowlist, scope set, dummy redirect_uri
// pre-registration). Message Signing layers a server-supplied DPoP
// nonce on top of Baseline because FAPI 2.0 Message Signing §5.3.4
// mandates one when DPoP is the binding mechanism. JARM is enabled
// automatically when WithProfile observes FAPI2MessageSigning, so this
// file does not need a separate WithFeature call for it.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// fapi2BaselineOptions returns the [op.Option] additions activated when
// -profile=fapi2-baseline. They are appended on top of the common base
// in [buildOptions]; the profile constant auto-enables PAR + JAR + the
// FAPI alg lockdown.
//
// The DPoP feature satisfies FAPI 2.0 §3.1.4 (sender-constrained access
// tokens — DPoP OR mTLS); op-demo picks DPoP for the fapi2-* plans
// because the OFCS templates ship sender_constrain=dpop. mTLS is
// reserved for the fapi-ciba profile (see profile_fapi_ciba.go) where
// the OFCS plan hardcodes cert-bound and exposes no variant.
func fapi2BaselineOptions() []op.Option {
	return []op.Option{
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	}
}

// fapi2MessageSigningOptions returns the [op.Option] additions
// activated when -profile=fapi2-message-signing.
//
// Wiring (everything Baseline does, plus):
//
//   - op.WithProfile(profile.FAPI2MessageSigning) — auto-enables JARM
//     (signed authorization response) on top of PAR / JAR / alg
//     lockdown.
//   - op.WithFeature(feature.DPoP) — same sender constraint as Baseline.
//   - op.WithDPoPNonceSource(...) — FAPI 2.0 Message Signing §5.3.4
//     mandates a server-supplied DPoP nonce. The option layer rejects
//     op.New under this profile if no source is wired.
//
// The in-memory rotator is dev-only: two replicas issue from
// independent rings and reject each other's nonces. A multi-instance
// OP implements [op.DPoPNonceSource] over a shared cache and passes it
// to [op.WithDPoPNonceSource]; there is no built-in distributed
// implementation yet.
func fapi2MessageSigningOptions(ctx context.Context, logger *slog.Logger) ([]op.Option, error) {
	nonces, err := op.NewInMemoryDPoPNonceSource(ctx, time.Minute,
		op.WithInMemoryDPoPNonceLogger(logger))
	if err != nil {
		return nil, fmt.Errorf("dpop nonce source: %w", err)
	}
	return []op.Option{
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(nonces),
	}, nil
}

// fapi2ClientSeeds returns the FAPI test-client seeds used by both the
// fapi2-baseline and fapi2-message-signing OFCS plans. Each
// PrivateKeyJWTClient holds the PUBLIC half of an OFCS test-client
// keypair; the matching private halves live in
// conformance/plans/fapi2-*.json so OFCS can sign private_key_jwt
// assertions.
//
// The "demo-fapi-2" client exists because the OFCS plans drive a
// "second client cannot poll / cannot token" assertion that needs a
// distinct identity.
func fapi2ClientSeeds(cfg runConfig, postLogoutURIs []string) ([]op.ClientSeed, error) {
	fapiURIs := withFAPIDummyRedirectURIs(cfg.redirectURIs)
	seeds := make([]op.ClientSeed, 0, 2)
	for _, entry := range []struct {
		id   string
		path string
	}{
		{"demo-fapi", cfg.fapiClient1JWKS},
		{"demo-fapi-2", cfg.fapiClient2JWKS},
	} {
		pub, err := op.LoadPublicJWKS(entry.path)
		if err != nil {
			return nil, fmt.Errorf("load JWKS %s: %w", entry.path, err)
		}
		seeds = append(seeds, op.PrivateKeyJWTClient{
			ID:                     entry.id,
			JWKS:                   pub,
			RedirectURIs:           fapiURIs,
			Scopes:                 fapiScopeCatalog,
			PostLogoutRedirectURIs: postLogoutURIs,
		})
	}
	return seeds, nil
}

// fapiScopeCatalog drops the address/phone scopes from [scopeCatalog]:
// the FAPI 2.0 conformance plans never request them, and trimming
// keeps the registered scope set consistent with the plan templates.
//
//nolint:gochecknoglobals // immutable demo seed; no per-instance tuning.
var fapiScopeCatalog = []string{"openid", "profile", "email", "offline_access"}

// withFAPIDummyRedirectURIs returns base extended with the dummy-query
// variants the OFCS happy-flow appends via AddDummyValuesToRedirectUri.
// FAPI 2.0 / OAuth 2.1 require exact-string redirect_uri match, but the
// OFCS happy-flow exercises a "second client with extra query params"
// path that the AS is expected to accept. Pre-registering the variants
// lets exact-match succeed without weakening the matcher.
func withFAPIDummyRedirectURIs(base []string) []string {
	const (
		twoDummies   = "?dummy1=lorem&dummy2=ipsum"
		threeDummies = "?dummy1=lorem&dummy2=ipsum&dummy3=dolor"
	)
	out := make([]string, 0, len(base)*3)
	for _, u := range base {
		out = append(out, u, u+twoDummies, u+threeDummies)
	}
	return out
}

// isFAPIProfile reports whether the profile name selects a FAPI 2.0
// posture (any of the three). The predicate is the trigger for the
// FAPI TLS allowlist in [run] and for the FAPI client seeding in
// [buildClientSeeds]; it stays here next to its primary consumers so
// "what does FAPI mean" reads top-to-bottom without cross-file
// references.
func isFAPIProfile(name string) bool {
	return name == "fapi2-baseline" || name == "fapi2-message-signing" || name == "fapi-ciba"
}

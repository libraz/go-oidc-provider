//go:build example

// Example 33-pairwise-saas demonstrates OIDC Core 1.0 §8.1 pairwise
// subject identifiers across two tenant Relying Parties served by a
// single multi-tenant OP. The same internal end-user (user-42) signs
// in to two different tenants; each tenant receives a distinct,
// sector-scoped "sub" value, but a given (tenant, user) pair always
// resolves to the same "sub" across repeated logins.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/33-pairwise-saas
//
// The example is self-contained: a single binary builds the OP,
// drives an in-process self-verify probe against the same
// SubjectGenerator the issuance pipeline runs at runtime, prints the
// three derived sub values along with the assertion outcomes, and
// exits 0 on success.
//
// The codebase is split by role across this directory:
//
//   - main.go  — entrypoint, package godoc, the high-level run()
//     sequence (build → log banner → probe).
//   - op.go    — OP-side wiring: buildProvider with
//     [op.WithPairwiseSubject] enabled and two tenant clients
//     declared `subject_type=pairwise`. Also owns the
//     pairwise-salt generator.
//   - probe.go — invariant assertion: three Generate calls (twice
//     for tenant-a, once for tenant-b) plus the
//     privacy-and-determinism checks the example exits 1 on.
//
// What the run prints, in order:
//
//  1. "[op] pairwise SaaS demo — issuer ..." — the OP banner.
//  2. "[op] tenant-a sector=tenant-a.example.com" /
//     "[op] tenant-b sector=tenant-b.example.com" — the per-tenant
//     sector hosts the pairwise generator derives from each client's
//     single registered redirect_uri (no sector_identifier_uri
//     fetch needed).
//  3. "[probe] tenant-a / user-42 -> sub=..." (twice) and
//     "[probe] tenant-b / user-42 -> sub=..." — the three Generate
//     calls.
//  4. "✓ self-verify: pairwise round-trip OK (A != B, A1 == A2)" on
//     success, or "✗ self-verify: <reason>" on failure.
//
// Why redirect-URI host fallback (not sector_identifier_uri):
//
//	Pairwise sector resolution prefers
//	[store.Client.SectorIdentifierURI] and falls back to the host of
//	the single registered redirect_uri per OIDC Core 1.0 §5. Because
//	this example registers exactly one redirect_uri per tenant and
//	the two URIs use distinct hosts (tenant-a.example.com vs
//	tenant-b.example.com), the fallback yields two stable sectors
//	with no remote HTTP round-trip. A real multi-redirect tenant
//	MUST publish a sector_identifier_uri document and reference it
//	from [op.ConfidentialClient]; this example skips that to stay
//	single-binary.
//
// PRODUCTION CAVEATS:
//   - Salt: the demo generates a 32-byte ephemeral salt at startup,
//     so every restart re-derives every "sub". Production embedders
//     load the salt from a KMS / secret manager and treat it as a
//     long-lived secret — rotating the salt invalidates every
//     previously-issued pairwise sub for every client and every
//     tenant. The library refuses to boot when the salt rotates over
//     a non-empty grant store; plan rotation behind a maintenance
//     window.
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: the demo never opens a TCP socket — the self-verify
//     probe runs entirely in-process. Production OPs front the
//     [op.Provider] handler behind a TLS-terminating ingress.
//   - Tenant onboarding: the demo seeds two static tenants through
//     [op.WithStaticClients]; a real SaaS OP onboards tenants via
//     RFC 7591 dynamic registration and surfaces "subject_type":
//     "pairwise" + "sector_identifier_uri" on the registration
//     payload so each tenant's redirect set is validated against an
//     RP-controlled JSON document.
package main

import (
	"fmt"
	"log/slog"
	"os"
)

const (
	issuer = "http://127.0.0.1:8091"

	// internalUserID is the OP-internal subject the example derives
	// pairwise sub values from. The pairwise generator hashes
	// (salt, sector, internalUserID) into the per-tenant "sub";
	// changing this constant changes every sub the demo prints.
	internalUserID = "user-42"

	tenantAClientID     = "tenant-a"
	tenantAClientSecret = "tenant-a-secret-rotate-me"
	tenantARedirectURI  = "https://tenant-a.example.com/callback"

	tenantBClientID     = "tenant-b"
	tenantBClientSecret = "tenant-b-secret-rotate-me"
	tenantBRedirectURI  = "https://tenant-b.example.com/callback"

	// pairwiseSaltLen matches subject.MinSaltLength (32 bytes / 256
	// bits). The constant is duplicated here so the demo does not
	// import the op/subject sub-package just for one number.
	pairwiseSaltLen = 32
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("pairwise example failed", slog.String("err", err.Error()))
		fmt.Println("✗ self-verify: " + err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	provider, st, salt, err := buildProvider()
	if err != nil {
		return err
	}

	logger.Info("op pairwise SaaS demo",
		slog.String("issuer", issuer),
		slog.Int("salt_bytes", len(salt)),
		slog.String("internal_user_id", internalUserID))

	return runProbe(logger, provider, st)
}

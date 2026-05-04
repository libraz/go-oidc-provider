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
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
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
	keys := devkeys.MustEphemeral("pairwise-saas-1")

	salt, err := newPairwiseSalt()
	if err != nil {
		return fmt.Errorf("generate pairwise salt: %w", err)
	}

	st := inmem.New()

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithPairwiseSubject(salt),
		op.WithStaticClients(
			op.ConfidentialClient{
				ID:           tenantAClientID,
				Secret:       tenantAClientSecret,
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{tenantARedirectURI},
				Scopes:       []string{"openid", "profile"},
				SubjectType:  "pairwise",
			},
			op.ConfidentialClient{
				ID:           tenantBClientID,
				Secret:       tenantBClientSecret,
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{tenantBRedirectURI},
				Scopes:       []string{"openid", "profile"},
				SubjectType:  "pairwise",
			},
		),
	)
	if err != nil {
		return fmt.Errorf("op.New: %w", err)
	}

	logger.Info("op pairwise SaaS demo",
		slog.String("issuer", issuer),
		slog.Int("salt_bytes", len(salt)),
		slog.String("internal_user_id", internalUserID))

	tenantA, err := lookupClient(st, tenantAClientID)
	if err != nil {
		return err
	}
	tenantB, err := lookupClient(st, tenantBClientID)
	if err != nil {
		return err
	}
	logger.Info("op tenant-a", slog.String("sector_host", hostOfFirstRedirect(tenantA)))
	logger.Info("op tenant-b", slog.String("sector_host", hostOfFirstRedirect(tenantB)))

	// Drive three Generate calls: tenant-a twice and tenant-b once.
	// The Provider returns the same SubjectGenerator the issuance
	// pipeline invokes at code emission, so the probe exercises the
	// production code path without standing up a full
	// authorization_code round-trip.
	gen := provider.SubjectGenerator()
	if gen == nil {
		return errors.New("SubjectGenerator() returned nil — the Provider is misconfigured")
	}

	ctx := context.Background()
	subA1, err := mintSub(ctx, gen, tenantA)
	if err != nil {
		return fmt.Errorf("mint tenant-a sub (first): %w", err)
	}
	logger.Info("probe tenant-a/user-42 (login #1)", slog.String("sub", subA1))

	subB1, err := mintSub(ctx, gen, tenantB)
	if err != nil {
		return fmt.Errorf("mint tenant-b sub: %w", err)
	}
	logger.Info("probe tenant-b/user-42 (login #1)", slog.String("sub", subB1))

	subA2, err := mintSub(ctx, gen, tenantA)
	if err != nil {
		return fmt.Errorf("mint tenant-a sub (second): %w", err)
	}
	logger.Info("probe tenant-a/user-42 (login #2)", slog.String("sub", subA2))

	if subA1 == subB1 {
		return fmt.Errorf(
			"privacy property violated: tenant-a sub == tenant-b sub (both %q) — pairwise should split sectors",
			subA1,
		)
	}
	if subA1 != subA2 {
		return fmt.Errorf(
			"determinism property violated: tenant-a sub differs across logins (%q != %q) — pairwise must be stable per (sector, user)",
			subA1, subA2,
		)
	}

	fmt.Println("✓ self-verify: pairwise round-trip OK (A != B, A1 == A2)")
	fmt.Printf("    tenant-a #1 sub = %s\n", subA1)
	fmt.Printf("    tenant-b #1 sub = %s\n", subB1)
	fmt.Printf("    tenant-a #2 sub = %s\n", subA2)
	return nil
}

// newPairwiseSalt returns a 32-byte cryptographically random salt
// suitable for [op.WithPairwiseSubject]. Production embedders pull the
// salt from a KMS or secret manager so it survives across restarts;
// the demo regenerates it on every boot, which is why the printed sub
// values are not stable across runs.
func newPairwiseSalt() ([]byte, error) {
	salt := make([]byte, pairwiseSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// mintSub invokes the configured [op.SubjectGenerator] for the
// canonical example user against the supplied tenant client record.
// The shape mirrors what [op.Provider]'s issuance pipeline passes at
// code-emission time; running the same call site here keeps the
// self-verify probe exercising the production hash.
func mintSub(ctx context.Context, gen op.SubjectGenerator, client *store.Client) (string, error) {
	out, err := gen.Generate(ctx, op.SubjectGeneratorInput{
		InternalUserID: internalUserID,
		Client:         client,
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// lookupClient pulls the persisted [store.Client] record back out of
// the in-memory store. The probe needs the canonical record (the same
// one the issuance pipeline reads at code emission) so the pairwise
// generator sees the redirect-URI host as the issuance pipeline does.
func lookupClient(st *inmem.Store, id string) (*store.Client, error) {
	c, err := st.GetClient(context.Background(), id)
	if err != nil {
		return nil, fmt.Errorf("lookup client %q: %w", id, err)
	}
	return c, nil
}

// hostOfFirstRedirect returns the host portion of the client's first
// registered redirect_uri. The example uses it for log output only;
// the pairwise generator runs its own URL parsing against the
// authoritative RedirectURIs list.
func hostOfFirstRedirect(c *store.Client) string {
	if c == nil || len(c.RedirectURIs) == 0 {
		return ""
	}
	// Rough-and-ready parse: the demo hardcodes well-formed https
	// URIs, so a substring extraction is sufficient. A production
	// surface would call net/url.Parse here.
	const httpsScheme = "https://"
	raw := c.RedirectURIs[0]
	if len(raw) <= len(httpsScheme) {
		return raw
	}
	hostAndPath := raw[len(httpsScheme):]
	for i := range len(hostAndPath) {
		if hostAndPath[i] == '/' {
			return hostAndPath[:i]
		}
	}
	return hostAndPath
}

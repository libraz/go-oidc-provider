//go:build example

// probe.go — pairwise self-verify probe for example 34-pairwise-saas.
//
// The probe drives three [op.SubjectGenerator] calls (twice for
// tenant-a, once for tenant-b) through the same generator the OP's
// issuance pipeline runs at code-emission time. Two invariants must
// hold: (a) **privacy** — distinct sectors yield distinct sub values
// (`subA1 != subB1`); (b) **determinism** — repeating the same
// (sector, user) pair yields the same sub (`subA1 == subA2`). Either
// failure exits the process with a descriptive error.
//
// This file also carries the read-only client lookup / redirect-URI
// host inspection helpers the probe uses for log output. There is no
// HTTP RP in this example: pairwise subject identifiers are a property
// of the SubjectGenerator, observable directly through the public
// [op.Provider.SubjectGenerator] seam.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func runProbe(logger *slog.Logger, provider *op.Provider, st *inmem.Store) error {
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

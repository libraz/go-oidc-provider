package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// The OP mints several short-lived artefacts that are each redeemable
// exactly once — an authorization code, a PAR request_uri, a refresh
// token, an interaction handle, a session ID, a consumed JWT identifier.
// They are separate substores rather than one generic single-use
// provider, and each carries a different privilege: an interaction
// handle only resumes a half-finished login, while an authorization code
// buys tokens.
//
// That separation defends nothing unless the backend keeps the
// namespaces disjoint. A backend that stores every kind under one
// keyspace — one table with no discriminator column, one Redis key
// pattern, one map — lets a value planted through the cheapest substore
// be redeemed through the most privileged one, which is authorization-code
// forgery without ever touching the authorization endpoint. The cases
// below pin disjointness directly, using one identifier across every
// substore the backend implements.

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var namespaceCases = []subtest{
	{"Disjoint", namespaceDisjoint},
	{"ConsumeIsScoped", namespaceConsumeIsScoped},
}

// sharedNamespaceID is used verbatim as the identifier in every substore
// the probes below touch. Reusing one value is the whole point: distinct
// per-substore identifiers would pass even on a backend with a single
// shared keyspace.
const sharedNamespaceID = "contract-shared-identifier"

// namespaceProbe adapts one substore to the plant/present pair the
// disjointness matrix needs. present reports whether the shared
// identifier resolves to a record in that substore; a transport fault
// fails the test rather than reading as absence.
type namespaceProbe struct {
	name    string
	plant   func(t *testing.T, ctx context.Context, b Backend)
	present func(t *testing.T, ctx context.Context, b Backend) bool
}

// namespaceProbes returns the probes for the substores b actually
// implements. Partial-coverage backends return nil from the accessors
// they do not host (a volatile cache backing only sessions, interactions
// and consumed JTIs, for instance), so the set is filtered rather than
// assumed.
func namespaceProbes(b Backend) []namespaceProbe {
	all := []struct {
		probe   namespaceProbe
		present bool
	}{
		{authCodeProbe(), b.Store.AuthorizationCodes() != nil},
		{parProbe(), b.Store.PushedAuthRequests() != nil},
		{refreshProbe(), b.Store.RefreshTokens() != nil},
		{interactionProbe(), b.Store.Interactions() != nil},
		{sessionProbe(), b.Store.Sessions() != nil},
		{jtiProbe(), b.Store.ConsumedJTIs() != nil},
	}
	out := make([]namespaceProbe, 0, len(all))
	for _, entry := range all {
		if entry.present {
			out = append(out, entry.probe)
		}
	}
	return out
}

func authCodeProbe() namespaceProbe {
	return namespaceProbe{
		name: "authorization code",
		plant: func(t *testing.T, ctx context.Context, b Backend) {
			t.Helper()
			if err := b.Store.AuthorizationCodes().Save(ctx, newAuthCode(b.Now(), sharedNamespaceID)); err != nil {
				t.Fatalf("plant authorization code: %v", err)
			}
		},
		present: func(t *testing.T, ctx context.Context, b Backend) bool {
			t.Helper()
			_, err := b.Store.AuthorizationCodes().Find(ctx, sharedNamespaceID)
			return presenceOf(t, "authorization code", err)
		},
	}
}

func parProbe() namespaceProbe {
	return namespaceProbe{
		name: "pushed authorization request",
		plant: func(t *testing.T, ctx context.Context, b Backend) {
			t.Helper()
			if err := b.Store.PushedAuthRequests().Save(ctx, newPAR(b.Now(), sharedNamespaceID)); err != nil {
				t.Fatalf("plant pushed authorization request: %v", err)
			}
		},
		present: func(t *testing.T, ctx context.Context, b Backend) bool {
			t.Helper()
			_, err := b.Store.PushedAuthRequests().Find(ctx, sharedNamespaceID)
			return presenceOf(t, "pushed authorization request", err)
		},
	}
}

func refreshProbe() namespaceProbe {
	return namespaceProbe{
		name: "refresh token",
		plant: func(t *testing.T, ctx context.Context, b Backend) {
			t.Helper()
			if err := b.Store.RefreshTokens().Save(ctx, newRefresh(b.Now(), sharedNamespaceID, nil)); err != nil {
				t.Fatalf("plant refresh token: %v", err)
			}
		},
		present: func(t *testing.T, ctx context.Context, b Backend) bool {
			t.Helper()
			_, err := b.Store.RefreshTokens().Find(ctx, sharedNamespaceID)
			return presenceOf(t, "refresh token", err)
		},
	}
}

func interactionProbe() namespaceProbe {
	return namespaceProbe{
		name: "interaction",
		plant: func(t *testing.T, ctx context.Context, b Backend) {
			t.Helper()
			if err := b.Store.Interactions().Save(ctx, newInteraction(b.Now(), sharedNamespaceID)); err != nil {
				t.Fatalf("plant interaction: %v", err)
			}
		},
		present: func(t *testing.T, ctx context.Context, b Backend) bool {
			t.Helper()
			_, err := b.Store.Interactions().Find(ctx, sharedNamespaceID)
			return presenceOf(t, "interaction", err)
		},
	}
}

func sessionProbe() namespaceProbe {
	return namespaceProbe{
		name: "session",
		plant: func(t *testing.T, ctx context.Context, b Backend) {
			t.Helper()
			if err := b.Store.Sessions().Save(ctx, newSession(b.Now(), sharedNamespaceID)); err != nil {
				t.Fatalf("plant session: %v", err)
			}
		},
		present: func(t *testing.T, ctx context.Context, b Backend) bool {
			t.Helper()
			_, err := b.Store.Sessions().Find(ctx, sharedNamespaceID)
			return presenceOf(t, "session", err)
		},
	}
}

func jtiProbe() namespaceProbe {
	return namespaceProbe{
		name: "consumed JTI",
		plant: func(t *testing.T, ctx context.Context, b Backend) {
			t.Helper()
			if err := b.Store.ConsumedJTIs().Mark(ctx, sharedNamespaceID, b.Now().Add(time.Hour)); err != nil {
				t.Fatalf("plant consumed JTI: %v", err)
			}
		},
		present: func(t *testing.T, ctx context.Context, b Backend) bool {
			t.Helper()
			got, err := b.Store.ConsumedJTIs().Has(ctx, sharedNamespaceID)
			if err != nil {
				t.Fatalf("consumed JTI lookup: %v", err)
			}
			return got
		},
	}
}

// presenceOf maps a lookup error onto presence. [store.ErrNotFound] is
// the only error that means "absent"; anything else is a transport fault
// that must not be read as a passing isolation check.
func presenceOf(t *testing.T, what string, err error) bool {
	t.Helper()
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNotFound):
		return false
	default:
		t.Fatalf("%s lookup: %v", what, err)
		return false // Fatalf stops the goroutine; the return is for static analysis.
	}
}

// namespaceDisjoint plants one identifier into each substore in turn and,
// after every plant, asserts that exactly the substores planted so far
// resolve it. Two failure shapes are caught at once: a substore that
// resolves an identifier it was never given (the keyspaces collide), and
// a substore that stops resolving its own record once a later substore
// takes the same identifier (a later write overwrote an earlier one).
//
// Tracks: CVE-2026-4282 (Keycloak) — a single-use-object provider held
// every kind of single-use artefact in one keyspace, so a value obtained
// through a low-privilege ceremony could be presented as an
// authorization code and exchanged for tokens. The structural defence is
// that the identifier alone never determines what an artefact is: the
// substore it was written to does, and no substore answers for another's
// namespace.
func namespaceDisjoint(t *testing.T, f Factory) {
	b := f(t)
	probes := namespaceProbes(b)
	if len(probes) < 2 {
		t.Skipf("backend implements %d probe-able substores; disjointness needs at least 2", len(probes))
	}
	ctx := context.Background()

	for planted, p := range probes {
		p.plant(t, ctx, b)
		for i, q := range probes {
			want := i <= planted
			if got := q.present(t, ctx, b); got != want {
				if got {
					t.Fatalf("after planting %q, the %q substore also resolves %q: the two share a keyspace",
						p.name, q.name, sharedNamespaceID)
				}
				t.Fatalf("after planting %q, the %q substore no longer resolves its own %q: a later write displaced it",
					p.name, q.name, sharedNamespaceID)
			}
		}
	}
}

// namespaceConsumeIsScoped pins the single-use half of the same property:
// redeeming an identifier through one substore MUST NOT redeem it in
// another. A backend sharing one consumed-flag across kinds would let a
// spent interaction handle silently retire a live authorization code, or
// — far worse in the other direction — let redeeming a cheap artefact
// leave a privileged one still spendable under a name the caller believes
// is used up.
func namespaceConsumeIsScoped(t *testing.T, f Factory) {
	b := f(t)
	if b.Store.AuthorizationCodes() == nil || b.Store.PushedAuthRequests() == nil {
		t.Skip("backend does not implement both AuthorizationCodeStore and PushedAuthRequestStore")
	}
	ctx := context.Background()
	if err := b.Store.AuthorizationCodes().Save(ctx, newAuthCode(b.Now(), sharedNamespaceID)); err != nil {
		t.Fatalf("seed authorization code: %v", err)
	}
	if err := b.Store.PushedAuthRequests().Save(ctx, newPAR(b.Now(), sharedNamespaceID)); err != nil {
		t.Fatalf("seed pushed authorization request: %v", err)
	}

	if _, err := b.Store.AuthorizationCodes().Consume(ctx, sharedNamespaceID); err != nil {
		t.Fatalf("consume authorization code: %v", err)
	}

	par, err := b.Store.PushedAuthRequests().Consume(ctx, sharedNamespaceID)
	if err != nil {
		t.Fatalf("consuming the authorization code also retired the pushed authorization request: %v", err)
	}
	if par.ConsumedAt == nil {
		t.Fatal("pushed authorization request Consume returned ConsumedAt=nil")
	}
	if _, err := b.Store.AuthorizationCodes().Consume(ctx, sharedNamespaceID); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("authorization code replay after the sibling consume: want ErrAlreadyConsumed, got %v", err)
	}
}

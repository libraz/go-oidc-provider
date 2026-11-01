package op

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
)

// newACRSatisfier builds the predicate the authorize endpoint asks before
// reusing an established session for a request naming an acr. The
// session's level is recovered from its canonical acr, its completed
// steps are the kinds it stands in for, and the configured [ACRPolicy]
// judges both, so a session satisfies a custom acr exactly when a fresh
// ceremony at the same level would.
func newACRSatisfier(cfg *config, orch *authn.Orchestrator) authorizeendpoint.ACRSatisfier {
	policy := cfg.effectiveACRPolicy()
	return func(ctx context.Context, requested string, entry authn.EntryAuthn) bool {
		completed := stepKindsOf(orch.InheritedCompletedKinds(entry))
		return policy.Satisfies(ctx, requested, authn.AALFromACRURI(entry.ACR), completed)
	}
}

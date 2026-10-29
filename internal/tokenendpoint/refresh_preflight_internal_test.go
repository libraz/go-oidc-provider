package tokenendpoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestRefreshPreflight_SenderConstraintRefusalLeavesTokenUnconsumed pins that
// a refresh request the deployment refuses for lacking a DPoP proof or client
// certificate is turned away before Consume, so it cannot spend the chain.
func TestRefreshPreflight_SenderConstraintRefusalLeavesTokenUnconsumed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := inmem.New()
	const tokenID = "rt-sender-constraint-preflight" //nolint:gosec // opaque test fixture id.
	if err := st.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:        tokenID,
		ClientID:  "client-1",
		Subject:   "user-1",
		GrantID:   "grant-1",
		Scope:     []string{"openid"},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	deps := Deps{RefreshTokens: st.RefreshTokens(), RequireSenderConstrainedTokens: true}
	client := &store.Client{ID: "client-1", Scopes: []string{"openid"}}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(""))
	rec := httptest.NewRecorder()

	ok := preflightRefreshBeforeConsume(ctx, rec, r, deps, client,
		refreshInputs{Token: tokenID}, &dpopOutcome{})
	if ok {
		t.Fatal("preflight admitted a bearer refresh where sender-constrained tokens are required")
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), errInvalidRequest) {
		t.Fatalf("status=%d body=%s, want 400 invalid_request", rec.Code, rec.Body.String())
	}
	stored, err := st.RefreshTokens().Find(ctx, tokenID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if stored.ConsumedAt != nil {
		t.Fatalf("ConsumedAt=%v; a refused refresh must not spend the token", stored.ConsumedAt)
	}

	rec = httptest.NewRecorder()
	if !preflightRefreshBeforeConsume(ctx, rec, r, deps, client,
		refreshInputs{Token: tokenID}, &dpopOutcome{JKT: "jkt-1", Presented: true}) {
		t.Fatalf("preflight refused a proof-carrying refresh: %s", rec.Body.String())
	}
}

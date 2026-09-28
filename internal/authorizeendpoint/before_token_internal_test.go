package authorizeendpoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op/store"
)

func TestRouteThroughBeforeToken(t *testing.T) {
	t.Parallel()

	grant := &store.Grant{ID: "grant-1"}
	auto := &grantUpsert{Subject: "user-1", ClientID: "client-1"}
	cases := []struct {
		name       string
		mint       authorizeHint
		promptNone bool
		want       authorizeHint
	}{
		{
			name:       "prompt=none never mints",
			mint:       authorizeHint{decision: decisionMint, grant: grant},
			promptNone: true,
			want:       authorizeHint{decision: decisionInteractionRequired},
		},
		{
			name: "cached-grant mint starts the chain at BeforeToken",
			mint: authorizeHint{decision: decisionMint, grant: grant},
			want: authorizeHint{decision: decisionInteract, grant: grant, startPhase: authn.PhaseBeforeToken},
		},
		{
			name: "first-party auto-grant starts the chain at BeforeToken",
			mint: authorizeHint{decision: decisionMint, autoGrant: auto},
			want: authorizeHint{decision: decisionInteract, autoGrant: auto, startPhase: authn.PhaseBeforeToken},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := routeThroughBeforeToken(tc.mint, tc.promptNone)
			if got.decision != tc.want.decision || got.prompt != tc.want.prompt || got.grant != tc.want.grant ||
				got.autoGrant != tc.want.autoGrant || got.startPhase != tc.want.startPhase {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// An auto-granted chain starts with consent marked as run, but flagged
// so the terminal gate does not look for a cached grant that was never
// there.
func TestInitialAuthnStateFirstPartyAutoGrant(t *testing.T) {
	t.Parallel()

	req := &authorize.Request{Scope: []string{"openid", "profile"}}
	hint := routeThroughBeforeToken(authorizeHint{decision: decisionMint, autoGrant: &grantUpsert{}}, false)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize", http.NoBody)
	st := initialAuthnState(r, resolved{}, req, &store.Client{ID: "client-1"}, nil, hint, "uid", time.Unix(0, 0).UTC())
	if st.Phase != authn.PhaseBeforeToken || !st.InteractionsRun[consent.Name] || !st.ConsentAutoGranted {
		t.Fatalf("phase=%v run=%v auto=%v; want BeforeToken with consent pre-marked as auto-granted",
			st.Phase, st.InteractionsRun, st.ConsentAutoGranted)
	}
}

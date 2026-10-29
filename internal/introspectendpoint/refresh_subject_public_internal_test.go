package introspectendpoint

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestResolveOpaque_RefreshTokenSubjectPublicIsNotReprojected pins that a
// refresh token whose recorded subject is already the public wire value
// is introspected with that value, while an OP-internal subject still
// goes through the pairwise projector.
func TestResolveOpaque_RefreshTokenSubjectPublicIsNotReprojected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	st := inmem.New(inmem.WithClock(fixedTestClock{now: now}))
	if err := st.RegisterClient(ctx, &store.Client{ID: "rp", TokenEndpointAuthMethod: "client_secret_basic"}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	deps := Deps{
		RefreshTokens: st.RefreshTokens(),
		Clients:       st.Clients(),
		Clock:         fixedTestClock{now: now},
		SubjectProjector: func(_ context.Context, raw string, c *store.Client) (string, error) {
			return c.ID + ":" + raw, nil
		},
	}
	cases := []struct {
		name          string
		subjectPublic bool
		want          string
	}{
		{"internal subject is projected", false, "rp:user-1"},
		{"public subject is reported verbatim", true, "user-1"},
	}
	for i, tc := range cases {
		id := []string{"rt-internal", "rt-public"}[i]
		if err := st.RefreshTokens().Save(ctx, &store.RefreshToken{
			ID: id, ClientID: "rp", Subject: "user-1", SubjectPublic: tc.subjectPublic,
			Origin: store.RefreshOriginCustomGrant, Scope: []string{"api"},
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}); err != nil {
			t.Fatalf("RefreshTokens.Save: %v", err)
		}
		got, ok := resolveOpaque(ctx, deps, "rp", id)
		if !ok || !got.Active {
			t.Fatalf("%s: resolveOpaque active=%v ok=%v want an active token", tc.name, got.Active, ok)
		}
		if got.Sub != tc.want {
			t.Errorf("%s: sub=%q want %q", tc.name, got.Sub, tc.want)
		}
	}
}

type fixedTestClock struct{ now time.Time }

func (c fixedTestClock) Now() time.Time { return c.now }

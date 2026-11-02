package cibaendpoint_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/cibaendpoint"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

type observingResolver struct {
	calls int
	value string
}

func (r *observingResolver) Resolve(_ context.Context, _ ciba.HintKind, value string) (string, error) {
	r.calls++
	r.value = value
	return value, nil
}

// TestServe_IDTokenHint_SubjectProjection pins that the resolver only
// ever sees an OP-internal subject: a projection that rewrites the
// client's "sub" makes the verified value unusable as one, so the
// request is refused instead of handing the resolver a projected value.
func TestServe_IDTokenHint_SubjectProjection(t *testing.T) {
	t.Parallel()
	const subject = "user-123"
	clock := fixedClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}

	cases := []struct {
		name      string
		projector func(context.Context, string, *store.Client) (string, error)
		want      int
	}{
		{"no projector", nil, http.StatusOK},
		{"identity projector", func(_ context.Context, raw string, _ *store.Client) (string, error) { return raw, nil }, http.StatusOK},
		{"rewriting projector", func(_ context.Context, raw string, _ *store.Client) (string, error) { return "gen-" + raw, nil }, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			entry, err := keys.GenerateES256("ciba-hint-kid")
			if err != nil {
				t.Fatalf("GenerateES256: %v", err)
			}
			set, err := keys.NewSet([]keys.Entry{entry})
			if err != nil {
				t.Fatalf("NewSet: %v", err)
			}
			hint, err := tokens.SignIDToken(tokens.FromInternalEntry(entry), tokens.IDTokenClaims{
				Issuer:    "https://op.example",
				Subject:   subject,
				Audience:  []string{testClientID},
				IssuedAt:  clock.now.Unix(),
				ExpiresAt: clock.now.Add(time.Minute).Unix(),
			})
			if err != nil {
				t.Fatalf("SignIDToken: %v", err)
			}

			resolver := &observingResolver{}
			deps := newDeps(newTestStore(t, clock), clock)
			deps.Keys = set
			deps.HintResolver = resolver
			deps.SubjectProjector = tc.projector

			rec := httptest.NewRecorder()
			cibaendpoint.Handler(deps).ServeHTTP(rec, newRequest(url.Values{
				"scope":         {"openid"},
				"id_token_hint": {hint},
			}))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusOK {
				if resolver.value != subject {
					t.Errorf("resolver saw %q, want %q", resolver.value, subject)
				}
				return
			}
			if got := decodeError(t, rec.Body.Bytes()); got != wireInvalidRequest {
				t.Errorf("error = %q, want %q", got, wireInvalidRequest)
			}
			if !strings.Contains(rec.Body.String(), "login_hint") {
				t.Errorf("body %s must name the supported alternative", rec.Body.String())
			}
			if resolver.calls != 0 {
				t.Errorf("resolver ran %d times for a refused hint", resolver.calls)
			}
		})
	}
}

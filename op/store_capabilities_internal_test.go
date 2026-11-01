package op

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// wrappedRevocationsStore is the hand-written wrapper the capability
// report exists for: it forwards GrantRevocations through a narrower
// interface value, which hides the backend's IssuanceRevocationChecker.
type wrappedRevocationsStore struct {
	*inmem.Store
}

type narrowRevocations struct{ store.GrantRevocationStore }

func (s wrappedRevocationsStore) GrantRevocations() store.GrantRevocationStore {
	return narrowRevocations{s.Store.GrantRevocations()}
}

// TestInfoMissingStoreCapabilities pins that a capability hidden by a
// wrapper is named once at INFO, and that a store implementing every
// capability logs nothing.
func TestInfoMissingStoreCapabilities(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		st   store.Store
		dcr  *RegistrationOption
		want []string
	}{
		{name: "bundled store", st: inmem.New()},
		{name: "bundled store with dynamic registration", st: inmem.New(), dcr: &RegistrationOption{}},
		{
			name: "wrapper hides IssuanceRevocationChecker",
			st:   wrappedRevocationsStore{inmem.New()},
			want: []string{"GrantRevocations: store.IssuanceRevocationChecker"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			c := &config{
				store:  tc.st,
				dcr:    tc.dcr,
				logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})),
			}
			c.infoMissingStoreCapabilities()
			out := buf.String()
			if len(tc.want) == 0 {
				if out != "" {
					t.Fatalf("want no output; got:\n%s", out)
				}
				return
			}
			if got := strings.Count(out, "level=INFO"); got != 1 {
				t.Fatalf("INFO lines = %d, want 1; got:\n%s", got, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Fatalf("output does not name %q; got:\n%s", w, out)
				}
			}
		})
	}
}

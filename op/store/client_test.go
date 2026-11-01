package store_test

import (
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

func TestStaticClientEquivalent_PreviousSecretExpiryNormalized(t *testing.T) {
	t.Parallel()

	tokyo := time.FixedZone("JST", 9*60*60)
	seeded := time.Date(2026, 11, 1, 12, 0, 0, 500, tokyo)
	scanned := time.Unix(seeded.Unix(), 0).UTC()

	base := store.Client{ID: "rp", SecretHash: "h1", PreviousSecretHash: "h0"}

	cases := []struct {
		name string
		a, b time.Time
		want bool
	}{
		{"same instant different location and sub-second", seeded, scanned, true},
		{"both zero", time.Time{}, time.Time{}, true},
		{"one second apart", scanned, scanned.Add(time.Second), false},
		{"zero versus set", time.Time{}, scanned, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, b := base, base
			a.PreviousSecretExpiresAt = tc.a
			b.PreviousSecretExpiresAt = tc.b
			if got := store.StaticClientEquivalent(&a, &b); got != tc.want {
				t.Fatalf("StaticClientEquivalent = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("previous hash differs", func(t *testing.T) {
		t.Parallel()
		a, b := base, base
		b.PreviousSecretHash = "other"
		if store.StaticClientEquivalent(&a, &b) {
			t.Fatal("clients with different previous hashes compared equal")
		}
	})
}

func TestStaticClientDifferences_NamesChangedFieldsInOrder(t *testing.T) {
	t.Parallel()

	stored := &store.Client{ID: "c", RedirectURIs: []string{"https://a/cb"}, Scopes: []string{"openid"}}
	seed := &store.Client{ID: "c", RedirectURIs: []string{"https://b/cb"}, Scopes: []string{"openid", "email"}, Contacts: []string{}}
	got := store.StaticClientDifferences(stored, seed)
	if want := []string{"RedirectURIs", "Scopes"}; !slices.Equal(got, want) {
		t.Fatalf("differences=%v want %v (an empty Contacts slice must equal nil)", got, want)
	}
	if diff := store.StaticClientDifferences(stored, stored.Clone()); diff != nil {
		t.Errorf("identical records differ in %v", diff)
	}
	if diff := store.StaticClientDifferences(nil, seed); diff != nil {
		t.Errorf("nil record differences=%v want nil", diff)
	}
}

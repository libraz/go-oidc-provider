package op

import (
	"sort"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// A fully populated store.StandardClaims must produce every standard
// claim the guard knows except updated_at (carried by User.UpdatedAt),
// each with the JSON type the guard accepts, so the typed builder and
// the guard cannot drift apart.
func TestStandardClaimsMatchesClaimTypeGuard(t *testing.T) {
	t.Parallel()

	full := store.StandardClaims{
		Name: "n", GivenName: "g", FamilyName: "f", MiddleName: "m",
		Nickname: "k", PreferredUsername: "p", Profile: "https://p",
		Picture: "https://i", Website: "https://w", Email: "e@example.com",
		EmailVerified: true, Gender: "x", Birthdate: "2000-01-01",
		Zoneinfo: "Asia/Tokyo", Locale: "ja-JP", PhoneNumber: "+81",
		PhoneNumberVerified: true,
		Address:             store.Address{Formatted: "a"},
	}.Map()

	var want, got []string
	for name := range standardClaimKinds {
		if name != "updated_at" {
			want = append(want, name)
		}
	}
	for name, v := range full {
		got = append(got, name)
		kind, ok := standardClaimKinds[name]
		if !ok {
			t.Errorf("StandardClaims emits %q, which the guard does not know", name)
			continue
		}
		if !claimValueIs(kind, v) {
			t.Errorf("StandardClaims emits %q as %T, which the guard drops", name, v)
		}
	}
	sort.Strings(want)
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("StandardClaims emits %v, want %v", got, want)
	}
}

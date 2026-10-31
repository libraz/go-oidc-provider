package store_test

import (
	"encoding/json"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

func TestStandardClaimsMap_ZeroValueIsEmpty(t *testing.T) {
	t.Parallel()

	if got := (store.StandardClaims{}).Map(); len(got) != 0 {
		t.Fatalf("zero StandardClaims released %v, want no claims", got)
	}
}

func TestStandardClaimsMap_VerifiedFlagFollowsItsValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		claims store.StandardClaims
		want   string
	}{
		{"verified without email", store.StandardClaims{EmailVerified: true}, `{}`},
		{"email unverified", store.StandardClaims{Email: "a@example.com"}, `{"email":"a@example.com","email_verified":false}`},
		{"email verified", store.StandardClaims{Email: "a@example.com", EmailVerified: true}, `{"email":"a@example.com","email_verified":true}`},
		{"verified without phone", store.StandardClaims{PhoneNumberVerified: true}, `{}`},
		{"phone verified", store.StandardClaims{PhoneNumber: "+81", PhoneNumberVerified: true}, `{"phone_number":"+81","phone_number_verified":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := encode(t, tc.claims.Map()); got != tc.want {
				t.Fatalf("Map() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestStandardClaimsMap_AddressIsAnObjectOfSetFields(t *testing.T) {
	t.Parallel()

	got := encode(t, store.StandardClaims{Address: store.Address{Locality: "Tokyo", Country: "JP"}}.Map())
	if want := `{"address":{"country":"JP","locality":"Tokyo"}}`; got != want {
		t.Fatalf("Map() = %s, want %s", got, want)
	}
}

func TestStandardClaimsMap_ReturnsAFreshMap(t *testing.T) {
	t.Parallel()

	c := store.StandardClaims{Name: "Alice"}
	first := c.Map()
	first["tenant"] = "t1"
	if _, leaked := c.Map()["tenant"]; leaked {
		t.Fatal("a key added to one Map() result appeared in the next")
	}
}

func encode(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

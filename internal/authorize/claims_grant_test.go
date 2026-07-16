package authorize_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

func TestEncodeClaimsToGrantReturnsNilForAbsentOrEmptyClaims(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   *authorize.ClaimsRequest
	}{
		{name: "nil", in: nil},
		{name: "empty", in: &authorize.ClaimsRequest{}},
		{name: "empty maps", in: &authorize.ClaimsRequest{
			IDToken:  map[string]authorize.ClaimSpec{},
			UserInfo: map[string]authorize.ClaimSpec{},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := authorize.EncodeClaimsToGrant(tc.in); got != nil {
				t.Fatalf("EncodeClaimsToGrant = %v, want nil", got)
			}
		})
	}
}

func TestClaimsGrantRoundTripThroughJSONStorageShape(t *testing.T) {
	t.Parallel()

	in := &authorize.ClaimsRequest{
		IDToken: map[string]authorize.ClaimSpec{
			"sub": {
				Value: "user-1",
			},
			"acr": {
				Essential: true,
				Values:    []any{"urn:mace:incommon:iap:silver", "http://idmanagement.gov/ns/assurance/loa/4"},
			},
		},
		UserInfo: map[string]authorize.ClaimSpec{
			"email": {
				Essential: true,
			},
			"name#ja-JP": {},
			"age": {
				Value: json.Number("42"),
			},
		},
	}

	encoded := authorize.EncodeClaimsToGrant(in)
	if encoded == nil {
		t.Fatal("EncodeClaimsToGrant returned nil for non-empty claims")
	}
	raw, err := json.Marshal(encoded)
	if err != nil {
		t.Fatalf("marshal grant claims: %v", err)
	}
	var stored map[string]any
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("unmarshal stored claims: %v", err)
	}

	got := authorize.DecodeClaimsFromGrant(stored)
	if got == nil {
		t.Fatal("DecodeClaimsFromGrant returned nil for encoded claims")
	}
	assertSpec(t, got.IDToken, "sub", authorize.ClaimSpec{Value: "user-1"})
	assertSpec(t, got.IDToken, "acr", authorize.ClaimSpec{
		Essential: true,
		Values:    []any{"urn:mace:incommon:iap:silver", "http://idmanagement.gov/ns/assurance/loa/4"},
	})
	assertSpec(t, got.UserInfo, "email", authorize.ClaimSpec{Essential: true})
	assertSpec(t, got.UserInfo, "name#ja-JP", authorize.ClaimSpec{})
	assertSpec(t, got.UserInfo, "age", authorize.ClaimSpec{Value: float64(42)})
}

func TestDecodeClaimsFromGrantIgnoresUnknownOrMalformedStoredPayloads(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   map[string]any
	}{
		{name: "nil", in: nil},
		{name: "missing request key", in: map[string]any{"vendor": map[string]any{"foo": "bar"}}},
		{name: "request is not object", in: map[string]any{"request": "not-an-object"}},
		{name: "locations are malformed", in: map[string]any{"request": map[string]any{
			"id_token": []any{"sub"},
			"userinfo": "name",
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := authorize.DecodeClaimsFromGrant(tc.in); got != nil {
				t.Fatalf("DecodeClaimsFromGrant = %+v, want nil", got)
			}
		})
	}
}

func TestDecodeClaimsFromGrantSkipsMalformedClaimEntries(t *testing.T) {
	t.Parallel()

	got := authorize.DecodeClaimsFromGrant(map[string]any{
		"request": map[string]any{
			"id_token": map[string]any{
				"sub": map[string]any{"value": "user-1"},
				"bad": []any{"not", "an", "object"},
			},
			"userinfo": map[string]any{
				"email": nil,
			},
		},
	})
	if got == nil {
		t.Fatal("DecodeClaimsFromGrant returned nil")
	}
	assertSpec(t, got.IDToken, "sub", authorize.ClaimSpec{Value: "user-1"})
	assertSpec(t, got.IDToken, "bad", authorize.ClaimSpec{})
	assertSpec(t, got.UserInfo, "email", authorize.ClaimSpec{})
}

func assertSpec(tb testing.TB, got map[string]authorize.ClaimSpec, name string, want authorize.ClaimSpec) {
	tb.Helper()

	spec, ok := got[name]
	if !ok {
		tb.Fatalf("claim %q missing from %v", name, got)
	}
	if !reflect.DeepEqual(spec, want) {
		tb.Fatalf("claim %q = %+v, want %+v", name, spec, want)
	}
}

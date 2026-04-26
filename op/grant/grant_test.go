package grant_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/grant"
)

func TestType_String(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   grant.Type
		want string
	}{
		{"authorization_code", grant.AuthorizationCode, "authorization_code"},
		{"refresh_token", grant.RefreshToken, "refresh_token"},
		{"client_credentials", grant.ClientCredentials, "client_credentials"},
		{"device_code", grant.DeviceCode, "urn:ietf:params:oauth:grant-type:device_code"},
		{"zero", grant.Type(0), ""},
		{"unknown", grant.Type(99), ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.in.String(); got != tc.want {
				t.Errorf("String()=%q want %q", got, tc.want)
			}
		})
	}
}

func TestType_IsValid(t *testing.T) {
	t.Parallel()

	valid := []grant.Type{
		grant.AuthorizationCode,
		grant.RefreshToken,
		grant.ClientCredentials,
		grant.DeviceCode,
	}
	for _, v := range valid {
		if !v.IsValid() {
			t.Errorf("%s should be valid", v)
		}
	}
	if grant.Type(0).IsValid() {
		t.Error("zero value must be invalid")
	}
	if grant.Type(99).IsValid() {
		t.Error("out-of-range value must be invalid")
	}
}

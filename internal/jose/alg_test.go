package jose_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

func TestAlgorithm_IsAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		alg  jose.Algorithm
		want bool
	}{
		{"RS256", jose.AlgRS256, true},
		{"PS256", jose.AlgPS256, true},
		{"ES256", jose.AlgES256, true},
		{"EdDSA", jose.AlgEdDSA, true},
		{"unspecified rejected", jose.AlgUnspecified, false},
		{"none rejected", jose.Algorithm("none"), false},
		{"HS256 rejected", jose.Algorithm("HS256"), false},
		{"HS384 rejected", jose.Algorithm("HS384"), false},
		{"HS512 rejected", jose.Algorithm("HS512"), false},
		{"RS384 rejected (not enabled)", jose.Algorithm("RS384"), false},
		{"empty rejected", jose.Algorithm(""), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.alg.IsAllowed(); got != tc.want {
				t.Fatalf("Algorithm(%q).IsAllowed() = %v, want %v", tc.alg, got, tc.want)
			}
		})
	}
}

func TestAlgorithm_StringReturnsWireValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		alg  jose.Algorithm
		want string
	}{
		{"allowed", jose.AlgPS256, "PS256"},
		{"unspecified", jose.AlgUnspecified, ""},
		{"unknown preserved", jose.Algorithm("RS384"), "RS384"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.alg.String(); got != tc.want {
				t.Fatalf("Algorithm(%q).String() = %q, want %q", tc.alg, got, tc.want)
			}
		})
	}
}

func TestParseAlgorithm(t *testing.T) {
	t.Parallel()

	if got, ok := jose.ParseAlgorithm("PS256"); !ok || got != jose.AlgPS256 {
		t.Fatalf("ParseAlgorithm(PS256) = (%q, %v), want (PS256, true)", got, ok)
	}
	if _, ok := jose.ParseAlgorithm("none"); ok {
		t.Fatal("ParseAlgorithm(none) must return ok=false")
	}
	if _, ok := jose.ParseAlgorithm("HS256"); ok {
		t.Fatal("ParseAlgorithm(HS256) must return ok=false")
	}
	if _, ok := jose.ParseAlgorithm(""); ok {
		t.Fatal("ParseAlgorithm(empty) must return ok=false")
	}
}

package endpointsupport_test

import (
	"encoding/base64"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
)

func TestLooksLikeJWTClassification(t *testing.T) {
	t.Parallel()

	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{"object header", enc(`{"alg":"ES256"}`) + ".e30.sig", true},
		{"object header with leading space", enc(` {"alg":"ES256"}`) + ".e30.sig", true},
		{"empty object", enc(`{}`) + ".e30.sig", false},
		{"empty object with space", enc(`{ }`) + ".e30.sig", false},
		{"null", enc(`null`) + ".e30.sig", false},
		{"array", enc(`[]`) + ".e30.sig", false},
		{"non-empty array", enc(`[1]`) + ".e30.sig", false},
		{"string", enc(`"x"`) + ".e30.sig", false},
		{"number", enc(`1`) + ".e30.sig", false},
		{"truncated object", enc(`{"alg":`) + ".e30.sig", false},
		{"trailing garbage", enc(`{"alg":"x"}x`) + ".e30.sig", false},
		{"not base64url", "!!!.e30.sig", false},
		{"two segments", enc(`{"alg":"x"}`) + ".e30", false},
		{"four segments", enc(`{"alg":"x"}`) + ".e30.sig.x", false},
		{"empty header", ".e30.sig", false},
		{"empty payload", enc(`{"alg":"x"}`) + "..sig", false},
		{"empty signature", enc(`{"alg":"x"}`) + ".e30.", false},
		{"opaque", "opaquetokenvalue", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := endpointsupport.LooksLikeJWT(tc.token); got != tc.want {
				t.Fatalf("LooksLikeJWT(%q) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

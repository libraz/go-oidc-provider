package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

func ptrInt64(v int64) *int64 { return &v }

func TestStepUpChallenge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		realm     string
		acrValues []string
		maxAge    *int64
		want      string
	}{
		{
			name: "error only",
			want: `Bearer error="insufficient_user_authentication"`,
		},
		{
			name:  "realm precedes error",
			realm: "api",
			want:  `Bearer realm="api", error="insufficient_user_authentication"`,
		},
		{
			name:      "acr_values joined space-delimited",
			acrValues: []string{"urn:acr:high", "urn:acr:mfa"},
			want:      `Bearer error="insufficient_user_authentication", acr_values="urn:acr:high urn:acr:mfa"`,
		},
		{
			name:   "max_age rendered as number",
			maxAge: ptrInt64(0),
			want:   `Bearer error="insufficient_user_authentication", max_age="0"`,
		},
		{
			name:      "all params in canonical order",
			realm:     "api",
			acrValues: []string{"urn:acr:high"},
			maxAge:    ptrInt64(300),
			want:      `Bearer realm="api", error="insufficient_user_authentication", acr_values="urn:acr:high", max_age="300"`,
		},
		{
			name:  "realm with quote and backslash is escaped",
			realm: `a"b\c`,
			want:  `Bearer realm="a\"b\\c", error="insufficient_user_authentication"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := op.StepUpChallenge(tc.realm, tc.acrValues, tc.maxAge)
			if got != tc.want {
				t.Fatalf("StepUpChallenge()\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

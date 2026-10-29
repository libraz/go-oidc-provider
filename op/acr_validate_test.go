package op_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestValidateACRAdvertisement pins the construction-time checks on the
// built-in ACR policy: an advertised acr the policy cannot resolve, and a
// malformed or contradictory ACRLevels table, fail op.New; a custom
// ACRPolicy is not inspected.
func TestValidateACRAdvertisement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		extra     []op.Option
		wantError string
	}{
		{
			name:  "no advertisement and default policy",
			extra: nil,
		},
		{
			name:  "canonical URIs advertised under the default policy",
			extra: []op.Option{op.WithACRValuesSupported(op.AAL1.ACRURI(), op.AAL3.ACRURI())},
		},
		{
			name:      "unknown value advertised under the default policy",
			extra:     []op.Option{op.WithACRValuesSupported("urn:x")},
			wantError: "urn:x",
		},
		{
			name: "unknown value declared through ACRLevels",
			extra: []op.Option{
				op.WithACRPolicy(op.ACRLevels{"urn:x": op.AAL2}),
				op.WithACRValuesSupported("urn:x", op.AAL1.ACRURI()),
			},
		},
		{
			name: "advertised value missing from ACRLevels",
			extra: []op.Option{
				op.WithACRPolicy(op.ACRLevels{"urn:x": op.AAL2}),
				op.WithACRValuesSupported("urn:y"),
			},
			wantError: "urn:y",
		},
		{
			name:      "empty key",
			extra:     []op.Option{op.WithACRPolicy(op.ACRLevels{"": op.AAL1})},
			wantError: "key must not be empty",
		},
		{
			name:      "AAL0 value",
			extra:     []op.Option{op.WithACRPolicy(op.ACRLevels{"urn:x": op.AAL0})},
			wantError: "urn:x",
		},
		{
			name:      "out-of-range value",
			extra:     []op.Option{op.WithACRPolicy(op.ACRLevels{"urn:x": op.AAL(9)})},
			wantError: "urn:x",
		},
		{
			name:      "canonical URI mapped to a different level",
			extra:     []op.Option{op.WithACRPolicy(op.ACRLevels{op.AAL1.ACRURI(): op.AAL2})},
			wantError: op.AAL1.ACRURI(),
		},
		{
			name:  "canonical URI mapped to its own level",
			extra: []op.Option{op.WithACRPolicy(op.ACRLevels{op.AAL2.ACRURI(): op.AAL2})},
		},
		{
			name: "custom policy is not inspected",
			extra: []op.Option{
				op.WithACRPolicy(stubACRPolicy{}),
				op.WithACRValuesSupported("urn:anything"),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t), tc.extra...)...)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("op.New: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("op.New accepted the configuration, want a configuration error")
			}
			if !op.IsServerError(err) {
				t.Errorf("want a server-side configuration error: %v", err)
			}
			if desc := configurationDescription(t, err); !strings.Contains(desc, tc.wantError) {
				t.Errorf("description %q must mention %q", desc, tc.wantError)
			}
		})
	}
}
